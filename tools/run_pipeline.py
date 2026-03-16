#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import io
import json
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Optional

from shared import dataset_dedup as _dataset_dedup
from shared.artifact_layout import (
    TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    DatasetExportPaths,
    PairTracePaths,
    PatchedPairingPaths,
    SliceStagePaths,
    build_dataset_export_paths,
    build_pair_trace_paths,
    build_patched_pairing_paths,
    build_slice_stage_paths,
)
from shared.jsonio import write_json
from shared.paths import PROJECT_HOME, PULSE_TAINT_CONFIG, RESULT_DIR
from stage import stage01_manifest as _stage01_manifest
from stage import stage02a_taint as _stage02a_taint
from stage import stage02b_flow as _stage02b_flow
from stage import stage03_infer as _stage03_infer
from stage import stage04_trace_flow as _stage04_trace_flow
from stage import stage05_pair_trace as _stage05_pair_trace
from stage import stage06_slices as _stage06_slices
from stage import stage07_dataset_export as _stage07_dataset_export
from stage import stage07b_patched_export as _stage07b_patched_export

PrimaryDatasetExportParams = _stage07_dataset_export.PrimaryDatasetExportParams
compute_pair_split = _stage07_dataset_export.compute_pair_split
dedupe_pairs_by_normalized_rows = _dataset_dedup.dedupe_pairs_by_normalized_rows
export_dataset_from_pipeline = _stage07_dataset_export.export_dataset_from_pipeline
export_primary_dataset = _stage07_dataset_export.export_primary_dataset
PatchedDatasetExportParams = _stage07b_patched_export.PatchedDatasetExportParams
export_patched_dataset = _stage07b_patched_export.export_patched_dataset


@dataclass(frozen=True)
class FullRunPaths:
    run_dir: Path
    manifest_dir: Path
    taint_dir: Path
    flow_dir: Path
    infer_results_root: Path
    signatures_root: Path
    trace_dir: Path
    logs_dir: Path
    manifest_with_comments_xml: Path
    generated_taint_config: Path
    infer_summary_json: Path
    trace_strict_jsonl: Path
    run_summary_path: Path
    source_testcases_root: Path
    stage02b: _stage02b_flow.Stage02BOutputPaths
    pair: PairTracePaths
    slices: SliceStagePaths
    dataset: DatasetExportPaths
    patched_pair: PatchedPairingPaths
    patched_slices: SliceStagePaths
    patched_dataset: DatasetExportPaths


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Unified runner for the full pipeline.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    full = subparsers.add_parser('full', help='Run the full pipeline.')
    full.add_argument('cwes', nargs='*', type=int)
    full.add_argument('--all', action='store_true', dest='all_cwes')
    full.add_argument('--files', action='append', default=[])
    full.add_argument(
        '--manifest',
        type=Path,
        default=Path(PROJECT_HOME)
        / 'experiments'
        / 'epic001_manifest_comment_scan'
        / 'inputs'
        / 'manifest.xml',
    )
    full.add_argument(
        '--source-root',
        type=Path,
        default=Path(PROJECT_HOME) / 'juliet-test-suite-v1.3' / 'C',
    )
    full.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
    )
    full.add_argument('--run-id', type=str, default=None)
    full.add_argument(
        '--committed-taint-config',
        type=Path,
        default=Path(PULSE_TAINT_CONFIG),
    )
    full.add_argument('--pair-split-seed', type=int, default=1234)
    full.add_argument('--pair-train-ratio', type=float, default=0.8)
    full.add_argument('--dedup-mode', choices=['none', 'row'], default='row')

    return parser.parse_args()


def now_ts() -> str:
    return datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')


def now_iso_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _build_full_run_paths(*, run_dir: Path, source_root: Path) -> FullRunPaths:
    run_dir = run_dir.resolve()
    source_root = source_root.resolve()

    manifest_dir = run_dir / '01_manifest'
    taint_dir = run_dir / '02a_taint'
    flow_dir = run_dir / '02b_flow'
    infer_results_root = run_dir / '03_infer-results'
    signatures_root = run_dir / '03_signatures'
    trace_dir = run_dir / '04_trace_flow'
    logs_dir = run_dir / 'logs'
    pair_paths = build_pair_trace_paths(run_dir / '05_pair_trace_ds')
    slice_paths = build_slice_stage_paths(run_dir / '06_slices')
    dataset_paths = build_dataset_export_paths(run_dir / '07_dataset_export')
    patched_pair_paths = build_patched_pairing_paths(
        pair_paths.output_dir,
        TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    )
    patched_slice_paths = build_slice_stage_paths(
        slice_paths.output_dir / TRAIN_PATCHED_COUNTERPARTS_BASENAME
    )
    patched_dataset_paths = build_dataset_export_paths(
        dataset_paths.output_dir,
        TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    )
    stage02b_output_paths = _stage02b_flow.build_stage02b_output_paths(flow_dir)

    return FullRunPaths(
        run_dir=run_dir,
        manifest_dir=manifest_dir,
        taint_dir=taint_dir,
        flow_dir=flow_dir,
        infer_results_root=infer_results_root,
        signatures_root=signatures_root,
        trace_dir=trace_dir,
        logs_dir=logs_dir,
        manifest_with_comments_xml=manifest_dir / 'manifest_with_comments.xml',
        generated_taint_config=taint_dir / 'pulse-taint-config.json',
        infer_summary_json=run_dir / '03_infer_summary.json',
        trace_strict_jsonl=trace_dir / 'trace_flow_match_strict.jsonl',
        run_summary_path=run_dir / 'run_summary.json',
        source_testcases_root=source_root / 'testcases',
        stage02b=stage02b_output_paths,
        pair=pair_paths,
        slices=slice_paths,
        dataset=dataset_paths,
        patched_pair=patched_pair_paths,
        patched_slices=patched_slice_paths,
        patched_dataset=patched_dataset_paths,
    )


def run_internal_step(
    step_key: str,
    logs_dir: Path,
    fn: Callable[[], dict[str, object]],
) -> dict[str, object]:
    started_at = now_iso_utc()
    started_perf = time.perf_counter()
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    result_payload: dict[str, object] = {}
    captured_exc: Exception | None = None

    try:
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            payload = fn()
            if hasattr(payload, 'to_payload'):
                payload = payload.to_payload()
            if isinstance(payload, dict):
                result_payload = payload
    except Exception as exc:  # pragma: no cover - surfaced to caller
        captured_exc = exc
    finally:
        duration_sec = round(time.perf_counter() - started_perf, 6)
        ended_at = now_iso_utc()
        logs_dir.mkdir(parents=True, exist_ok=True)
        stdout_text = stdout_buffer.getvalue()
        stderr_text = stderr_buffer.getvalue()
        stdout_log = logs_dir / f'{step_key}.stdout.log'
        stderr_log = logs_dir / f'{step_key}.stderr.log'
        stdout_log.write_text(stdout_text, encoding='utf-8')
        stderr_log.write_text(stderr_text, encoding='utf-8')
        if stdout_text:
            print(stdout_text, end='' if stdout_text.endswith('\n') else '\n')
        if stderr_text:
            print(stderr_text, file=sys.stderr, end='' if stderr_text.endswith('\n') else '\n')

    if captured_exc is not None:
        raise captured_exc

    result = {
        'executor': 'internal',
        'returncode': 0,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': duration_sec,
        'stdout_log': str(stdout_log),
        'stderr_log': str(stderr_log),
    }
    result.update(result_payload)
    return result


def _validate_full_inputs(
    *,
    manifest: Path,
    source_root: Path,
    committed_taint_config: Path,
    cwes: Optional[list[int]],
    all_cwes: bool,
    files: list[str],
    pair_train_ratio: float,
    dedup_mode: str,
) -> None:
    if not manifest.exists():
        raise ValueError(f'Manifest not found: {manifest}')
    if not source_root.exists():
        raise ValueError(f'Source root not found: {source_root}')
    if not committed_taint_config.exists():
        raise ValueError(f'Committed taint config not found: {committed_taint_config}')
    if not files and not all_cwes and not cwes:
        raise ValueError('Provide cwes, use --all, or use --files')
    if not (0.0 < pair_train_ratio < 1.0):
        raise ValueError(f'pair_train_ratio must be between 0 and 1: {pair_train_ratio}')
    if dedup_mode not in {'none', 'row'}:
        raise ValueError(f'dedup_mode must be one of: none, row (got {dedup_mode})')


def _require_exists(path: Path, error_message: str) -> None:
    if not path.exists():
        raise RuntimeError(error_message)


def _require_all(required_outputs: list[tuple[Path, str]]) -> None:
    for output_path, error_message in required_outputs:
        _require_exists(output_path, error_message)


def _run_checked_internal_step(
    *,
    step_key: str,
    logs_dir: Path,
    fn: Callable[[], dict[str, object]],
    required_outputs: list[tuple[Path, str]],
) -> dict[str, object]:
    result = run_internal_step(step_key, logs_dir=logs_dir, fn=fn)
    _require_all(required_outputs)
    return result


def _run_checked_stage_call(
    *,
    step_key: str,
    paths: FullRunPaths,
    runner: Callable[..., dict[str, object]],
    required_outputs: list[tuple[Path, str]],
    **runner_kwargs: object,
) -> dict[str, object]:
    return _run_checked_internal_step(
        step_key=step_key,
        logs_dir=paths.logs_dir,
        fn=lambda: runner(**runner_kwargs),
        required_outputs=required_outputs,
    )


def _select_taint_config(
    *,
    generated_taint_config: Path,
    committed_taint_config: Path,
) -> tuple[Path, str]:
    if generated_taint_config.exists():
        return generated_taint_config, 'generated'
    return committed_taint_config.resolve(), 'fallback_committed'


def run_step01_manifest_comment_scan(
    *,
    paths: FullRunPaths,
    manifest: Path,
    source_root: Path,
) -> dict[str, object]:
    output_xml = paths.manifest_with_comments_xml
    return _run_checked_stage_call(
        step_key='01_manifest_comment_scan',
        paths=paths,
        runner=_stage01_manifest.scan_manifest_comments,
        manifest=manifest,
        source_root=source_root,
        output_xml=output_xml,
        required_outputs=[
            (output_xml, f'Expected manifest_with_comments_xml not found: {output_xml}')
        ],
    )


def run_step02a_code_field_inventory(
    *,
    paths: FullRunPaths,
    source_root: Path,
) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='02a_code_field_inventory',
        paths=paths,
        runner=_stage02a_taint.extract_unique_code_fields,
        input_xml=paths.manifest_with_comments_xml,
        source_root=source_root,
        output_dir=paths.taint_dir,
        pulse_taint_config_output=paths.generated_taint_config,
        required_outputs=[
            (
                paths.generated_taint_config,
                f'Expected generated_taint_config not found: {paths.generated_taint_config}',
            )
        ],
    )


def run_step02b_flow_build(*, paths: FullRunPaths) -> dict[str, dict[str, object]]:
    stage02b_output_paths = paths.stage02b
    results: dict[str, dict[str, object]] = {}
    results['02b_function_inventory_extract'] = run_internal_step(
        '02b_function_inventory_extract',
        logs_dir=paths.logs_dir,
        fn=lambda: _stage02b_flow.extract_function_inventory(
            input_xml=paths.manifest_with_comments_xml,
            output_csv=stage02b_output_paths.function_names_unique_csv,
            output_summary=stage02b_output_paths.function_inventory_summary_json,
        ),
    )
    results['02b_function_inventory_categorize'] = run_internal_step(
        '02b_function_inventory_categorize',
        logs_dir=paths.logs_dir,
        fn=lambda: _stage02b_flow.categorize_function_names(
            input_csv=stage02b_output_paths.function_names_unique_csv,
            manifest_xml=paths.manifest_with_comments_xml,
            source_root=paths.source_testcases_root,
            output_jsonl=stage02b_output_paths.function_names_categorized_jsonl,
            output_nested_json=stage02b_output_paths.grouped_family_role_json,
            output_summary=stage02b_output_paths.category_summary_json,
        ),
    )
    results['02b_testcase_flow_partition'] = run_internal_step(
        '02b_testcase_flow_partition',
        logs_dir=paths.logs_dir,
        fn=lambda: _stage02b_flow.add_flow_tags_to_testcase(
            input_xml=paths.manifest_with_comments_xml,
            function_categories_jsonl=stage02b_output_paths.function_names_categorized_jsonl,
            output_xml=stage02b_output_paths.manifest_with_testcase_flows_xml,
            summary_json=stage02b_output_paths.testcase_flow_summary_json,
        ),
    )
    _require_all(stage02b_output_paths.required_outputs())
    return results


def run_step03_infer_and_signature(
    *,
    paths: FullRunPaths,
    selected_taint_config: Path,
    files: list[str],
    all_cwes: bool,
    cwes: Optional[list[int]],
) -> tuple[dict[str, object], dict[str, object], Path]:
    result = run_internal_step(
        '03_infer_and_signature',
        logs_dir=paths.logs_dir,
        fn=lambda: _stage03_infer.run_infer_and_signature(
            cwes=cwes,
            global_result=False,
            all_cwes=all_cwes,
            files=files,
            pulse_taint_config=selected_taint_config,
            infer_results_root=paths.infer_results_root,
            signatures_root=paths.signatures_root,
            summary_json=paths.infer_summary_json,
        ),
    )

    _require_all(
        [
            (
                paths.infer_summary_json,
                f'Infer summary JSON not found: {paths.infer_summary_json}',
            )
        ]
    )
    infer_summary = json.loads(paths.infer_summary_json.read_text(encoding='utf-8'))

    signature_non_empty_raw = infer_summary.get('signature_non_empty_dir')
    if signature_non_empty_raw:
        signature_non_empty_dir = Path(signature_non_empty_raw)
    else:
        signature_output_dir = infer_summary.get('signature_output_dir')
        if not signature_output_dir:
            raise RuntimeError('signature_output_dir not found in infer summary')
        signature_non_empty_dir = Path(signature_output_dir) / 'non_empty'

    _require_all(
        [
            (
                signature_non_empty_dir,
                f'Signature non_empty directory not found: {signature_non_empty_dir}',
            )
        ]
    )

    return result, infer_summary, signature_non_empty_dir


def run_step04_trace_flow(
    *,
    paths: FullRunPaths,
    signature_non_empty_dir: Path,
) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='04_trace_flow_filter',
        paths=paths,
        runner=_stage04_trace_flow.filter_traces_by_flow,
        flow_xml=paths.stage02b.manifest_with_testcase_flows_xml,
        signatures_dir=signature_non_empty_dir,
        output_dir=paths.trace_dir,
        required_outputs=[
            (
                paths.trace_strict_jsonl,
                f'Expected trace_flow_match_strict_jsonl not found: {paths.trace_strict_jsonl}',
            )
        ],
    )


def run_step05_pair_trace(*, paths: FullRunPaths) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='05_pair_trace_dataset',
        paths=paths,
        runner=_stage05_pair_trace.build_paired_trace_dataset,
        trace_jsonl=paths.trace_strict_jsonl,
        output_dir=paths.pair.output_dir,
        overwrite=False,
        run_dir=paths.run_dir,
        required_outputs=paths.pair.required_outputs(),
    )


def run_step06_slices(*, paths: FullRunPaths) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='06_generate_slices',
        paths=paths,
        runner=_stage06_slices.generate_slices,
        signature_db_dir=paths.pair.paired_signatures_dir,
        output_dir=paths.slices.output_dir,
        overwrite=False,
        run_dir=paths.run_dir,
        required_outputs=paths.slices.required_outputs(),
    )


def run_step07_dataset_export(
    *,
    paths: FullRunPaths,
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
) -> dict[str, object]:
    return _run_checked_stage_call(
        step_key='07_dataset_export',
        paths=paths,
        runner=export_primary_dataset,
        params=PrimaryDatasetExportParams(
            pairs_jsonl=paths.pair.pairs_jsonl,
            paired_signatures_dir=paths.pair.paired_signatures_dir,
            slice_dir=paths.slices.slice_dir,
            output_dir=paths.dataset.output_dir,
            split_seed=pair_split_seed,
            train_ratio=pair_train_ratio,
            dedup_mode=dedup_mode,
        ),
        required_outputs=paths.dataset.required_outputs(),
    )


def run_step07b_train_patched_counterparts(
    *,
    paths: FullRunPaths,
    dedup_mode: str,
) -> dict[str, object]:
    required_outputs = (
        paths.patched_pair.required_outputs(prefix='pairing_')
        + paths.patched_slices.required_outputs(prefix='slices_')
        + paths.patched_dataset.required_outputs(prefix='dataset_')
    )
    return _run_checked_stage_call(
        step_key='07b_train_patched_counterparts_export',
        paths=paths,
        runner=export_patched_dataset,
        params=PatchedDatasetExportParams(run_dir=paths.run_dir, dedup_mode=dedup_mode),
        required_outputs=required_outputs,
    )


def _summarize_steps(steps: dict[str, dict[str, object]]) -> dict[str, dict[str, object]]:
    keys = (
        'returncode',
        'started_at',
        'ended_at',
        'duration_sec',
        'stdout_log',
        'stderr_log',
    )
    return {
        step_key: {key: value[key] for key in keys if key in value}
        for step_key, value in steps.items()
    }


def _build_run_summary_payload(
    *,
    status: str,
    error_message: Optional[str],
    started_at: str,
    ended_at: str,
    total_duration_sec: float,
    pipeline_root: Path,
    run_id: str,
    manifest: Path,
    source_root: Path,
    all_cwes: bool,
    cwes: Optional[list[int]],
    files: list[str],
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
    committed_taint_config: Path,
    paths: FullRunPaths,
    selected_taint_config: Optional[Path],
    selected_reason: Optional[str],
    steps: dict[str, dict[str, object]],
    infer_summary: dict[str, object],
    signature_non_empty_dir: Optional[Path],
) -> dict[str, object]:
    selected_taint_config_str = (
        str(selected_taint_config.resolve()) if selected_taint_config is not None else None
    )

    return {
        'status': status,
        'error_message': error_message,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': total_duration_sec,
        'run': {
            'pipeline_root': str(pipeline_root),
            'run_id': run_id,
            'run_dir': str(paths.run_dir),
        },
        'inputs': {
            'manifest': str(manifest.resolve()),
            'source_root': str(source_root.resolve()),
            'mode': 'files' if files else ('all' if all_cwes else 'cwes'),
            'cwes': cwes or [],
            'files': files,
        },
        'config': {
            'pair_split_seed': pair_split_seed,
            'pair_train_ratio': pair_train_ratio,
            'dedup_mode': dedup_mode,
            'selected_taint_config_path': selected_taint_config_str,
            'selected_reason': selected_reason,
        },
        'steps': _summarize_steps(steps),
        'outputs': {
            'stage01': {'output_dir': str(paths.manifest_dir)},
            'stage02a': {'output_dir': str(paths.taint_dir)},
            'stage02b': {'output_dir': str(paths.stage02b.output_dir)},
            'stage03': {
                'infer_summary_json': str(paths.infer_summary_json),
                'signature_non_empty_dir': str(signature_non_empty_dir)
                if signature_non_empty_dir is not None
                else None,
            },
            'stage04': {'trace_flow_match_strict_jsonl': str(paths.trace_strict_jsonl)},
            'stage05': {'output_dir': str(paths.pair.output_dir)},
            'stage06': {
                'output_dir': str(paths.slices.output_dir),
                'slice_dir': str(paths.slices.slice_dir),
            },
            'stage07': {
                'output_dir': str(paths.dataset.output_dir),
                'summary_json': str(paths.dataset.summary_json),
            },
            'stage07b': {
                'output_dir': str(paths.patched_dataset.output_dir),
                'summary_json': str(paths.patched_dataset.summary_json),
            },
        },
    }


def run_full_pipeline(
    *,
    cwes: Optional[list[int]],
    all_cwes: bool,
    files: list[str],
    manifest: Path,
    source_root: Path,
    pipeline_root: Path,
    run_id: Optional[str],
    committed_taint_config: Path,
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
) -> int:
    _validate_full_inputs(
        manifest=manifest,
        source_root=source_root,
        committed_taint_config=committed_taint_config,
        cwes=cwes,
        all_cwes=all_cwes,
        files=files,
        pair_train_ratio=pair_train_ratio,
        dedup_mode=dedup_mode,
    )

    manifest = manifest.resolve()
    source_root = source_root.resolve()
    committed_taint_config = committed_taint_config.resolve()
    pipeline_root = pipeline_root.resolve()

    if run_id is None:
        run_id = f'run-{now_ts()}'

    run_dir = (pipeline_root / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    paths = _build_full_run_paths(run_dir=run_dir, source_root=source_root)

    started_at = now_iso_utc()
    started_perf = time.perf_counter()
    steps: dict[str, dict[str, object]] = {}
    status = 'success'
    error_message: Optional[str] = None
    selected_taint_config: Optional[Path] = None
    selected_reason: Optional[str] = None
    infer_summary: dict[str, object] = {}
    signature_non_empty_dir: Optional[Path] = None

    try:
        steps['01_manifest_comment_scan'] = run_step01_manifest_comment_scan(
            paths=paths,
            manifest=manifest,
            source_root=source_root,
        )
        steps['02a_code_field_inventory'] = run_step02a_code_field_inventory(
            paths=paths,
            source_root=source_root,
        )
        steps.update(run_step02b_flow_build(paths=paths))

        selected_taint_config, selected_reason = _select_taint_config(
            generated_taint_config=paths.generated_taint_config,
            committed_taint_config=committed_taint_config,
        )
        (
            steps['03_infer_and_signature'],
            infer_summary,
            signature_non_empty_dir,
        ) = run_step03_infer_and_signature(
            paths=paths,
            selected_taint_config=selected_taint_config,
            files=files,
            all_cwes=all_cwes,
            cwes=cwes,
        )
        steps['04_trace_flow_filter'] = run_step04_trace_flow(
            paths=paths,
            signature_non_empty_dir=signature_non_empty_dir,
        )
        steps['05_pair_trace_dataset'] = run_step05_pair_trace(paths=paths)
        steps['06_generate_slices'] = run_step06_slices(paths=paths)
        steps['07_dataset_export'] = run_step07_dataset_export(
            paths=paths,
            pair_split_seed=pair_split_seed,
            pair_train_ratio=pair_train_ratio,
            dedup_mode=dedup_mode,
        )
        steps['07b_train_patched_counterparts_export'] = run_step07b_train_patched_counterparts(
            paths=paths,
            dedup_mode=dedup_mode,
        )
    except Exception as exc:
        status = 'failed'
        error_message = str(exc)

    ended_at = now_iso_utc()
    total_duration_sec = round(time.perf_counter() - started_perf, 6)

    summary_payload = _build_run_summary_payload(
        status=status,
        error_message=error_message,
        started_at=started_at,
        ended_at=ended_at,
        total_duration_sec=total_duration_sec,
        pipeline_root=pipeline_root,
        run_id=run_id,
        manifest=manifest,
        source_root=source_root,
        all_cwes=all_cwes,
        cwes=cwes,
        files=files,
        pair_split_seed=pair_split_seed,
        pair_train_ratio=pair_train_ratio,
        dedup_mode=dedup_mode,
        committed_taint_config=committed_taint_config,
        paths=paths,
        selected_taint_config=selected_taint_config,
        selected_reason=selected_reason,
        steps=steps,
        infer_summary=infer_summary,
        signature_non_empty_dir=signature_non_empty_dir,
    )
    write_json(paths.run_summary_path, summary_payload)

    print(json.dumps(summary_payload, ensure_ascii=False))
    return 0 if status == 'success' else 1


def main() -> int:
    args = parse_args()
    try:
        return run_full_pipeline(
            cwes=args.cwes or None,
            all_cwes=args.all_cwes,
            files=args.files,
            manifest=args.manifest,
            source_root=args.source_root,
            pipeline_root=args.pipeline_root,
            run_id=args.run_id,
            committed_taint_config=args.committed_taint_config,
            pair_split_seed=args.pair_split_seed,
            pair_train_ratio=args.pair_train_ratio,
            dedup_mode=args.dedup_mode,
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
