#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

from shared import dataset_dedup as _dataset_dedup
from shared.artifact_layout import (
    TRAIN_PATCHED_COUNTERPARTS_BASENAME,
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
from stage import stage03_signature as _stage03_signature
from stage import stage04_trace_flow as _stage04_trace_flow
from stage import stage05_pair_trace as _stage05_pair_trace
from stage import stage06_slices as _stage06_slices
from stage import stage07_dataset_export as _stage07_dataset_export
from stage import stage07b_patched_export as _stage07b_patched_export

PrimaryDatasetExportParams = _stage07_dataset_export.PrimaryDatasetExportParams
PrimaryDatasetExportResult = _stage07_dataset_export.PrimaryDatasetExportResult
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
    pair_dir: Path
    slice_stage_dir: Path
    dataset_stage_dir: Path
    logs_dir: Path
    manifest_with_comments_xml: Path
    generated_taint_config: Path
    function_names_unique_csv: Path
    function_inventory_summary_json: Path
    function_names_categorized_jsonl: Path
    grouped_family_role_json: Path
    category_summary_json: Path
    manifest_with_testcase_flows_xml: Path
    testcase_flow_summary_json: Path
    infer_summary_json: Path
    trace_strict_jsonl: Path
    pairs_jsonl: Path
    leftover_counterparts_jsonl: Path
    paired_signatures_dir: Path
    paired_trace_summary_json: Path
    train_patched_counterparts_pairs_jsonl: Path
    train_patched_counterparts_signatures_dir: Path
    train_patched_counterparts_selection_summary_json: Path
    slice_dir: Path
    slice_summary_json: Path
    train_patched_counterparts_slice_stage_dir: Path
    train_patched_counterparts_slice_dir: Path
    train_patched_counterparts_slice_summary_json: Path
    normalized_slices_dir: Path
    real_vul_data_csv: Path
    real_vul_data_dedup_dropped_csv: Path
    normalized_token_counts_csv: Path
    slice_token_distribution_png: Path
    dataset_split_manifest_json: Path
    dataset_summary_json: Path
    train_patched_counterparts_csv: Path
    train_patched_counterparts_dedup_dropped_csv: Path
    train_patched_counterparts_slices_dir: Path
    train_patched_counterparts_token_counts_csv: Path
    train_patched_counterparts_token_distribution_png: Path
    train_patched_counterparts_split_manifest_json: Path
    train_patched_counterparts_summary_json: Path
    run_summary_path: Path
    source_testcases_root: Path

    def __getitem__(self, key: str) -> Path:
        return getattr(self, key)


def _print_result(result: Any) -> int:
    if hasattr(result, 'to_payload'):
        result = result.to_payload()
    if isinstance(result, dict):
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    return int(result or 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Unified runner for pipeline full/stage commands.')
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

    stage01 = subparsers.add_parser('stage01', help='Run Stage 01 manifest comment scan.')
    stage01.add_argument('--manifest', type=Path, required=True)
    stage01.add_argument('--source-root', type=Path, required=True)
    stage01.add_argument('--output-xml', type=Path, required=True)

    stage02a = subparsers.add_parser('stage02a', help='Run Stage 02a taint extraction.')
    stage02a.add_argument('--input-xml', type=Path, required=True)
    stage02a.add_argument('--source-root', type=Path, required=True)
    stage02a.add_argument('--output-dir', type=Path, required=True)
    stage02a.add_argument('--pulse-taint-config-output', type=Path, default=None)

    stage02b = subparsers.add_parser('stage02b', help='Run Stage 02b flow bundle.')
    stage02b.add_argument('--input-xml', type=Path, required=True)
    stage02b.add_argument('--source-root', type=Path, required=True)
    stage02b.add_argument('--output-dir', type=Path, required=True)

    stage03 = subparsers.add_parser('stage03', help='Run Stage 03 infer and signature.')
    stage03.add_argument('cwes', nargs='*', type=int)
    stage03.add_argument('--global-result', action='store_true')
    stage03.add_argument('--all', action='store_true', dest='all_cwes')
    stage03.add_argument('--files', action='append', default=[])
    stage03.add_argument(
        '--pulse-taint-config',
        type=Path,
        default=Path(_stage03_infer.PULSE_TAINT_CONFIG),
    )
    stage03.add_argument('--infer-results-root', type=Path, default=None)
    stage03.add_argument(
        '--signatures-root',
        type=Path,
        default=Path(_stage03_infer.RESULT_DIR) / 'signatures',
    )
    stage03.add_argument('--summary-json', type=Path, default=None)

    stage03_signature = subparsers.add_parser(
        'stage03-signature',
        help='Run signature generation from an existing infer-* directory.',
    )
    stage03_signature.add_argument('--input-dir', type=Path, default=None)
    stage03_signature.add_argument(
        '--output-root',
        type=Path,
        default=Path(_stage03_signature.RESULT_DIR) / 'signatures',
    )

    stage04 = subparsers.add_parser('stage04', help='Run Stage 04 trace flow filter.')
    stage04.add_argument('--flow-xml', type=Path, required=True)
    stage04.add_argument('--signatures-dir', type=Path, required=True)
    stage04.add_argument('--output-dir', type=Path, required=True)

    stage05 = subparsers.add_parser('stage05', help='Run Stage 05 pair trace dataset.')
    stage05.add_argument('--trace-jsonl', type=Path, default=None)
    stage05.add_argument('--output-dir', type=Path, default=None)
    stage05.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(_stage05_pair_trace.RESULT_DIR) / 'pipeline-runs',
    )
    stage05.add_argument('--overwrite', action='store_true')
    stage05.add_argument('--run-dir', type=Path, default=None)

    stage06 = subparsers.add_parser('stage06', help='Run Stage 06 slices generation.')
    stage06.add_argument('--signature-db-dir', type=Path, default=None)
    stage06.add_argument('--output-dir', type=Path, default=None)
    stage06.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(_stage06_slices.RESULT_DIR) / 'pipeline-runs',
    )
    stage06.add_argument('--old-prefix', type=str, default=None)
    stage06.add_argument('--new-prefix', type=str, default=None)
    stage06.add_argument('--overwrite', action='store_true')
    stage06.add_argument('--run-dir', type=Path, default=None)

    stage07 = subparsers.add_parser('stage07', help='Run Stage 07 dataset export.')
    stage07.add_argument('--pairs-jsonl', type=Path, required=True)
    stage07.add_argument('--paired-signatures-dir', type=Path, required=True)
    stage07.add_argument('--slice-dir', type=Path, required=True)
    stage07.add_argument('--output-dir', type=Path, required=True)
    stage07.add_argument('--split-seed', type=int, default=1234)
    stage07.add_argument('--train-ratio', type=float, default=0.8)
    stage07.add_argument('--dedup-mode', choices=['none', 'row'], default='row')

    stage07b = subparsers.add_parser('stage07b', help='Run Stage 07b patched export.')
    stage07b.add_argument('--run-dir', type=Path, default=None)
    stage07b.add_argument('--pair-dir', type=Path, default=None)
    stage07b.add_argument('--dataset-export-dir', type=Path, default=None)
    stage07b.add_argument('--signature-output-dir', type=Path, default=None)
    stage07b.add_argument('--slice-output-dir', type=Path, default=None)
    stage07b.add_argument('--output-pairs-jsonl', type=Path, default=None)
    stage07b.add_argument('--selection-summary-json', type=Path, default=None)
    stage07b.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(_stage07b_patched_export.RESULT_DIR) / 'pipeline-runs',
    )
    stage07b.add_argument('--dedup-mode', choices=['none', 'row'], default='row')
    stage07b.add_argument('--overwrite', action='store_true')
    stage07b.add_argument('--old-prefix', type=str, default=None)
    stage07b.add_argument('--new-prefix', type=str, default=None)

    return parser.parse_args()


def now_ts() -> str:
    return datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')


def now_iso_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    hasher = hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def _build_full_run_paths(*, run_dir: Path, source_root: Path) -> FullRunPaths:
    run_dir = run_dir.resolve()
    source_root = source_root.resolve()

    manifest_dir = run_dir / '01_manifest'
    taint_dir = run_dir / '02a_taint'
    flow_dir = run_dir / '02b_flow'
    infer_results_root = run_dir / '03_infer-results'
    signatures_root = run_dir / '03_signatures'
    trace_dir = run_dir / '04_trace_flow'
    pair_dir = run_dir / '05_pair_trace_ds'
    slice_stage_dir = run_dir / '06_slices'
    dataset_stage_dir = run_dir / '07_dataset_export'
    logs_dir = run_dir / 'logs'
    train_patched_counterparts_slice_stage_dir = (
        slice_stage_dir / TRAIN_PATCHED_COUNTERPARTS_BASENAME
    )
    pair_trace_paths = build_pair_trace_paths(pair_dir)
    slice_stage_paths = build_slice_stage_paths(slice_stage_dir)
    train_patched_slice_stage_paths = build_slice_stage_paths(
        train_patched_counterparts_slice_stage_dir
    )
    primary_dataset_paths = build_dataset_export_paths(dataset_stage_dir)
    train_patched_counterparts_paths = build_patched_pairing_paths(
        pair_dir,
        TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    )
    train_patched_dataset_paths = build_dataset_export_paths(
        dataset_stage_dir,
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
        pair_dir=pair_dir,
        slice_stage_dir=slice_stage_dir,
        dataset_stage_dir=dataset_stage_dir,
        logs_dir=logs_dir,
        manifest_with_comments_xml=manifest_dir / 'manifest_with_comments.xml',
        generated_taint_config=taint_dir / 'pulse-taint-config.json',
        function_names_unique_csv=stage02b_output_paths['function_names_unique_csv'],
        function_inventory_summary_json=stage02b_output_paths['function_inventory_summary_json'],
        function_names_categorized_jsonl=stage02b_output_paths['function_names_categorized_jsonl'],
        grouped_family_role_json=stage02b_output_paths['grouped_family_role_json'],
        category_summary_json=stage02b_output_paths['category_summary_json'],
        manifest_with_testcase_flows_xml=stage02b_output_paths['manifest_with_testcase_flows_xml'],
        testcase_flow_summary_json=stage02b_output_paths['testcase_flow_summary_json'],
        infer_summary_json=run_dir / '03_infer_summary.json',
        trace_strict_jsonl=trace_dir / 'trace_flow_match_strict.jsonl',
        pairs_jsonl=pair_trace_paths['pairs_jsonl'],
        leftover_counterparts_jsonl=pair_trace_paths['leftover_counterparts_jsonl'],
        paired_signatures_dir=pair_trace_paths['paired_signatures_dir'],
        paired_trace_summary_json=pair_trace_paths['summary_json'],
        train_patched_counterparts_pairs_jsonl=train_patched_counterparts_paths['pairs_jsonl'],
        train_patched_counterparts_signatures_dir=train_patched_counterparts_paths[
            'signatures_dir'
        ],
        train_patched_counterparts_selection_summary_json=train_patched_counterparts_paths[
            'selection_summary_json'
        ],
        slice_dir=slice_stage_paths['slice_dir'],
        slice_summary_json=slice_stage_paths['summary_json'],
        train_patched_counterparts_slice_stage_dir=train_patched_counterparts_slice_stage_dir,
        train_patched_counterparts_slice_dir=train_patched_slice_stage_paths['slice_dir'],
        train_patched_counterparts_slice_summary_json=train_patched_slice_stage_paths[
            'summary_json'
        ],
        normalized_slices_dir=primary_dataset_paths['normalized_slices_dir'],
        real_vul_data_csv=primary_dataset_paths['csv_path'],
        real_vul_data_dedup_dropped_csv=primary_dataset_paths['dedup_dropped_csv'],
        normalized_token_counts_csv=primary_dataset_paths['token_counts_csv'],
        slice_token_distribution_png=primary_dataset_paths['token_distribution_png'],
        dataset_split_manifest_json=primary_dataset_paths['split_manifest_json'],
        dataset_summary_json=primary_dataset_paths['summary_json'],
        train_patched_counterparts_csv=train_patched_dataset_paths['csv_path'],
        train_patched_counterparts_dedup_dropped_csv=train_patched_dataset_paths[
            'dedup_dropped_csv'
        ],
        train_patched_counterparts_slices_dir=train_patched_dataset_paths['normalized_slices_dir'],
        train_patched_counterparts_token_counts_csv=train_patched_dataset_paths['token_counts_csv'],
        train_patched_counterparts_token_distribution_png=train_patched_dataset_paths[
            'token_distribution_png'
        ],
        train_patched_counterparts_split_manifest_json=train_patched_dataset_paths[
            'split_manifest_json'
        ],
        train_patched_counterparts_summary_json=train_patched_dataset_paths['summary_json'],
        run_summary_path=run_dir / 'run_summary.json',
        source_testcases_root=source_root / 'testcases',
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
    return _run_checked_internal_step(
        step_key='01_manifest_comment_scan',
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage01_manifest.scan_manifest_comments(
            manifest=manifest,
            source_root=source_root,
            output_xml=paths['manifest_with_comments_xml'],
        ),
        required_outputs=[
            (
                paths['manifest_with_comments_xml'],
                f'Expected manifest_with_comments.xml not found: {paths["manifest_with_comments_xml"]}',
            )
        ],
    )


def run_step02a_code_field_inventory(
    *,
    paths: FullRunPaths,
    source_root: Path,
) -> dict[str, object]:
    return _run_checked_internal_step(
        step_key='02a_code_field_inventory',
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage02a_taint.extract_unique_code_fields(
            input_xml=paths['manifest_with_comments_xml'],
            source_root=source_root,
            output_dir=paths['taint_dir'],
            pulse_taint_config_output=paths['generated_taint_config'],
        ),
        required_outputs=[
            (
                paths['generated_taint_config'],
                f'Expected generated taint config not found: {paths["generated_taint_config"]}',
            )
        ],
    )


def run_step02b_flow_build(*, paths: FullRunPaths) -> dict[str, dict[str, object]]:
    stage02b_output_paths = _stage02b_flow.build_stage02b_output_paths(paths['flow_dir'])
    results: dict[str, dict[str, object]] = {}
    results['02b_function_inventory_extract'] = run_internal_step(
        '02b_function_inventory_extract',
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage02b_flow.extract_function_inventory(
            input_xml=paths['manifest_with_comments_xml'],
            output_csv=stage02b_output_paths['function_names_unique_csv'],
            output_summary=stage02b_output_paths['function_inventory_summary_json'],
        ),
    )
    results['02b_function_inventory_categorize'] = run_internal_step(
        '02b_function_inventory_categorize',
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage02b_flow.categorize_function_names(
            input_csv=stage02b_output_paths['function_names_unique_csv'],
            manifest_xml=paths['manifest_with_comments_xml'],
            source_root=paths['source_testcases_root'],
            output_jsonl=stage02b_output_paths['function_names_categorized_jsonl'],
            output_nested_json=stage02b_output_paths['grouped_family_role_json'],
            output_summary=stage02b_output_paths['category_summary_json'],
        ),
    )
    results['02b_testcase_flow_partition'] = run_internal_step(
        '02b_testcase_flow_partition',
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage02b_flow.add_flow_tags_to_testcase(
            input_xml=paths['manifest_with_comments_xml'],
            function_categories_jsonl=stage02b_output_paths['function_names_categorized_jsonl'],
            output_xml=stage02b_output_paths['manifest_with_testcase_flows_xml'],
            summary_json=stage02b_output_paths['testcase_flow_summary_json'],
        ),
    )

    required_outputs = [
        (
            stage02b_output_paths['function_names_unique_csv'],
            'Expected function inventory CSV not found: '
            f'{stage02b_output_paths["function_names_unique_csv"]}',
        ),
        (
            stage02b_output_paths['function_inventory_summary_json'],
            'Expected function inventory summary not found: '
            f'{stage02b_output_paths["function_inventory_summary_json"]}',
        ),
        (
            stage02b_output_paths['function_names_categorized_jsonl'],
            'Expected categorized functions JSONL not found: '
            f'{stage02b_output_paths["function_names_categorized_jsonl"]}',
        ),
        (
            stage02b_output_paths['grouped_family_role_json'],
            'Expected grouped family role JSON not found: '
            f'{stage02b_output_paths["grouped_family_role_json"]}',
        ),
        (
            stage02b_output_paths['category_summary_json'],
            f'Expected category summary JSON not found: {stage02b_output_paths["category_summary_json"]}',
        ),
        (
            stage02b_output_paths['manifest_with_testcase_flows_xml'],
            'Expected manifest_with_testcase_flows.xml not found: '
            f'{stage02b_output_paths["manifest_with_testcase_flows_xml"]}',
        ),
        (
            stage02b_output_paths['testcase_flow_summary_json'],
            'Expected testcase flow summary JSON not found: '
            f'{stage02b_output_paths["testcase_flow_summary_json"]}',
        ),
    ]
    _require_all(required_outputs)

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
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage03_infer.run_infer_and_signature(
            cwes=cwes,
            global_result=False,
            all_cwes=all_cwes,
            files=files,
            pulse_taint_config=selected_taint_config,
            infer_results_root=paths['infer_results_root'],
            signatures_root=paths['signatures_root'],
            summary_json=paths['infer_summary_json'],
        ),
    )

    _require_all(
        [
            (
                paths['infer_summary_json'],
                f'Infer summary JSON not found: {paths["infer_summary_json"]}',
            )
        ]
    )
    infer_summary = json.loads(paths['infer_summary_json'].read_text(encoding='utf-8'))

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
    return _run_checked_internal_step(
        step_key='04_trace_flow_filter',
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage04_trace_flow.filter_traces_by_flow(
            flow_xml=paths['manifest_with_testcase_flows_xml'],
            signatures_dir=signature_non_empty_dir,
            output_dir=paths['trace_dir'],
        ),
        required_outputs=[
            (
                paths['trace_strict_jsonl'],
                f'Expected strict trace output not found: {paths["trace_strict_jsonl"]}',
            )
        ],
    )


def run_step05_pair_trace(*, paths: FullRunPaths) -> dict[str, object]:
    return _run_checked_internal_step(
        step_key='05_pair_trace_dataset',
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage05_pair_trace.build_paired_trace_dataset(
            trace_jsonl=paths['trace_strict_jsonl'],
            output_dir=paths['pair_dir'],
            overwrite=False,
            run_dir=paths['run_dir'],
        ),
        required_outputs=[
            (paths['pairs_jsonl'], f'Expected pairs output not found: {paths["pairs_jsonl"]}'),
            (
                paths['paired_signatures_dir'],
                f'Expected paired signatures dir not found: {paths["paired_signatures_dir"]}',
            ),
            (
                paths['paired_trace_summary_json'],
                f'Expected paired trace summary not found: {paths["paired_trace_summary_json"]}',
            ),
        ],
    )


def run_step06_slices(*, paths: FullRunPaths) -> dict[str, object]:
    return _run_checked_internal_step(
        step_key='06_generate_slices',
        logs_dir=paths['logs_dir'],
        fn=lambda: _stage06_slices.generate_slices(
            signature_db_dir=paths['paired_signatures_dir'],
            output_dir=paths['slice_stage_dir'],
            overwrite=False,
            run_dir=paths['run_dir'],
        ),
        required_outputs=[
            (paths['slice_dir'], f'Expected slice dir not found: {paths["slice_dir"]}'),
            (
                paths['slice_summary_json'],
                f'Expected slice summary not found: {paths["slice_summary_json"]}',
            ),
        ],
    )


def run_step07_dataset_export(
    *,
    paths: FullRunPaths,
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
) -> dict[str, object]:
    return _run_checked_internal_step(
        step_key='07_dataset_export',
        logs_dir=paths['logs_dir'],
        fn=lambda: export_primary_dataset(
            PrimaryDatasetExportParams(
                pairs_jsonl=paths['pairs_jsonl'],
                paired_signatures_dir=paths['paired_signatures_dir'],
                slice_dir=paths['slice_dir'],
                output_dir=paths['dataset_stage_dir'],
                split_seed=pair_split_seed,
                train_ratio=pair_train_ratio,
                dedup_mode=dedup_mode,
            )
        ).to_payload(),
        required_outputs=[
            (
                paths['normalized_slices_dir'],
                f'Expected normalized slices dir not found: {paths["normalized_slices_dir"]}',
            ),
            (
                paths['real_vul_data_csv'],
                f'Expected Real_Vul_data.csv not found: {paths["real_vul_data_csv"]}',
            ),
            (
                paths['real_vul_data_dedup_dropped_csv'],
                'Expected Real_Vul_data dedup dropped CSV not found: '
                f'{paths["real_vul_data_dedup_dropped_csv"]}',
            ),
            (
                paths['normalized_token_counts_csv'],
                'Expected normalized token counts CSV not found: '
                f'{paths["normalized_token_counts_csv"]}',
            ),
            (
                paths['slice_token_distribution_png'],
                f'Expected token distribution plot not found: {paths["slice_token_distribution_png"]}',
            ),
            (
                paths['dataset_split_manifest_json'],
                f'Expected dataset split manifest not found: {paths["dataset_split_manifest_json"]}',
            ),
            (
                paths['dataset_summary_json'],
                f'Expected dataset summary JSON not found: {paths["dataset_summary_json"]}',
            ),
        ],
    )


def run_step07b_train_patched_counterparts(
    *,
    paths: FullRunPaths,
    dedup_mode: str,
) -> dict[str, object]:
    return _run_checked_internal_step(
        step_key='07b_train_patched_counterparts_export',
        logs_dir=paths['logs_dir'],
        fn=lambda: export_patched_dataset(
            PatchedDatasetExportParams(
                run_dir=paths['run_dir'],
                pair_dir=paths['pair_dir'],
                dataset_export_dir=paths['dataset_stage_dir'],
                signature_output_dir=paths['train_patched_counterparts_signatures_dir'],
                slice_output_dir=paths['train_patched_counterparts_slice_stage_dir'],
                output_pairs_jsonl=paths['train_patched_counterparts_pairs_jsonl'],
                selection_summary_json=paths['train_patched_counterparts_selection_summary_json'],
                dedup_mode=dedup_mode,
                overwrite=False,
                old_prefix=None,
                new_prefix=None,
            )
        ).to_payload(),
        required_outputs=[
            (
                paths['train_patched_counterparts_pairs_jsonl'],
                'Expected train_patched_counterparts pairs output not found: '
                f'{paths["train_patched_counterparts_pairs_jsonl"]}',
            ),
            (
                paths['train_patched_counterparts_signatures_dir'],
                'Expected train_patched_counterparts signatures dir not found: '
                f'{paths["train_patched_counterparts_signatures_dir"]}',
            ),
            (
                paths['train_patched_counterparts_selection_summary_json'],
                'Expected train_patched_counterparts selection summary not found: '
                f'{paths["train_patched_counterparts_selection_summary_json"]}',
            ),
            (
                paths['train_patched_counterparts_slice_dir'],
                'Expected train_patched_counterparts slice dir not found: '
                f'{paths["train_patched_counterparts_slice_dir"]}',
            ),
            (
                paths['train_patched_counterparts_slice_summary_json'],
                'Expected train_patched_counterparts slice summary not found: '
                f'{paths["train_patched_counterparts_slice_summary_json"]}',
            ),
            (
                paths['train_patched_counterparts_csv'],
                'Expected train_patched_counterparts CSV not found: '
                f'{paths["train_patched_counterparts_csv"]}',
            ),
            (
                paths['train_patched_counterparts_dedup_dropped_csv'],
                'Expected train_patched_counterparts dedup dropped CSV not found: '
                f'{paths["train_patched_counterparts_dedup_dropped_csv"]}',
            ),
            (
                paths['train_patched_counterparts_slices_dir'],
                'Expected train_patched_counterparts slices dir not found: '
                f'{paths["train_patched_counterparts_slices_dir"]}',
            ),
            (
                paths['train_patched_counterparts_token_counts_csv'],
                'Expected train_patched_counterparts token counts CSV not found: '
                f'{paths["train_patched_counterparts_token_counts_csv"]}',
            ),
            (
                paths['train_patched_counterparts_token_distribution_png'],
                'Expected train_patched_counterparts token distribution plot not found: '
                f'{paths["train_patched_counterparts_token_distribution_png"]}',
            ),
            (
                paths['train_patched_counterparts_split_manifest_json'],
                'Expected train_patched_counterparts split manifest not found: '
                f'{paths["train_patched_counterparts_split_manifest_json"]}',
            ),
            (
                paths['train_patched_counterparts_summary_json'],
                'Expected train_patched_counterparts summary JSON not found: '
                f'{paths["train_patched_counterparts_summary_json"]}',
            ),
        ],
    )


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
    committed_taint_config = committed_taint_config.resolve()
    generated_taint_config = paths['generated_taint_config'].resolve()
    selected_taint_config_str = (
        str(selected_taint_config.resolve()) if selected_taint_config is not None else None
    )

    return {
        'status': status,
        'error_message': error_message,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': total_duration_sec,
        'pipeline_root': str(pipeline_root),
        'run_id': run_id,
        'run_dir': str(paths['run_dir']),
        'input_manifest': str(manifest.resolve()),
        'source_root': str(source_root.resolve()),
        'mode': 'files' if files else ('all' if all_cwes else 'cwes'),
        'all_cwes': all_cwes,
        'cwes': cwes or [],
        'files': files,
        'pair_split_seed': pair_split_seed,
        'pair_train_ratio': pair_train_ratio,
        'dedup_mode': dedup_mode,
        'committed_taint_config_path': str(committed_taint_config),
        'generated_taint_config_path': str(generated_taint_config),
        'selected_taint_config_path': selected_taint_config_str,
        'selected_reason': selected_reason,
        'sha256': {
            'committed_taint_config': sha256_file(committed_taint_config),
            'generated_taint_config': sha256_file(generated_taint_config),
            'selected_taint_config': sha256_file(Path(selected_taint_config_str))
            if selected_taint_config_str
            else None,
        },
        'steps': steps,
        'outputs': {
            'manifest_with_comments_xml': str(paths['manifest_with_comments_xml']),
            'generated_taint_config': str(paths['generated_taint_config']),
            'manifest_with_testcase_flows_xml': str(paths['manifest_with_testcase_flows_xml']),
            'infer_summary_json': str(paths['infer_summary_json']),
            'signature_non_empty_dir': str(signature_non_empty_dir)
            if signature_non_empty_dir is not None
            else None,
            'trace_flow_match_strict_jsonl': str(paths['trace_strict_jsonl']),
            'pairs_jsonl': str(paths['pairs_jsonl']),
            'leftover_counterparts_jsonl': str(paths['leftover_counterparts_jsonl']),
            'paired_signatures_dir': str(paths['paired_signatures_dir']),
            'paired_trace_summary_json': str(paths['paired_trace_summary_json']),
            'train_patched_counterparts_pairs_jsonl': str(
                paths['train_patched_counterparts_pairs_jsonl']
            ),
            'train_patched_counterparts_signatures_dir': str(
                paths['train_patched_counterparts_signatures_dir']
            ),
            'train_patched_counterparts_selection_summary_json': str(
                paths['train_patched_counterparts_selection_summary_json']
            ),
            'slice_dir': str(paths['slice_dir']),
            'slice_summary_json': str(paths['slice_summary_json']),
            'train_patched_counterparts_slice_dir': str(
                paths['train_patched_counterparts_slice_dir']
            ),
            'train_patched_counterparts_slice_summary_json': str(
                paths['train_patched_counterparts_slice_summary_json']
            ),
            'dataset_export_dir': str(paths['dataset_stage_dir']),
            'normalized_slices_dir': str(paths['normalized_slices_dir']),
            'real_vul_data_csv': str(paths['real_vul_data_csv']),
            'real_vul_data_dedup_dropped_csv': str(paths['real_vul_data_dedup_dropped_csv']),
            'normalized_token_counts_csv': str(paths['normalized_token_counts_csv']),
            'slice_token_distribution_png': str(paths['slice_token_distribution_png']),
            'dataset_split_manifest_json': str(paths['dataset_split_manifest_json']),
            'dataset_summary_json': str(paths['dataset_summary_json']),
            'train_patched_counterparts_csv': str(paths['train_patched_counterparts_csv']),
            'train_patched_counterparts_dedup_dropped_csv': str(
                paths['train_patched_counterparts_dedup_dropped_csv']
            ),
            'train_patched_counterparts_slices_dir': str(
                paths['train_patched_counterparts_slices_dir']
            ),
            'train_patched_counterparts_token_counts_csv': str(
                paths['train_patched_counterparts_token_counts_csv']
            ),
            'train_patched_counterparts_token_distribution_png': str(
                paths['train_patched_counterparts_token_distribution_png']
            ),
            'train_patched_counterparts_split_manifest_json': str(
                paths['train_patched_counterparts_split_manifest_json']
            ),
            'train_patched_counterparts_summary_json': str(
                paths['train_patched_counterparts_summary_json']
            ),
        },
        'infer_summary': infer_summary,
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
            generated_taint_config=paths['generated_taint_config'],
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
    write_json(paths['run_summary_path'], summary_payload)

    print(json.dumps(summary_payload, ensure_ascii=False))
    return 0 if status == 'success' else 1


def main() -> int:
    args = parse_args()

    if args.command == 'full':
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

    if args.command == 'stage01':
        return _print_result(
            _stage01_manifest.scan_manifest_comments(
                manifest=args.manifest,
                source_root=args.source_root,
                output_xml=args.output_xml,
            )
        )

    if args.command == 'stage02a':
        return _print_result(
            _stage02a_taint.extract_unique_code_fields(
                input_xml=args.input_xml,
                source_root=args.source_root,
                output_dir=args.output_dir,
                pulse_taint_config_output=args.pulse_taint_config_output,
            )
        )

    if args.command == 'stage02b':
        return _print_result(
            _stage02b_flow.run_stage02b_flow(
                input_xml=args.input_xml,
                source_root=args.source_root,
                output_dir=args.output_dir,
            )
        )

    if args.command == 'stage03':
        return _print_result(
            _stage03_infer.run_infer_and_signature(
                cwes=args.cwes or None,
                global_result=args.global_result,
                all_cwes=args.all_cwes,
                files=args.files,
                pulse_taint_config=args.pulse_taint_config,
                infer_results_root=args.infer_results_root,
                signatures_root=args.signatures_root,
                summary_json=args.summary_json,
            )
        )

    if args.command == 'stage03-signature':
        return int(
            _stage03_signature.main(
                input_dir=args.input_dir,
                output_root=args.output_root,
            )
            or 0
        )

    if args.command == 'stage04':
        return _print_result(
            _stage04_trace_flow.filter_traces_by_flow(
                flow_xml=args.flow_xml,
                signatures_dir=args.signatures_dir,
                output_dir=args.output_dir,
            )
        )

    if args.command == 'stage05':
        trace_jsonl, output_dir, run_dir = _stage05_pair_trace.resolve_paths(
            trace_jsonl=args.trace_jsonl,
            output_dir=args.output_dir,
            pipeline_root=args.pipeline_root,
            run_dir=args.run_dir,
        )
        return _print_result(
            _stage05_pair_trace.build_paired_trace_dataset(
                trace_jsonl=trace_jsonl,
                output_dir=output_dir,
                overwrite=args.overwrite,
                run_dir=run_dir,
            )
        )

    if args.command == 'stage06':
        signature_db_dir, output_dir, _slice_dir, run_dir = _stage06_slices.resolve_paths(
            signature_db_dir=args.signature_db_dir,
            output_dir=args.output_dir,
            pipeline_root=args.pipeline_root,
            run_dir=args.run_dir,
        )
        return _print_result(
            _stage06_slices.generate_slices(
                signature_db_dir=signature_db_dir,
                output_dir=output_dir,
                old_prefix=args.old_prefix,
                new_prefix=args.new_prefix,
                overwrite=args.overwrite,
                run_dir=run_dir,
            )
        )

    if args.command == 'stage07':
        return _print_result(
            _stage07_dataset_export.export_primary_dataset(
                _stage07_dataset_export.PrimaryDatasetExportParams(
                    pairs_jsonl=args.pairs_jsonl,
                    paired_signatures_dir=args.paired_signatures_dir,
                    slice_dir=args.slice_dir,
                    output_dir=args.output_dir,
                    split_seed=args.split_seed,
                    train_ratio=args.train_ratio,
                    dedup_mode=args.dedup_mode,
                )
            )
        )

    if args.command == 'stage07b':
        paths = _stage07b_patched_export.resolve_paths(
            run_dir=args.run_dir,
            pair_dir=args.pair_dir,
            dataset_export_dir=args.dataset_export_dir,
            signature_output_dir=args.signature_output_dir,
            slice_output_dir=args.slice_output_dir,
            pipeline_root=args.pipeline_root,
        )
        _stage07b_patched_export.validate_args(
            pair_dir=paths['pair_dir'],
            dataset_export_dir=paths['dataset_export_dir'],
            old_prefix=args.old_prefix,
            new_prefix=args.new_prefix,
        )
        run_dir = paths['run_dir']
        pair_dir = paths['pair_dir']
        dataset_export_dir = paths['dataset_export_dir']
        signature_output_dir = paths['signature_output_dir']
        slice_output_dir = paths['slice_output_dir']
        if (
            run_dir is None
            or pair_dir is None
            or dataset_export_dir is None
            or signature_output_dir is None
            or slice_output_dir is None
        ):
            raise ValueError('Failed to resolve required stage07b paths.')
        patched_pairing_paths = build_patched_pairing_paths(
            pair_dir,
            _stage07b_patched_export.DATASET_BASENAME,
        )
        output_pairs_jsonl = (
            args.output_pairs_jsonl.resolve()
            if args.output_pairs_jsonl is not None
            else patched_pairing_paths['pairs_jsonl']
        )
        selection_summary_json = (
            args.selection_summary_json.resolve()
            if args.selection_summary_json is not None
            else patched_pairing_paths['selection_summary_json']
        )
        return _print_result(
            _stage07b_patched_export.export_patched_dataset(
                _stage07b_patched_export.PatchedDatasetExportParams(
                    run_dir=run_dir,
                    pair_dir=pair_dir,
                    dataset_export_dir=dataset_export_dir,
                    signature_output_dir=signature_output_dir,
                    slice_output_dir=slice_output_dir,
                    output_pairs_jsonl=output_pairs_jsonl,
                    selection_summary_json=selection_summary_json,
                    dedup_mode=args.dedup_mode,
                    overwrite=args.overwrite,
                    old_prefix=args.old_prefix,
                    new_prefix=args.new_prefix,
                )
            )
        )

    raise ValueError(f'Unsupported command: {args.command}')


if __name__ == '__main__':
    raise SystemExit(main())
