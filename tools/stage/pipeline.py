#!/usr/bin/env python3
from __future__ import annotations

import datetime
import hashlib
import io
import json
import shlex
import subprocess
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional

import typer
from shared.paths import PROJECT_HOME, PULSE_TAINT_CONFIG, RESULT_DIR

from stage import dataset_export as _dataset_export
from stage import pair_trace as _pair_trace
from stage import slices as _slices
from stage import trace_flow as _trace_flow

PrimaryDatasetExportParams = _dataset_export.PrimaryDatasetExportParams
PrimaryDatasetExportResult = _dataset_export.PrimaryDatasetExportResult
compute_pair_split = _dataset_export.compute_pair_split
export_dataset_from_pipeline = _dataset_export.export_dataset_from_pipeline
export_primary_dataset = _dataset_export.export_primary_dataset
load_pairs_jsonl = _dataset_export.load_pairs_jsonl


@dataclass(frozen=True)
class PipelinePaths:
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
    scan_script: Path
    code_field_script: Path
    function_inventory_script: Path
    categorize_script: Path
    flow_partition_script: Path
    infer_script: Path
    train_patched_counterparts_script: Path

    @classmethod
    def from_run_dir(cls, *, run_dir: Path, source_root: Path) -> PipelinePaths:
        run_dir = run_dir.resolve()

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

        manifest_with_comments_xml = manifest_dir / 'manifest_with_comments.xml'
        generated_taint_config = taint_dir / 'pulse-taint-config.json'

        function_names_unique_csv = flow_dir / 'function_names_unique.csv'
        function_inventory_summary_json = flow_dir / 'function_inventory_summary.json'
        function_names_categorized_jsonl = flow_dir / 'function_names_categorized.jsonl'
        grouped_family_role_json = flow_dir / 'grouped_family_role.json'
        category_summary_json = flow_dir / 'category_summary.json'
        manifest_with_testcase_flows_xml = flow_dir / 'manifest_with_testcase_flows.xml'
        testcase_flow_summary_json = flow_dir / 'testcase_flow_summary.json'

        infer_summary_json = run_dir / '03_infer_summary.json'
        trace_strict_jsonl = trace_dir / 'trace_flow_match_strict.jsonl'
        pairs_jsonl = pair_dir / 'pairs.jsonl'
        leftover_counterparts_jsonl = pair_dir / 'leftover_counterparts.jsonl'
        paired_signatures_dir = pair_dir / 'paired_signatures'
        paired_trace_summary_json = pair_dir / 'summary.json'
        train_patched_counterparts_pairs_jsonl = pair_dir / 'train_patched_counterparts_pairs.jsonl'
        train_patched_counterparts_signatures_dir = (
            pair_dir / 'train_patched_counterparts_signatures'
        )
        train_patched_counterparts_selection_summary_json = (
            pair_dir / 'train_patched_counterparts_selection_summary.json'
        )
        slice_dir = slice_stage_dir / 'slice'
        slice_summary_json = slice_stage_dir / 'summary.json'
        train_patched_counterparts_slice_stage_dir = slice_stage_dir / 'train_patched_counterparts'
        train_patched_counterparts_slice_dir = train_patched_counterparts_slice_stage_dir / 'slice'
        train_patched_counterparts_slice_summary_json = (
            train_patched_counterparts_slice_stage_dir / 'summary.json'
        )
        normalized_slices_dir = dataset_stage_dir / 'normalized_slices'
        real_vul_data_csv = dataset_stage_dir / 'Real_Vul_data.csv'
        real_vul_data_dedup_dropped_csv = dataset_stage_dir / 'Real_Vul_data_dedup_dropped.csv'
        normalized_token_counts_csv = dataset_stage_dir / 'normalized_token_counts.csv'
        slice_token_distribution_png = dataset_stage_dir / 'slice_token_distribution.png'
        dataset_split_manifest_json = dataset_stage_dir / 'split_manifest.json'
        dataset_summary_json = dataset_stage_dir / 'summary.json'
        train_patched_counterparts_csv = dataset_stage_dir / 'train_patched_counterparts.csv'
        train_patched_counterparts_dedup_dropped_csv = (
            dataset_stage_dir / 'train_patched_counterparts_dedup_dropped.csv'
        )
        train_patched_counterparts_slices_dir = (
            dataset_stage_dir / 'train_patched_counterparts_slices'
        )
        train_patched_counterparts_token_counts_csv = (
            dataset_stage_dir / 'train_patched_counterparts_token_counts.csv'
        )
        train_patched_counterparts_token_distribution_png = (
            dataset_stage_dir / 'train_patched_counterparts_token_distribution.png'
        )
        train_patched_counterparts_split_manifest_json = (
            dataset_stage_dir / 'train_patched_counterparts_split_manifest.json'
        )
        train_patched_counterparts_summary_json = (
            dataset_stage_dir / 'train_patched_counterparts_summary.json'
        )
        run_summary_path = run_dir / 'run_summary.json'

        source_testcases_root = source_root / 'testcases'

        scan_script = (
            Path(PROJECT_HOME)
            / 'experiments'
            / 'epic001_manifest_comment_scan'
            / 'scripts'
            / 'scan_manifest_comments.py'
        )
        code_field_script = (
            Path(PROJECT_HOME)
            / 'experiments'
            / 'epic001a_code_field_inventory'
            / 'scripts'
            / 'extract_unique_code_fields.py'
        )
        function_inventory_script = (
            Path(PROJECT_HOME)
            / 'experiments'
            / 'epic001b_function_inventory'
            / 'scripts'
            / 'extract_function_inventory.py'
        )
        categorize_script = (
            Path(PROJECT_HOME)
            / 'experiments'
            / 'epic001b_function_inventory'
            / 'scripts'
            / 'categorize_function_names.py'
        )
        flow_partition_script = (
            Path(PROJECT_HOME)
            / 'experiments'
            / 'epic001c_testcase_flow_partition'
            / 'scripts'
            / 'add_flow_tags_to_testcase.py'
        )
        infer_script = Path(PROJECT_HOME) / 'tools' / 'run-infer-all-juliet.py'
        train_patched_counterparts_script = (
            Path(PROJECT_HOME) / 'tools' / 'export_train_patched_counterparts.py'
        )

        return cls(
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
            manifest_with_comments_xml=manifest_with_comments_xml,
            generated_taint_config=generated_taint_config,
            function_names_unique_csv=function_names_unique_csv,
            function_inventory_summary_json=function_inventory_summary_json,
            function_names_categorized_jsonl=function_names_categorized_jsonl,
            grouped_family_role_json=grouped_family_role_json,
            category_summary_json=category_summary_json,
            manifest_with_testcase_flows_xml=manifest_with_testcase_flows_xml,
            testcase_flow_summary_json=testcase_flow_summary_json,
            infer_summary_json=infer_summary_json,
            trace_strict_jsonl=trace_strict_jsonl,
            pairs_jsonl=pairs_jsonl,
            leftover_counterparts_jsonl=leftover_counterparts_jsonl,
            paired_signatures_dir=paired_signatures_dir,
            paired_trace_summary_json=paired_trace_summary_json,
            train_patched_counterparts_pairs_jsonl=train_patched_counterparts_pairs_jsonl,
            train_patched_counterparts_signatures_dir=train_patched_counterparts_signatures_dir,
            train_patched_counterparts_selection_summary_json=(
                train_patched_counterparts_selection_summary_json
            ),
            slice_dir=slice_dir,
            slice_summary_json=slice_summary_json,
            train_patched_counterparts_slice_stage_dir=train_patched_counterparts_slice_stage_dir,
            train_patched_counterparts_slice_dir=train_patched_counterparts_slice_dir,
            train_patched_counterparts_slice_summary_json=(
                train_patched_counterparts_slice_summary_json
            ),
            normalized_slices_dir=normalized_slices_dir,
            real_vul_data_csv=real_vul_data_csv,
            real_vul_data_dedup_dropped_csv=real_vul_data_dedup_dropped_csv,
            normalized_token_counts_csv=normalized_token_counts_csv,
            slice_token_distribution_png=slice_token_distribution_png,
            dataset_split_manifest_json=dataset_split_manifest_json,
            dataset_summary_json=dataset_summary_json,
            train_patched_counterparts_csv=train_patched_counterparts_csv,
            train_patched_counterparts_dedup_dropped_csv=(
                train_patched_counterparts_dedup_dropped_csv
            ),
            train_patched_counterparts_slices_dir=train_patched_counterparts_slices_dir,
            train_patched_counterparts_token_counts_csv=(
                train_patched_counterparts_token_counts_csv
            ),
            train_patched_counterparts_token_distribution_png=(
                train_patched_counterparts_token_distribution_png
            ),
            train_patched_counterparts_split_manifest_json=(
                train_patched_counterparts_split_manifest_json
            ),
            train_patched_counterparts_summary_json=train_patched_counterparts_summary_json,
            run_summary_path=run_summary_path,
            source_testcases_root=source_testcases_root,
            scan_script=scan_script,
            code_field_script=code_field_script,
            function_inventory_script=function_inventory_script,
            categorize_script=categorize_script,
            flow_partition_script=flow_partition_script,
            infer_script=infer_script,
            train_patched_counterparts_script=train_patched_counterparts_script,
        )


def now_ts() -> str:
    return datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')


def now_iso_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def command_to_string(cmd: List[str]) -> str:
    return ' '.join(shlex.quote(x) for x in cmd)


def run_command(step_key: str, cmd: List[str], cwd: Path, logs_dir: Path) -> Dict[str, object]:
    started_at = now_iso_utc()
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    duration_sec = round(time.perf_counter() - t0, 6)
    ended_at = now_iso_utc()

    logs_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = logs_dir / f'{step_key}.stdout.log'
    stderr_log = logs_dir / f'{step_key}.stderr.log'
    stdout_log.write_text(proc.stdout or '', encoding='utf-8')
    stderr_log.write_text(proc.stderr or '', encoding='utf-8')

    if proc.stdout:
        print(proc.stdout, end='' if proc.stdout.endswith('\n') else '\n')
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end='' if proc.stderr.endswith('\n') else '\n')

    result = {
        'command': command_to_string(cmd),
        'cwd': str(cwd),
        'returncode': proc.returncode,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': duration_sec,
        'stdout_log': str(stdout_log),
        'stderr_log': str(stderr_log),
    }
    if proc.returncode != 0:
        raise RuntimeError(
            f'[{step_key}] failed with return code {proc.returncode}: {result["command"]}'
        )
    return result


def run_internal_step(
    step_key: str, logs_dir: Path, fn: Callable[[], Dict[str, object]]
) -> Dict[str, object]:
    started_at = now_iso_utc()
    t0 = time.perf_counter()
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    result_payload: Dict[str, object] = {}
    captured_exc: Exception | None = None

    try:
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            payload = fn()
            if isinstance(payload, dict):
                result_payload = payload
    except Exception as exc:  # pragma: no cover - surfaced to caller
        captured_exc = exc
    finally:
        duration_sec = round(time.perf_counter() - t0, 6)
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


def _validate_main_inputs(
    *,
    manifest: Path,
    source_root: Path,
    committed_taint_config: Path,
    cwes: Optional[List[int]],
    all_cwes: bool,
    files: List[str],
    pair_train_ratio: float,
    dedup_mode: str,
) -> None:
    if not manifest.exists():
        raise typer.BadParameter(f'Manifest not found: {manifest}')
    if not source_root.exists():
        raise typer.BadParameter(f'Source root not found: {source_root}')
    if not committed_taint_config.exists():
        raise typer.BadParameter(f'Committed taint config not found: {committed_taint_config}')
    if not files and not all_cwes and not cwes:
        raise typer.BadParameter('Provide cwes, use --all, or use --files')
    if not (0.0 < pair_train_ratio < 1.0):
        raise typer.BadParameter(f'pair_train_ratio must be between 0 and 1: {pair_train_ratio}')
    if dedup_mode not in {'none', 'row'}:
        raise typer.BadParameter(f'dedup_mode must be one of: none, row (got {dedup_mode})')


def _require_exists(path: Path, error_message: str) -> None:
    if not path.exists():
        raise RuntimeError(error_message)


def _select_taint_config(
    *, generated_taint_config: Path, committed_taint_config: Path
) -> tuple[Path, str]:
    if generated_taint_config.exists():
        return generated_taint_config, 'generated'
    return committed_taint_config.resolve(), 'fallback_committed'


def run_step01_manifest_comment_scan(
    *, paths: PipelinePaths, manifest: Path, source_root: Path
) -> Dict[str, object]:
    result = run_command(
        '01_manifest_comment_scan',
        [
            sys.executable,
            str(paths.scan_script),
            '--manifest',
            str(manifest),
            '--source-root',
            str(source_root),
            '--output-xml',
            str(paths.manifest_with_comments_xml),
        ],
        cwd=Path(PROJECT_HOME),
        logs_dir=paths.logs_dir,
    )
    _require_exists(
        paths.manifest_with_comments_xml,
        f'Expected manifest_with_comments.xml not found: {paths.manifest_with_comments_xml}',
    )
    return result


def run_step02a_code_field_inventory(
    *, paths: PipelinePaths, source_root: Path
) -> Dict[str, object]:
    return run_command(
        '02a_code_field_inventory',
        [
            sys.executable,
            str(paths.code_field_script),
            '--input-xml',
            str(paths.manifest_with_comments_xml),
            '--source-root',
            str(source_root),
            '--output-dir',
            str(paths.taint_dir),
            '--pulse-taint-config-output',
            str(paths.generated_taint_config),
        ],
        cwd=Path(PROJECT_HOME),
        logs_dir=paths.logs_dir,
    )


def run_step02b_flow_build(*, paths: PipelinePaths) -> Dict[str, Dict[str, object]]:
    results: Dict[str, Dict[str, object]] = {}
    results['02b_function_inventory_extract'] = run_command(
        '02b_function_inventory_extract',
        [
            sys.executable,
            str(paths.function_inventory_script),
            '--input-xml',
            str(paths.manifest_with_comments_xml),
            '--output-csv',
            str(paths.function_names_unique_csv),
            '--output-summary',
            str(paths.function_inventory_summary_json),
        ],
        cwd=Path(PROJECT_HOME),
        logs_dir=paths.logs_dir,
    )
    results['02b_function_inventory_categorize'] = run_command(
        '02b_function_inventory_categorize',
        [
            sys.executable,
            str(paths.categorize_script),
            '--input-csv',
            str(paths.function_names_unique_csv),
            '--manifest-xml',
            str(paths.manifest_with_comments_xml),
            '--source-root',
            str(paths.source_testcases_root),
            '--output-jsonl',
            str(paths.function_names_categorized_jsonl),
            '--output-nested-json',
            str(paths.grouped_family_role_json),
            '--output-summary',
            str(paths.category_summary_json),
        ],
        cwd=Path(PROJECT_HOME),
        logs_dir=paths.logs_dir,
    )
    results['02b_testcase_flow_partition'] = run_command(
        '02b_testcase_flow_partition',
        [
            sys.executable,
            str(paths.flow_partition_script),
            '--input-xml',
            str(paths.manifest_with_comments_xml),
            '--function-categories-jsonl',
            str(paths.function_names_categorized_jsonl),
            '--output-xml',
            str(paths.manifest_with_testcase_flows_xml),
            '--summary-json',
            str(paths.testcase_flow_summary_json),
        ],
        cwd=Path(PROJECT_HOME),
        logs_dir=paths.logs_dir,
    )

    required_outputs = [
        (
            paths.function_names_unique_csv,
            f'Expected function inventory CSV not found: {paths.function_names_unique_csv}',
        ),
        (
            paths.function_inventory_summary_json,
            'Expected function inventory summary not found: '
            f'{paths.function_inventory_summary_json}',
        ),
        (
            paths.function_names_categorized_jsonl,
            'Expected categorized functions JSONL not found: '
            f'{paths.function_names_categorized_jsonl}',
        ),
        (
            paths.grouped_family_role_json,
            f'Expected grouped family role JSON not found: {paths.grouped_family_role_json}',
        ),
        (
            paths.category_summary_json,
            f'Expected category summary JSON not found: {paths.category_summary_json}',
        ),
        (
            paths.manifest_with_testcase_flows_xml,
            'Expected manifest_with_testcase_flows.xml not found: '
            f'{paths.manifest_with_testcase_flows_xml}',
        ),
        (
            paths.testcase_flow_summary_json,
            f'Expected testcase flow summary JSON not found: {paths.testcase_flow_summary_json}',
        ),
    ]
    for output_path, error_message in required_outputs:
        _require_exists(output_path, error_message)

    return results


def run_step03_infer_and_signature(
    *,
    paths: PipelinePaths,
    selected_taint_config: Path,
    files: List[str],
    all_cwes: bool,
    cwes: Optional[List[int]],
) -> tuple[Dict[str, object], Dict[str, object], Path]:
    infer_cmd = [
        sys.executable,
        str(paths.infer_script),
        '--pulse-taint-config',
        str(selected_taint_config),
        '--infer-results-root',
        str(paths.infer_results_root),
        '--signatures-root',
        str(paths.signatures_root),
        '--summary-json',
        str(paths.infer_summary_json),
    ]
    if files:
        for file_path in files:
            infer_cmd.extend(['--files', file_path])
    elif all_cwes:
        infer_cmd.append('--all')
    else:
        infer_cmd[2:2] = [str(x) for x in cwes or []]

    result = run_command(
        '03_infer_and_signature',
        infer_cmd,
        cwd=Path(PROJECT_HOME),
        logs_dir=paths.logs_dir,
    )

    _require_exists(
        paths.infer_summary_json, f'Infer summary JSON not found: {paths.infer_summary_json}'
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

    _require_exists(
        signature_non_empty_dir,
        f'Signature non_empty directory not found: {signature_non_empty_dir}',
    )

    return result, infer_summary, signature_non_empty_dir


def run_step04_trace_flow(
    *, paths: PipelinePaths, signature_non_empty_dir: Path
) -> Dict[str, object]:
    result = run_internal_step(
        '04_trace_flow_filter',
        logs_dir=paths.logs_dir,
        fn=lambda: _trace_flow.filter_traces_by_flow(
            flow_xml=paths.manifest_with_testcase_flows_xml,
            signatures_dir=signature_non_empty_dir,
            output_dir=paths.trace_dir,
        ),
    )
    _require_exists(
        paths.trace_strict_jsonl,
        f'Expected strict trace output not found: {paths.trace_strict_jsonl}',
    )
    return result


def run_step05_pair_trace(*, paths: PipelinePaths) -> Dict[str, object]:
    result = run_internal_step(
        '05_pair_trace_dataset',
        logs_dir=paths.logs_dir,
        fn=lambda: _pair_trace.build_paired_trace_dataset(
            trace_jsonl=paths.trace_strict_jsonl,
            output_dir=paths.pair_dir,
            overwrite=False,
            run_dir=paths.run_dir,
        ),
    )
    _require_exists(paths.pairs_jsonl, f'Expected pairs output not found: {paths.pairs_jsonl}')
    _require_exists(
        paths.paired_signatures_dir,
        f'Expected paired signatures dir not found: {paths.paired_signatures_dir}',
    )
    _require_exists(
        paths.paired_trace_summary_json,
        f'Expected paired trace summary not found: {paths.paired_trace_summary_json}',
    )
    return result


def run_step06_slices(*, paths: PipelinePaths) -> Dict[str, object]:
    result = run_internal_step(
        '06_generate_slices',
        logs_dir=paths.logs_dir,
        fn=lambda: _slices.generate_slices(
            signature_db_dir=paths.paired_signatures_dir,
            output_dir=paths.slice_stage_dir,
            overwrite=False,
            run_dir=paths.run_dir,
        ),
    )
    _require_exists(paths.slice_dir, f'Expected slice dir not found: {paths.slice_dir}')
    _require_exists(
        paths.slice_summary_json,
        f'Expected slice summary not found: {paths.slice_summary_json}',
    )
    return result


def run_step07_dataset_export(
    *,
    paths: PipelinePaths,
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
) -> Dict[str, object]:
    result = run_internal_step(
        '07_dataset_export',
        logs_dir=paths.logs_dir,
        fn=lambda: export_primary_dataset(
            PrimaryDatasetExportParams(
                pairs_jsonl=paths.pairs_jsonl,
                paired_signatures_dir=paths.paired_signatures_dir,
                slice_dir=paths.slice_dir,
                output_dir=paths.dataset_stage_dir,
                split_seed=pair_split_seed,
                train_ratio=pair_train_ratio,
                dedup_mode=dedup_mode,
            )
        ).to_payload(),
    )

    required_outputs = [
        (
            paths.normalized_slices_dir,
            f'Expected normalized slices dir not found: {paths.normalized_slices_dir}',
        ),
        (
            paths.real_vul_data_csv,
            f'Expected Real_Vul_data.csv not found: {paths.real_vul_data_csv}',
        ),
        (
            paths.real_vul_data_dedup_dropped_csv,
            'Expected Real_Vul_data dedup dropped CSV not found: '
            f'{paths.real_vul_data_dedup_dropped_csv}',
        ),
        (
            paths.normalized_token_counts_csv,
            f'Expected normalized token counts CSV not found: {paths.normalized_token_counts_csv}',
        ),
        (
            paths.slice_token_distribution_png,
            f'Expected token distribution plot not found: {paths.slice_token_distribution_png}',
        ),
        (
            paths.dataset_split_manifest_json,
            f'Expected dataset split manifest not found: {paths.dataset_split_manifest_json}',
        ),
        (
            paths.dataset_summary_json,
            f'Expected dataset summary JSON not found: {paths.dataset_summary_json}',
        ),
    ]
    for output_path, error_message in required_outputs:
        _require_exists(output_path, error_message)

    return result


def run_step07b_train_patched_counterparts(
    *, paths: PipelinePaths, dedup_mode: str
) -> Dict[str, object]:
    result = run_command(
        '07b_train_patched_counterparts_export',
        [
            sys.executable,
            str(paths.train_patched_counterparts_script),
            '--run-dir',
            str(paths.run_dir),
            '--dedup-mode',
            dedup_mode,
        ],
        cwd=Path(PROJECT_HOME),
        logs_dir=paths.logs_dir,
    )

    required_outputs = [
        (
            paths.train_patched_counterparts_pairs_jsonl,
            'Expected train_patched_counterparts pairs output not found: '
            f'{paths.train_patched_counterparts_pairs_jsonl}',
        ),
        (
            paths.train_patched_counterparts_signatures_dir,
            'Expected train_patched_counterparts signatures dir not found: '
            f'{paths.train_patched_counterparts_signatures_dir}',
        ),
        (
            paths.train_patched_counterparts_selection_summary_json,
            'Expected train_patched_counterparts selection summary not found: '
            f'{paths.train_patched_counterparts_selection_summary_json}',
        ),
        (
            paths.train_patched_counterparts_slice_dir,
            'Expected train_patched_counterparts slice dir not found: '
            f'{paths.train_patched_counterparts_slice_dir}',
        ),
        (
            paths.train_patched_counterparts_slice_summary_json,
            'Expected train_patched_counterparts slice summary not found: '
            f'{paths.train_patched_counterparts_slice_summary_json}',
        ),
        (
            paths.train_patched_counterparts_csv,
            'Expected train_patched_counterparts CSV not found: '
            f'{paths.train_patched_counterparts_csv}',
        ),
        (
            paths.train_patched_counterparts_dedup_dropped_csv,
            'Expected train_patched_counterparts dedup dropped CSV not found: '
            f'{paths.train_patched_counterparts_dedup_dropped_csv}',
        ),
        (
            paths.train_patched_counterparts_slices_dir,
            'Expected train_patched_counterparts slices dir not found: '
            f'{paths.train_patched_counterparts_slices_dir}',
        ),
        (
            paths.train_patched_counterparts_token_counts_csv,
            'Expected train_patched_counterparts token counts CSV not found: '
            f'{paths.train_patched_counterparts_token_counts_csv}',
        ),
        (
            paths.train_patched_counterparts_token_distribution_png,
            'Expected train_patched_counterparts token distribution plot not found: '
            f'{paths.train_patched_counterparts_token_distribution_png}',
        ),
        (
            paths.train_patched_counterparts_split_manifest_json,
            'Expected train_patched_counterparts split manifest not found: '
            f'{paths.train_patched_counterparts_split_manifest_json}',
        ),
        (
            paths.train_patched_counterparts_summary_json,
            'Expected train_patched_counterparts summary JSON not found: '
            f'{paths.train_patched_counterparts_summary_json}',
        ),
    ]
    for output_path, error_message in required_outputs:
        _require_exists(output_path, error_message)

    return result


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
    cwes: Optional[List[int]],
    files: List[str],
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
    committed_taint_config: Path,
    paths: PipelinePaths,
    selected_taint_config: Optional[Path],
    selected_reason: Optional[str],
    steps: Dict[str, Dict[str, object]],
    infer_summary: Dict[str, object],
    signature_non_empty_dir: Optional[Path],
) -> Dict[str, object]:
    committed_taint_config = committed_taint_config.resolve()
    generated_taint_config = paths.generated_taint_config.resolve()
    selected_taint_config_str = (
        str(selected_taint_config.resolve()) if selected_taint_config else None
    )

    return {
        'status': status,
        'error_message': error_message,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': total_duration_sec,
        'pipeline_root': str(pipeline_root),
        'run_id': run_id,
        'run_dir': str(paths.run_dir),
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
            'manifest_with_comments_xml': str(paths.manifest_with_comments_xml),
            'generated_taint_config': str(paths.generated_taint_config),
            'manifest_with_testcase_flows_xml': str(paths.manifest_with_testcase_flows_xml),
            'infer_summary_json': str(paths.infer_summary_json),
            'signature_non_empty_dir': str(signature_non_empty_dir)
            if signature_non_empty_dir
            else None,
            'trace_flow_match_strict_jsonl': str(paths.trace_strict_jsonl),
            'pairs_jsonl': str(paths.pairs_jsonl),
            'leftover_counterparts_jsonl': str(paths.leftover_counterparts_jsonl),
            'paired_signatures_dir': str(paths.paired_signatures_dir),
            'paired_trace_summary_json': str(paths.paired_trace_summary_json),
            'train_patched_counterparts_pairs_jsonl': str(
                paths.train_patched_counterparts_pairs_jsonl
            ),
            'train_patched_counterparts_signatures_dir': str(
                paths.train_patched_counterparts_signatures_dir
            ),
            'train_patched_counterparts_selection_summary_json': str(
                paths.train_patched_counterparts_selection_summary_json
            ),
            'slice_dir': str(paths.slice_dir),
            'slice_summary_json': str(paths.slice_summary_json),
            'train_patched_counterparts_slice_dir': str(paths.train_patched_counterparts_slice_dir),
            'train_patched_counterparts_slice_summary_json': str(
                paths.train_patched_counterparts_slice_summary_json
            ),
            'dataset_export_dir': str(paths.dataset_stage_dir),
            'normalized_slices_dir': str(paths.normalized_slices_dir),
            'real_vul_data_csv': str(paths.real_vul_data_csv),
            'real_vul_data_dedup_dropped_csv': str(paths.real_vul_data_dedup_dropped_csv),
            'normalized_token_counts_csv': str(paths.normalized_token_counts_csv),
            'slice_token_distribution_png': str(paths.slice_token_distribution_png),
            'dataset_split_manifest_json': str(paths.dataset_split_manifest_json),
            'dataset_summary_json': str(paths.dataset_summary_json),
            'train_patched_counterparts_csv': str(paths.train_patched_counterparts_csv),
            'train_patched_counterparts_dedup_dropped_csv': str(
                paths.train_patched_counterparts_dedup_dropped_csv
            ),
            'train_patched_counterparts_slices_dir': str(
                paths.train_patched_counterparts_slices_dir
            ),
            'train_patched_counterparts_token_counts_csv': str(
                paths.train_patched_counterparts_token_counts_csv
            ),
            'train_patched_counterparts_token_distribution_png': str(
                paths.train_patched_counterparts_token_distribution_png
            ),
            'train_patched_counterparts_split_manifest_json': str(
                paths.train_patched_counterparts_split_manifest_json
            ),
            'train_patched_counterparts_summary_json': str(
                paths.train_patched_counterparts_summary_json
            ),
        },
        'infer_summary': infer_summary,
    }


def main(
    cwes: Optional[List[int]] = typer.Argument(None),
    all_cwes: bool = typer.Option(
        False, '--all', help='Run the pipeline for all CWEs in the testcase directory'
    ),
    files: List[str] = typer.Option(
        [],
        '--files',
        help='Run infer for specific files (repeatable); if set, cwes and --all are ignored',
    ),
    manifest: Path = typer.Option(
        Path(PROJECT_HOME)
        / 'experiments'
        / 'epic001_manifest_comment_scan'
        / 'inputs'
        / 'manifest.xml',
        '--manifest',
        help='Input manifest.xml path',
    ),
    source_root: Path = typer.Option(
        Path(PROJECT_HOME) / 'juliet-test-suite-v1.3' / 'C',
        '--source-root',
        help='Juliet C source root',
    ),
    pipeline_root: Path = typer.Option(
        Path(RESULT_DIR) / 'pipeline-runs',
        '--pipeline-root',
        help='Root directory for pipeline runs',
    ),
    run_id: Optional[str] = typer.Option(
        None, '--run-id', help='Run id under pipeline root (default: run-<YYYY.MM.DD-HH:MM:SS>)'
    ),
    committed_taint_config: Path = typer.Option(
        Path(PULSE_TAINT_CONFIG),
        '--committed-taint-config',
        help='Committed taint config path for fallback/reference',
    ),
    pair_split_seed: int = typer.Option(
        1234, '--pair-split-seed', help='Random seed for pair-level train/test split'
    ),
    pair_train_ratio: float = typer.Option(
        0.8, '--pair-train-ratio', help='Train ratio for pair-level train/test split'
    ),
    dedup_mode: str = typer.Option(
        'row', '--dedup-mode', help='Normalized-slice dedup mode before split/export: none or row'
    ),
):
    _validate_main_inputs(
        manifest=manifest,
        source_root=source_root,
        committed_taint_config=committed_taint_config,
        cwes=cwes,
        all_cwes=all_cwes,
        files=files,
        pair_train_ratio=pair_train_ratio,
        dedup_mode=dedup_mode,
    )

    if run_id is None:
        run_id = f'run-{now_ts()}'

    pipeline_root = pipeline_root.resolve()
    run_dir = (pipeline_root / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    paths = PipelinePaths.from_run_dir(run_dir=run_dir, source_root=source_root.resolve())

    started_at = now_iso_utc()
    start_perf = time.perf_counter()
    steps: Dict[str, Dict[str, object]] = {}
    status = 'success'
    error_message: Optional[str] = None
    selected_taint_config: Optional[Path] = None
    selected_reason: Optional[str] = None
    infer_summary: Dict[str, object] = {}
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
    total_duration_sec = round(time.perf_counter() - start_perf, 6)

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

    paths.run_summary_path.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )

    print(json.dumps(summary_payload, ensure_ascii=False))

    if status != 'success':
        raise typer.Exit(code=1)


if __name__ == '__main__':
    typer.run(main)
