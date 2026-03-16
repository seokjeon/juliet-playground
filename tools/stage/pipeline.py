#!/usr/bin/env python3
from __future__ import annotations

import datetime
import hashlib
import io
import json
import random
import shlex
import subprocess
import sys
import time
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import typer
from shared import step07 as _step07_shared
from shared.paths import PROJECT_HOME, PULSE_TAINT_CONFIG, RESULT_DIR

from stage import pair_trace as _pair_trace
from stage import slices as _slices
from stage import trace_flow as _trace_flow

CPP_LIKE_SUFFIXES = {'.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hh', '.hxx'}
ROLE_SORT_ORDER = {'b2b': 0, 'counterpart': 1}
PROJECT_HOME_PATH = Path(PROJECT_HOME).resolve()

normalize_artifact_path = _step07_shared.normalize_artifact_path
unique_in_order = _step07_shared.unique_in_order
build_dedup_audit_row = _step07_shared.build_dedup_audit_row
extract_std_bug_trace = _step07_shared.extract_std_bug_trace
load_tree_sitter_parsers = _step07_shared.load_tree_sitter_parsers
candidate_languages_for_source = _step07_shared.candidate_languages_for_source
node_text = _step07_shared.node_text
extract_function_name_from_declarator = _step07_shared.extract_function_name_from_declarator
extract_defined_function_names = _step07_shared.extract_defined_function_names
dedupe_paths = _step07_shared.dedupe_paths
build_source_file_candidates = _step07_shared.build_source_file_candidates
lex_c_like = _step07_shared.lex_c_like
previous_meaningful_token = _step07_shared.previous_meaningful_token
next_meaningful_token = _step07_shared.next_meaningful_token
normalize_slice_function_names = _step07_shared.normalize_slice_function_names
find_slice_path = _step07_shared.find_slice_path
compact_code_for_hash = _step07_shared.compact_code_for_hash
normalized_code_md5 = _step07_shared.normalized_code_md5
dedupe_pairs_by_normalized_rows = _step07_shared.dedupe_pairs_by_normalized_rows


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


def collect_defined_function_names(
    source_path: Path, parsers: dict[str, object]
) -> tuple[set[str], str | None]:
    try:
        source_bytes = source_path.read_bytes()
    except Exception as exc:
        return set(), f'read_error:{exc}'

    last_error: str | None = None
    for language_name in candidate_languages_for_source(source_path):
        parser = parsers.get(language_name)
        if parser is None:
            continue
        try:
            tree = parser.parse(source_bytes)
            return extract_defined_function_names(tree.root_node, source_bytes), None
        except Exception as exc:  # pragma: no cover - parser errors are rare and data-dependent
            last_error = f'{language_name}:{exc}'

    if not parsers:
        return set(), 'parser_unavailable'
    return set(), last_error or 'parse_failed'


def load_pairs_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            pair_id = obj.get('pair_id')
            testcase_key = obj.get('testcase_key')
            if not pair_id or not testcase_key:
                raise ValueError(f'Missing pair_id/testcase_key at line {lineno} in {path}')
            records.append(obj)
    return records


def compute_pair_split(pair_ids: list[str], train_ratio: float, seed: int) -> dict[str, str]:
    keys = sorted(set(pair_ids))
    shuffled = list(keys)
    random.Random(seed).shuffle(shuffled)

    test_ratio = 1.0 - train_ratio
    test_count = int(round(len(shuffled) * test_ratio))
    if len(shuffled) > 1:
        test_count = max(1, min(len(shuffled) - 1, test_count))
    else:
        test_count = 0

    test_keys = set(shuffled[:test_count])
    split_map: dict[str, str] = {}
    for key in shuffled:
        split_map[key] = 'test' if key in test_keys else 'train_val'
    return split_map


def export_dataset_from_pipeline(
    *,
    pairs_jsonl: Path,
    paired_signatures_dir: Path,
    slice_dir: Path,
    output_dir: Path,
    split_seed: int,
    train_ratio: float,
    dedup_mode: str,
) -> dict[str, object]:
    if not pairs_jsonl.exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {pairs_jsonl}')
    if not paired_signatures_dir.exists():
        raise FileNotFoundError(f'Paired signatures dir not found: {paired_signatures_dir}')
    if not slice_dir.exists():
        raise FileNotFoundError(f'Slice dir not found: {slice_dir}')
    if not (0.0 < train_ratio < 1.0):
        raise ValueError(f'train_ratio must be between 0 and 1: {train_ratio}')
    if dedup_mode not in {'none', 'row'}:
        raise ValueError(f'Unsupported dedup_mode: {dedup_mode}')

    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_slices_dir = output_dir / 'normalized_slices'
    real_vul_data_csv = output_dir / 'Real_Vul_data.csv'
    dedup_dropped_csv = output_dir / 'Real_Vul_data_dedup_dropped.csv'
    normalized_token_counts_csv = output_dir / 'normalized_token_counts.csv'
    slice_token_distribution_png = output_dir / 'slice_token_distribution.png'
    split_manifest_json = output_dir / 'split_manifest.json'
    summary_json = output_dir / 'summary.json'

    pairs = load_pairs_jsonl(pairs_jsonl)

    result = _step07_shared.run_step07_export_core(
        pairs=pairs,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        csv_path=real_vul_data_csv,
        dedup_dropped_csv=dedup_dropped_csv,
        normalized_slices_dir=normalized_slices_dir,
        token_counts_csv=normalized_token_counts_csv,
        token_distribution_png=slice_token_distribution_png,
        split_manifest_json=split_manifest_json,
        summary_json=summary_json,
        dedup_mode=dedup_mode,
        split_assignments_fn=lambda pair_ids: compute_pair_split(
            pair_ids, train_ratio=train_ratio, seed=split_seed
        ),
        summary_metadata={
            'pairs_jsonl': str(pairs_jsonl),
            'paired_signatures_dir': str(paired_signatures_dir),
            'slice_dir': str(slice_dir),
            'output_dir': str(output_dir),
            'real_vul_data_csv': str(real_vul_data_csv),
            'normalized_token_counts_csv': str(normalized_token_counts_csv),
            'slice_token_distribution_png': str(slice_token_distribution_png),
            'seed': split_seed,
            'train_ratio': train_ratio,
            'test_ratio': round(1.0 - train_ratio, 6),
        },
        split_manifest_metadata={
            'output_dir': str(output_dir),
            'pairs_jsonl': str(pairs_jsonl),
            'paired_signatures_dir': str(paired_signatures_dir),
            'slice_dir': str(slice_dir),
            'split_unit': 'pair_id',
            'train_ratio': train_ratio,
            'test_ratio': round(1.0 - train_ratio, 6),
            'seed': split_seed,
        },
        collect_defined_function_names_fn=collect_defined_function_names,
        build_source_file_candidates_fn=build_source_file_candidates,
    )

    return {
        'summary_json': str(result['summary_json']),
        'output_dir': str(output_dir),
        'normalized_slices_dir': str(result['normalized_slices_dir']),
        'real_vul_data_csv': str(real_vul_data_csv),
        'dedup_dropped_csv': str(result['dedup_dropped_csv']),
        'normalized_token_counts_csv': str(result['token_counts_csv']),
        'slice_token_distribution_png': str(result['token_distribution_png']),
        'split_manifest_json': str(result['split_manifest_json']),
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

    if run_id is None:
        run_id = f'run-{now_ts()}'

    pipeline_root = pipeline_root.resolve()
    run_dir = (pipeline_root / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    # Paths per stage
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
    train_patched_counterparts_signatures_dir = pair_dir / 'train_patched_counterparts_signatures'
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
    train_patched_counterparts_slices_dir = dataset_stage_dir / 'train_patched_counterparts_slices'
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
        # Step 01: manifest -> manifest_with_comments.xml
        steps['01_manifest_comment_scan'] = run_command(
            '01_manifest_comment_scan',
            [
                sys.executable,
                str(scan_script),
                '--manifest',
                str(manifest),
                '--source-root',
                str(source_root),
                '--output-xml',
                str(manifest_with_comments_xml),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        # Step 02a: with_comments -> taint config
        steps['02a_code_field_inventory'] = run_command(
            '02a_code_field_inventory',
            [
                sys.executable,
                str(code_field_script),
                '--input-xml',
                str(manifest_with_comments_xml),
                '--source-root',
                str(source_root),
                '--output-dir',
                str(taint_dir),
                '--pulse-taint-config-output',
                str(generated_taint_config),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        # Step 02b-1: function inventory
        steps['02b_function_inventory_extract'] = run_command(
            '02b_function_inventory_extract',
            [
                sys.executable,
                str(function_inventory_script),
                '--input-xml',
                str(manifest_with_comments_xml),
                '--output-csv',
                str(function_names_unique_csv),
                '--output-summary',
                str(function_inventory_summary_json),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        # Step 02b-2: categorize functions
        steps['02b_function_inventory_categorize'] = run_command(
            '02b_function_inventory_categorize',
            [
                sys.executable,
                str(categorize_script),
                '--input-csv',
                str(function_names_unique_csv),
                '--manifest-xml',
                str(manifest_with_comments_xml),
                '--source-root',
                str(source_testcases_root),
                '--output-jsonl',
                str(function_names_categorized_jsonl),
                '--output-nested-json',
                str(grouped_family_role_json),
                '--output-summary',
                str(category_summary_json),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        # Step 02b-3: build manifest_with_testcase_flows.xml
        steps['02b_testcase_flow_partition'] = run_command(
            '02b_testcase_flow_partition',
            [
                sys.executable,
                str(flow_partition_script),
                '--input-xml',
                str(manifest_with_comments_xml),
                '--function-categories-jsonl',
                str(function_names_categorized_jsonl),
                '--output-xml',
                str(manifest_with_testcase_flows_xml),
                '--summary-json',
                str(testcase_flow_summary_json),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if generated_taint_config.exists():
            selected_taint_config = generated_taint_config
            selected_reason = 'generated'
        else:
            selected_taint_config = committed_taint_config.resolve()
            selected_reason = 'fallback_committed'

        # Step 03: infer + signature
        infer_cmd = [
            sys.executable,
            str(infer_script),
            '--pulse-taint-config',
            str(selected_taint_config),
            '--infer-results-root',
            str(infer_results_root),
            '--signatures-root',
            str(signatures_root),
            '--summary-json',
            str(infer_summary_json),
        ]
        if files:
            for f in files:
                infer_cmd.extend(['--files', f])
        elif all_cwes:
            infer_cmd.append('--all')
        else:
            infer_cmd[2:2] = [str(x) for x in cwes or []]

        steps['03_infer_and_signature'] = run_command(
            '03_infer_and_signature',
            infer_cmd,
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if not infer_summary_json.exists():
            raise RuntimeError(f'Infer summary JSON not found: {infer_summary_json}')
        infer_summary = json.loads(infer_summary_json.read_text(encoding='utf-8'))

        signature_non_empty_raw = infer_summary.get('signature_non_empty_dir')
        if signature_non_empty_raw:
            signature_non_empty_dir = Path(signature_non_empty_raw)
        else:
            signature_output_dir = infer_summary.get('signature_output_dir')
            if not signature_output_dir:
                raise RuntimeError('signature_output_dir not found in infer summary')
            signature_non_empty_dir = Path(signature_output_dir) / 'non_empty'

        if not signature_non_empty_dir.exists():
            raise RuntimeError(
                f'Signature non_empty directory not found: {signature_non_empty_dir}'
            )

        # Step 04: filter traces by testcase flow
        steps['04_trace_flow_filter'] = run_internal_step(
            '04_trace_flow_filter',
            logs_dir=logs_dir,
            fn=lambda: _trace_flow.filter_traces_by_flow(
                flow_xml=manifest_with_testcase_flows_xml,
                signatures_dir=signature_non_empty_dir,
                output_dir=trace_dir,
            ),
        )

        if not trace_strict_jsonl.exists():
            raise RuntimeError(f'Expected strict trace output not found: {trace_strict_jsonl}')

        # Step 05: pair strict traces and export signature-style testcase dirs
        steps['05_pair_trace_dataset'] = run_internal_step(
            '05_pair_trace_dataset',
            logs_dir=logs_dir,
            fn=lambda: _pair_trace.build_paired_trace_dataset(
                trace_jsonl=trace_strict_jsonl,
                output_dir=pair_dir,
                overwrite=False,
                run_dir=run_dir,
            ),
        )

        if not pairs_jsonl.exists():
            raise RuntimeError(f'Expected pairs output not found: {pairs_jsonl}')
        if not paired_signatures_dir.exists():
            raise RuntimeError(f'Expected paired signatures dir not found: {paired_signatures_dir}')
        if not paired_trace_summary_json.exists():
            raise RuntimeError(
                f'Expected paired trace summary not found: {paired_trace_summary_json}'
            )

        # Step 06: generate source slices from paired signatures
        steps['06_generate_slices'] = run_internal_step(
            '06_generate_slices',
            logs_dir=logs_dir,
            fn=lambda: _slices.generate_slices(
                signature_db_dir=paired_signatures_dir,
                output_dir=slice_stage_dir,
                overwrite=False,
                run_dir=run_dir,
            ),
        )

        if not slice_dir.exists():
            raise RuntimeError(f'Expected slice dir not found: {slice_dir}')
        if not slice_summary_json.exists():
            raise RuntimeError(f'Expected slice summary not found: {slice_summary_json}')

        # Step 07: normalize slices, tokenize, filter, split, and export dataset
        steps['07_dataset_export'] = run_internal_step(
            '07_dataset_export',
            logs_dir=logs_dir,
            fn=lambda: export_dataset_from_pipeline(
                pairs_jsonl=pairs_jsonl,
                paired_signatures_dir=paired_signatures_dir,
                slice_dir=slice_dir,
                output_dir=dataset_stage_dir,
                split_seed=pair_split_seed,
                train_ratio=pair_train_ratio,
                dedup_mode=dedup_mode,
            ),
        )

        if not normalized_slices_dir.exists():
            raise RuntimeError(f'Expected normalized slices dir not found: {normalized_slices_dir}')
        if not real_vul_data_csv.exists():
            raise RuntimeError(f'Expected Real_Vul_data.csv not found: {real_vul_data_csv}')
        if not real_vul_data_dedup_dropped_csv.exists():
            raise RuntimeError(
                'Expected Real_Vul_data dedup dropped CSV not found: '
                f'{real_vul_data_dedup_dropped_csv}'
            )
        if not normalized_token_counts_csv.exists():
            raise RuntimeError(
                f'Expected normalized token counts CSV not found: {normalized_token_counts_csv}'
            )
        if not slice_token_distribution_png.exists():
            raise RuntimeError(
                f'Expected token distribution plot not found: {slice_token_distribution_png}'
            )
        if not dataset_split_manifest_json.exists():
            raise RuntimeError(
                f'Expected dataset split manifest not found: {dataset_split_manifest_json}'
            )
        if not dataset_summary_json.exists():
            raise RuntimeError(f'Expected dataset summary JSON not found: {dataset_summary_json}')

        # Step 07b: export train-only patched counterparts for evaluation
        steps['07b_train_patched_counterparts_export'] = run_command(
            '07b_train_patched_counterparts_export',
            [
                sys.executable,
                str(train_patched_counterparts_script),
                '--run-dir',
                str(run_dir),
                '--dedup-mode',
                dedup_mode,
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if not train_patched_counterparts_pairs_jsonl.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts pairs output not found: '
                f'{train_patched_counterparts_pairs_jsonl}'
            )
        if not train_patched_counterparts_signatures_dir.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts signatures dir not found: '
                f'{train_patched_counterparts_signatures_dir}'
            )
        if not train_patched_counterparts_selection_summary_json.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts selection summary not found: '
                f'{train_patched_counterparts_selection_summary_json}'
            )
        if not train_patched_counterparts_slice_dir.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts slice dir not found: '
                f'{train_patched_counterparts_slice_dir}'
            )
        if not train_patched_counterparts_slice_summary_json.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts slice summary not found: '
                f'{train_patched_counterparts_slice_summary_json}'
            )
        if not train_patched_counterparts_csv.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts CSV not found: '
                f'{train_patched_counterparts_csv}'
            )
        if not train_patched_counterparts_dedup_dropped_csv.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts dedup dropped CSV not found: '
                f'{train_patched_counterparts_dedup_dropped_csv}'
            )
        if not train_patched_counterparts_slices_dir.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts slices dir not found: '
                f'{train_patched_counterparts_slices_dir}'
            )
        if not train_patched_counterparts_token_counts_csv.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts token counts CSV not found: '
                f'{train_patched_counterparts_token_counts_csv}'
            )
        if not train_patched_counterparts_token_distribution_png.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts token distribution plot not found: '
                f'{train_patched_counterparts_token_distribution_png}'
            )
        if not train_patched_counterparts_split_manifest_json.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts split manifest not found: '
                f'{train_patched_counterparts_split_manifest_json}'
            )
        if not train_patched_counterparts_summary_json.exists():
            raise RuntimeError(
                'Expected train_patched_counterparts summary JSON not found: '
                f'{train_patched_counterparts_summary_json}'
            )

    except Exception as exc:
        status = 'failed'
        error_message = str(exc)

    ended_at = now_iso_utc()
    total_duration_sec = round(time.perf_counter() - start_perf, 6)

    committed_taint_config = committed_taint_config.resolve()
    generated_taint_config = generated_taint_config.resolve()
    selected_taint_config_str = (
        str(selected_taint_config.resolve()) if selected_taint_config else None
    )

    summary_payload = {
        'status': status,
        'error_message': error_message,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': total_duration_sec,
        'pipeline_root': str(pipeline_root),
        'run_id': run_id,
        'run_dir': str(run_dir),
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
            'manifest_with_comments_xml': str(manifest_with_comments_xml),
            'generated_taint_config': str(generated_taint_config),
            'manifest_with_testcase_flows_xml': str(manifest_with_testcase_flows_xml),
            'infer_summary_json': str(infer_summary_json),
            'signature_non_empty_dir': str(signature_non_empty_dir)
            if signature_non_empty_dir
            else None,
            'trace_flow_match_strict_jsonl': str(trace_strict_jsonl),
            'pairs_jsonl': str(pairs_jsonl),
            'leftover_counterparts_jsonl': str(leftover_counterparts_jsonl),
            'paired_signatures_dir': str(paired_signatures_dir),
            'paired_trace_summary_json': str(paired_trace_summary_json),
            'train_patched_counterparts_pairs_jsonl': str(train_patched_counterparts_pairs_jsonl),
            'train_patched_counterparts_signatures_dir': str(
                train_patched_counterparts_signatures_dir
            ),
            'train_patched_counterparts_selection_summary_json': str(
                train_patched_counterparts_selection_summary_json
            ),
            'slice_dir': str(slice_dir),
            'slice_summary_json': str(slice_summary_json),
            'train_patched_counterparts_slice_dir': str(train_patched_counterparts_slice_dir),
            'train_patched_counterparts_slice_summary_json': str(
                train_patched_counterparts_slice_summary_json
            ),
            'dataset_export_dir': str(dataset_stage_dir),
            'normalized_slices_dir': str(normalized_slices_dir),
            'real_vul_data_csv': str(real_vul_data_csv),
            'real_vul_data_dedup_dropped_csv': str(real_vul_data_dedup_dropped_csv),
            'normalized_token_counts_csv': str(normalized_token_counts_csv),
            'slice_token_distribution_png': str(slice_token_distribution_png),
            'dataset_split_manifest_json': str(dataset_split_manifest_json),
            'dataset_summary_json': str(dataset_summary_json),
            'train_patched_counterparts_csv': str(train_patched_counterparts_csv),
            'train_patched_counterparts_dedup_dropped_csv': str(
                train_patched_counterparts_dedup_dropped_csv
            ),
            'train_patched_counterparts_slices_dir': str(train_patched_counterparts_slices_dir),
            'train_patched_counterparts_token_counts_csv': str(
                train_patched_counterparts_token_counts_csv
            ),
            'train_patched_counterparts_token_distribution_png': str(
                train_patched_counterparts_token_distribution_png
            ),
            'train_patched_counterparts_split_manifest_json': str(
                train_patched_counterparts_split_manifest_json
            ),
            'train_patched_counterparts_summary_json': str(train_patched_counterparts_summary_json),
        },
        'infer_summary': infer_summary,
    }

    run_summary_path.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )

    print(json.dumps(summary_payload, ensure_ascii=False))

    if status != 'success':
        raise typer.Exit(code=1)


if __name__ == '__main__':
    typer.run(main)
