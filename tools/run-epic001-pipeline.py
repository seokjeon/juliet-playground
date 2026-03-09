#!/usr/bin/env python3
from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import time
from typing import Dict, List, Optional

import typer

from paths import PROJECT_HOME, RESULT_DIR, PULSE_TAINT_CONFIG


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


def run_command(step_key: str, cmd: List[str], cwd: Path,
                logs_dir: Path) -> Dict[str, object]:
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
            f'[{step_key}] failed with return code {proc.returncode}: {result["command"]}')
    return result


def main(
    cwes: Optional[List[int]] = typer.Argument(None),
    files: List[str] = typer.Option(
        [], '--files', help='Run infer for specific files (repeatable); if set, cwes are ignored'),
    manifest: Path = typer.Option(
        Path(PROJECT_HOME) / 'experiments' / 'epic001_manifest_comment_scan' / 'inputs' / 'manifest.xml',
        '--manifest',
        help='Input manifest.xml path'),
    source_root: Path = typer.Option(
        Path(PROJECT_HOME) / 'juliet-test-suite-v1.3' / 'C',
        '--source-root',
        help='Juliet C source root'),
    pipeline_root: Path = typer.Option(
        Path(RESULT_DIR) / 'pipeline-runs',
        '--pipeline-root',
        help='Root directory for pipeline runs'),
    run_id: Optional[str] = typer.Option(
        None,
        '--run-id',
        help='Run id under pipeline root (default: run-<YYYY.MM.DD-HH:MM:SS>)'),
    committed_taint_config: Path = typer.Option(
        Path(PULSE_TAINT_CONFIG),
        '--committed-taint-config',
        help='Committed taint config path for fallback/reference'),
    pair_split_seed: int = typer.Option(
        1234,
        '--pair-split-seed',
        help='Random seed for testcase-level paired trace train/test split'),
    pair_train_ratio: float = typer.Option(
        0.8,
        '--pair-train-ratio',
        help='Train ratio for testcase-level paired trace train/test split'),
):
    if not manifest.exists():
        raise typer.BadParameter(f'Manifest not found: {manifest}')
    if not source_root.exists():
        raise typer.BadParameter(f'Source root not found: {source_root}')
    if not committed_taint_config.exists():
        raise typer.BadParameter(f'Committed taint config not found: {committed_taint_config}')
    if not files and not cwes:
        raise typer.BadParameter('Provide cwes or use --files')

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
    split_manifest_json = pair_dir / 'split_manifest.json'
    paired_signatures_dir = pair_dir / 'paired_signatures'
    paired_trace_summary_json = pair_dir / 'summary.json'
    run_summary_path = run_dir / 'run_summary.json'

    source_testcases_root = source_root / 'testcases'

    scan_script = Path(PROJECT_HOME) / 'experiments' / 'epic001_manifest_comment_scan' / 'scripts' / 'scan_manifest_comments.py'
    code_field_script = Path(PROJECT_HOME) / 'experiments' / 'epic001a_code_field_inventory' / 'scripts' / 'extract_unique_code_fields.py'
    function_inventory_script = Path(PROJECT_HOME) / 'experiments' / 'epic001b_function_inventory' / 'scripts' / 'extract_function_inventory.py'
    categorize_script = Path(PROJECT_HOME) / 'experiments' / 'epic001b_function_inventory' / 'scripts' / 'categorize_function_names.py'
    flow_partition_script = Path(PROJECT_HOME) / 'experiments' / 'epic001c_testcase_flow_partition' / 'scripts' / 'add_flow_tags_to_testcase.py'
    infer_script = Path(PROJECT_HOME) / 'tools' / 'run-infer-all-juliet.py'
    filter_script = Path(PROJECT_HOME) / 'experiments' / 'epic001d_trace_flow_filter' / 'scripts' / 'filter_traces_by_flow.py'
    pair_script = Path(PROJECT_HOME) / 'tools' / 'build-paired-trace-signatures.py'

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
                '--manifest', str(manifest),
                '--source-root', str(source_root),
                '--output-xml', str(manifest_with_comments_xml),
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
                '--input-xml', str(manifest_with_comments_xml),
                '--source-root', str(source_root),
                '--output-dir', str(taint_dir),
                '--pulse-taint-config-output', str(generated_taint_config),
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
                '--input-xml', str(manifest_with_comments_xml),
                '--output-csv', str(function_names_unique_csv),
                '--output-summary', str(function_inventory_summary_json),
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
                '--input-csv', str(function_names_unique_csv),
                '--manifest-xml', str(manifest_with_comments_xml),
                '--source-root', str(source_testcases_root),
                '--output-jsonl', str(function_names_categorized_jsonl),
                '--output-nested-json', str(grouped_family_role_json),
                '--output-summary', str(category_summary_json),
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
                '--input-xml', str(manifest_with_comments_xml),
                '--function-categories-jsonl', str(function_names_categorized_jsonl),
                '--output-xml', str(manifest_with_testcase_flows_xml),
                '--summary-json', str(testcase_flow_summary_json),
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
            '--pulse-taint-config', str(selected_taint_config),
            '--infer-results-root', str(infer_results_root),
            '--signatures-root', str(signatures_root),
            '--summary-json', str(infer_summary_json),
        ]
        if files:
            for f in files:
                infer_cmd.extend(['--files', f])
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
            raise RuntimeError(f'Signature non_empty directory not found: {signature_non_empty_dir}')

        # Step 04: filter traces by testcase flow
        steps['04_trace_flow_filter'] = run_command(
            '04_trace_flow_filter',
            [
                sys.executable,
                str(filter_script),
                '--flow-xml', str(manifest_with_testcase_flows_xml),
                '--signatures-dir', str(signature_non_empty_dir),
                '--output-dir', str(trace_dir),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if not trace_strict_jsonl.exists():
            raise RuntimeError(f'Expected strict trace output not found: {trace_strict_jsonl}')

        # Step 05: pair strict traces and export signature-style testcase dirs
        steps['05_pair_trace_dataset'] = run_command(
            '05_pair_trace_dataset',
            [
                sys.executable,
                str(pair_script),
                '--trace-jsonl', str(trace_strict_jsonl),
                '--output-dir', str(pair_dir),
                '--split-seed', str(pair_split_seed),
                '--train-ratio', str(pair_train_ratio),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if not pairs_jsonl.exists():
            raise RuntimeError(f'Expected pairs output not found: {pairs_jsonl}')
        if not paired_signatures_dir.exists():
            raise RuntimeError(f'Expected paired signatures dir not found: {paired_signatures_dir}')
        if not paired_trace_summary_json.exists():
            raise RuntimeError(f'Expected paired trace summary not found: {paired_trace_summary_json}')

    except Exception as exc:
        status = 'failed'
        error_message = str(exc)

    ended_at = now_iso_utc()
    total_duration_sec = round(time.perf_counter() - start_perf, 6)

    committed_taint_config = committed_taint_config.resolve()
    generated_taint_config = generated_taint_config.resolve()
    selected_taint_config_str = str(selected_taint_config.resolve()) if selected_taint_config else None

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
        'mode': 'files' if files else 'cwes',
        'cwes': cwes or [],
        'files': files,
        'pair_split_seed': pair_split_seed,
        'pair_train_ratio': pair_train_ratio,
        'committed_taint_config_path': str(committed_taint_config),
        'generated_taint_config_path': str(generated_taint_config),
        'selected_taint_config_path': selected_taint_config_str,
        'selected_reason': selected_reason,
        'sha256': {
            'committed_taint_config': sha256_file(committed_taint_config),
            'generated_taint_config': sha256_file(generated_taint_config),
            'selected_taint_config': sha256_file(Path(selected_taint_config_str)) if selected_taint_config_str else None,
        },
        'steps': steps,
        'outputs': {
            'manifest_with_comments_xml': str(manifest_with_comments_xml),
            'generated_taint_config': str(generated_taint_config),
            'manifest_with_testcase_flows_xml': str(manifest_with_testcase_flows_xml),
            'infer_summary_json': str(infer_summary_json),
            'signature_non_empty_dir': str(signature_non_empty_dir) if signature_non_empty_dir else None,
            'trace_flow_match_strict_jsonl': str(trace_strict_jsonl),
            'pairs_jsonl': str(pairs_jsonl),
            'leftover_counterparts_jsonl': str(leftover_counterparts_jsonl),
            'split_manifest_json': str(split_manifest_json),
            'paired_signatures_dir': str(paired_signatures_dir),
            'paired_trace_summary_json': str(paired_trace_summary_json),
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
