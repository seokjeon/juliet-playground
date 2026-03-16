import concurrent.futures
import csv
import datetime
import importlib.util
import json
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Dict, Generator, List, Optional, Set, Tuple

import typer
from shared.paths import (
    GLOBAL_INFER_RESULTS_DIR,
    INFER_BIN,
    INFER_RESULTS_DIR,
    JULIET_TESTCASE_DIR,
    PROJECT_HOME,
    PULSE_TAINT_CONFIG,
    RESULT_DIR,
)

TOTAL_CORES = os.cpu_count() or 4
# Conservative memory-aware parallelization to prevent OOM
# Each infer process uses ~500MB-1GB memory
CORES_PER_JOB = 1
MAX_PARALLEL_JOBS = TOTAL_CORES  # Conservative: one job per core
MAX_CWE_PARALLEL = 1  # Process CWEs sequentially to control memory usage
VALID_EXTENSIONS = {'c', 'cpp'}
WINDOWS_SPECIFIC_MARKERS = ('w32', 'wchar_t')


CaseGroup = Tuple[
    str, str, str, str, str, str
]  # (directory, cwe_num, cwe_name, variant, flow_id, extension)


def get_testcase_filename_regex() -> str:
    return (
        '^cwe'
        + '(?P<cwe_number>\\d+)'
        + '_'
        + '(?P<cwe_name>.*)'
        + '__'
        + '(?P<functional_variant_name>.*)'
        + '_'
        + '(?P<flow_variant_id>\\d+)'
        + '_?'
        + '(?P<subfile_id>[a-z]{1}|(bad)|(good(\\d)+)|(base)|(goodB2G)|(goodG2B))?'
        + '\\.'
        + '(?P<extension>c|cpp|java|h)$'
    )


TESTCASE_FILENAME_REGEX = re.compile(get_testcase_filename_regex(), re.IGNORECASE)


def find_cwe_dir(cwe_number: int) -> Optional[str]:
    prefix = f'CWE{cwe_number}_'
    for entry in os.listdir(JULIET_TESTCASE_DIR):
        if entry.startswith(prefix):
            return entry
    return None


def find_all_cwe_dirs() -> List[str]:
    """Find all CWE directories in the testcase directory."""
    cwe_dirs = []
    for entry in os.listdir(JULIET_TESTCASE_DIR):
        if entry.startswith('CWE') and os.path.isdir(os.path.join(JULIET_TESTCASE_DIR, entry)):
            cwe_dirs.append(entry)
    return sorted(cwe_dirs)


def iter_candidate_files(target_dir: str) -> Generator[str, None, None]:
    for entry in os.listdir(target_dir):
        file_path = os.path.join(target_dir, entry)
        if os.path.isdir(file_path):
            yield from iter_candidate_files(file_path)
            continue

        if '.' not in entry or 'CWE' not in entry:
            continue
        if any(marker in entry for marker in WINDOWS_SPECIFIC_MARKERS):
            continue

        _, extension = entry.rsplit('.', 1)
        if extension in VALID_EXTENSIONS:
            yield file_path


def parse_case_group(file_path: str) -> Optional[Tuple[CaseGroup, str, str, str, str]]:
    filename = os.path.basename(file_path)
    match = TESTCASE_FILENAME_REGEX.search(filename)
    if match is None:
        return None

    cwe_num = match.group('cwe_number')
    cwe_name = match.group('cwe_name')
    functional_variant_name = match.group('functional_variant_name')
    flow_variant_id = match.group('flow_variant_id')
    extension = match.group('extension').lower()

    if extension not in VALID_EXTENSIONS:
        return None

    filename_head = f'CWE{cwe_num}_{cwe_name}__{functional_variant_name}'
    group_key: CaseGroup = (
        os.path.dirname(file_path),
        cwe_num,
        cwe_name,
        functional_variant_name,
        flow_variant_id,
        extension,
    )
    return group_key, f'CWE{cwe_num}', filename_head, flow_variant_id, extension


def find_group_files(group_key: CaseGroup) -> List[str]:
    directory, cwe_num, cwe_name, functional_variant_name, flow_variant_id, extension = group_key
    matched_files: List[str] = []
    for entry in os.listdir(directory):
        candidate = os.path.join(directory, entry)
        if not os.path.isfile(candidate):
            continue
        parsed = parse_case_group(candidate)
        if parsed is None:
            continue
        candidate_group_key, _, _, _, candidate_extension = parsed
        if candidate_extension != extension:
            continue
        if candidate_group_key == group_key:
            matched_files.append(candidate)
    return sorted(matched_files)


def build_infer_command(
    target_files: List[str], extension: str, pulse_taint_config: str, cores: int = CORES_PER_JOB
) -> str:
    testcasesupport_dir = os.path.join(
        PROJECT_HOME, 'juliet-test-suite-v1.3', 'C', 'testcasesupport'
    )
    io_c = os.path.join(testcasesupport_dir, 'io.c')
    std_thread_c = os.path.join(testcasesupport_dir, 'std_thread.c')

    compiler = 'clang++' if extension == 'cpp' else 'clang'
    link_flag = ' -lpthread -lm'

    quoted_files = ' '.join(shlex.quote(file) for file in target_files)
    compile_cmd = (
        f'{compiler} -I {shlex.quote(testcasesupport_dir)} -D INCLUDEMAIN '
        f'{shlex.quote(io_c)} {shlex.quote(std_thread_c)} {quoted_files}{link_flag}'
    )
    return (
        f'{INFER_BIN} run -j {cores} '
        f'--pulse-taint-config {shlex.quote(pulse_taint_config)} -- {compile_cmd}'
    )


def run_case(result_path: str, infer_cmd: str, representative_file: str) -> Dict[str, object]:
    """Run a single infer case. Returns a result dict (thread/process safe)."""
    os.makedirs(result_path, exist_ok=True)
    result = subprocess.run(
        infer_cmd, shell=True, cwd=result_path, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    if result.returncode != 0:
        stderr_text = result.stderr.decode(errors='replace').strip()
        if stderr_text:
            print(f'[ERROR] infer failed for {representative_file}\n{stderr_text}')
        return {'status': 'error', 'file': representative_file}

    if b'No issues found' in result.stdout:
        return {'status': 'no_issue', 'file': representative_file}
    else:
        return {'status': 'issue', 'file': representative_file}


def _collect_results(futures: List, summary: Dict[str, object]) -> None:
    """Aggregate results from completed futures into summary."""
    for future in concurrent.futures.as_completed(futures):
        res = future.result()
        status = res['status']
        summary[status] += 1
        if status == 'no_issue':
            summary['no_issue_files'].append(res['file'])


def _run_tasks(tasks: List[Tuple[str, str, str]], summary: Dict[str, object]) -> None:
    """Run infer tasks in parallel with ProcessPoolExecutor."""
    if not tasks:
        return
    futures = []
    with concurrent.futures.ProcessPoolExecutor(max_workers=MAX_PARALLEL_JOBS) as executor:
        for result_path, infer_cmd, representative_file in tasks:
            futures.append(executor.submit(run_case, result_path, infer_cmd, representative_file))
        _collect_results(futures, summary)


def run_infer_all(cwe_dir: str, result_dir: str, pulse_taint_config: str) -> Dict[str, object]:
    processed_groups = set()
    summary: Dict[str, object] = {'issue': 0, 'no_issue': 0, 'error': 0, 'no_issue_files': []}
    start_time = time.time()
    target_dir = os.path.join(JULIET_TESTCASE_DIR, cwe_dir)

    tasks: List[Tuple[str, str, str]] = []
    for file_path in iter_candidate_files(target_dir):
        parsed = parse_case_group(file_path)
        if parsed is None:
            continue

        group_key, cwe_num, filename_head, filename_num, extension = parsed
        if group_key in processed_groups:
            continue

        processed_groups.add(group_key)
        result_path = os.path.join(result_dir, f'{cwe_num}_{filename_num}-{filename_head}')
        target_files = find_group_files(group_key)
        if not target_files:
            continue
        infer_cmd = build_infer_command(target_files, extension, pulse_taint_config)
        tasks.append((result_path, infer_cmd, file_path))

    _run_tasks(tasks, summary)

    summary['time'] = time.time() - start_time
    return summary


def run_infer_for_files(
    files: List[str], result_dir: str, pulse_taint_config: str
) -> Dict[str, object]:
    summary: Dict[str, object] = {'issue': 0, 'no_issue': 0, 'error': 0, 'no_issue_files': []}
    start_time = time.time()
    processed_targets: Set[Tuple[str, ...]] = set()

    tasks: List[Tuple[str, str, str]] = []
    for file_path in files:
        abs_file = os.path.abspath(file_path)
        if not os.path.isfile(abs_file):
            raise typer.BadParameter(f'File not found: {file_path}')

        filename = os.path.basename(abs_file)
        if '.' not in filename:
            raise typer.BadParameter(f'Invalid file (no extension): {file_path}')

        name_without_ext, extension = filename.rsplit('.', 1)
        if extension not in VALID_EXTENSIONS:
            raise typer.BadParameter(f'Unsupported extension for file: {file_path}')

        parsed = parse_case_group(abs_file)
        if parsed is not None:
            group_key, cwe_num, filename_head, filename_num, parsed_extension = parsed
            if parsed_extension != extension:
                raise typer.BadParameter(f'Extension mismatch in parsed testcase: {file_path}')
            target_key = ('group',) + group_key
            if target_key in processed_targets:
                continue
            processed_targets.add(target_key)
            target_files = find_group_files(group_key)
            if not target_files:
                raise typer.BadParameter(f'No grouped testcase files found for: {file_path}')
            result_name = f'{cwe_num}_{filename_num}-{filename_head}'
        else:
            target_key = ('single', abs_file)
            if target_key in processed_targets:
                continue
            processed_targets.add(target_key)
            target_files = [abs_file]
            result_name = f'FILE-{name_without_ext}'

        result_path = os.path.join(result_dir, result_name)
        infer_cmd = build_infer_command(target_files, extension, pulse_taint_config)
        tasks.append((result_path, infer_cmd, abs_file))

    _run_tasks(tasks, summary)

    summary['time'] = time.time() - start_time
    return summary


def generate_result_csv(result_map: Dict[object, Dict[str, object]], result_dir: str) -> Path:
    analysis_dir = os.path.join(result_dir, 'analysis')
    os.makedirs(analysis_dir, exist_ok=True)
    csv_path = os.path.join(analysis_dir, 'result.csv')
    with open(csv_path, 'w') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow(['CWE NUMBER', 'ALL_TESTCASES', 'TIME(s)', 'ISSUE', 'NO ISSUE', 'ERROR'])

        for cwe_number in result_map:
            cwe_number_info = result_map[cwe_number]

            elapsed_sec = cwe_number_info['time']
            issue = cwe_number_info['issue']
            no_issue = cwe_number_info['no_issue']
            error = cwe_number_info['error']
            total_cases = issue + no_issue + error

            writer.writerow([cwe_number, total_cases, elapsed_sec, issue, no_issue, error])
    return Path(csv_path)


def generate_no_issue_files(result_map: Dict[object, Dict[str, object]], result_dir: str) -> Path:
    analysis_dir = os.path.join(result_dir, 'analysis')
    os.makedirs(analysis_dir, exist_ok=True)
    txt_path = os.path.join(analysis_dir, 'no_issue_files.txt')
    with open(txt_path, 'w') as f:
        for cwe_number in result_map:
            no_issue_files = result_map[cwe_number]['no_issue_files']

            for file in no_issue_files:
                f.write(file)
                f.write('\n')
    return Path(txt_path)


def load_signature_module():
    module_path = os.path.join(PROJECT_HOME, 'tools', 'generate-signature.py')
    spec = importlib.util.spec_from_file_location('generate_signature_module', module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Failed to load signature module: {module_path}')

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _build_summary_by_target(
    result_map: Dict[object, Dict[str, object]],
) -> Dict[str, Dict[str, object]]:
    compact: Dict[str, Dict[str, object]] = {}
    for key, value in result_map.items():
        compact[str(key)] = {
            'issue': value['issue'],
            'no_issue': value['no_issue'],
            'error': value['error'],
            'time': value['time'],
            'total_cases': value['issue'] + value['no_issue'] + value['error'],
        }
    return compact


def main(
    cwes: Optional[List[int]] = typer.Argument(None),
    global_result: bool = typer.Option(False),
    all_cwes: bool = typer.Option(False, '--all', help='Run all CWEs in the testcase directory'),
    files: List[str] = typer.Option(
        [], '--files', help='Run infer for specific files (repeatable)'
    ),
    pulse_taint_config: Path = typer.Option(
        Path(PULSE_TAINT_CONFIG),
        '--pulse-taint-config',
        help='Pulse taint config path to pass to infer',
    ),
    infer_results_root: Optional[Path] = typer.Option(
        None, '--infer-results-root', help='Output root for infer-* run directories'
    ),
    signatures_root: Path = typer.Option(
        Path(RESULT_DIR) / 'signatures',
        '--signatures-root',
        help='Output root for signature directories',
    ),
    summary_json: Optional[Path] = typer.Option(
        None, '--summary-json', help='Optional JSON summary output path'
    ),
):

    pulse_taint_config = pulse_taint_config.resolve()
    if not pulse_taint_config.exists():
        raise typer.BadParameter(f'Pulse taint config not found: {pulse_taint_config}')

    if infer_results_root is None:
        infer_results_root = (
            Path(GLOBAL_INFER_RESULTS_DIR) if global_result else Path(INFER_RESULTS_DIR)
        )

    infer_results_root = infer_results_root.resolve()
    signatures_root = signatures_root.resolve()

    os.makedirs(infer_results_root, exist_ok=True)
    os.makedirs(signatures_root, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')
    infer_run_dir = infer_results_root / f'infer-{timestamp}'
    os.makedirs(infer_run_dir, exist_ok=True)

    result_map: Dict[object, Dict[str, object]] = {}
    if files:
        result_map['FILES'] = run_infer_for_files(
            files, str(infer_run_dir), str(pulse_taint_config)
        )
    elif all_cwes:
        cwe_dirs = find_all_cwe_dirs()
        for cwe_dir in cwe_dirs:
            result_map[cwe_dir] = run_infer_all(
                cwe_dir, str(infer_run_dir), str(pulse_taint_config)
            )
    else:
        if not cwes:
            raise typer.BadParameter('Provide cwes, use --all, or use --files')
        for cwe_number in cwes:
            cwe_dir = find_cwe_dir(cwe_number)
            if cwe_dir is None:
                continue
            result_map[cwe_number] = run_infer_all(
                cwe_dir, str(infer_run_dir), str(pulse_taint_config)
            )

    result_csv = generate_result_csv(result_map, str(infer_run_dir))
    no_issue_txt = generate_no_issue_files(result_map, str(infer_run_dir))

    signature_module = load_signature_module()
    signature_output_dir = signature_module.generate_signatures(
        input_dir=Path(infer_run_dir),
        output_root=Path(signatures_root),
        infer_run_name=Path(infer_run_dir).name,
    )
    signature_non_empty_dir = Path(signature_output_dir) / 'non_empty'

    compact = _build_summary_by_target(result_map)
    totals = {
        'issue': sum(v['issue'] for v in compact.values()),
        'no_issue': sum(v['no_issue'] for v in compact.values()),
        'error': sum(v['error'] for v in compact.values()),
        'total_cases': sum(v['total_cases'] for v in compact.values()),
        'elapsed_seconds': sum(float(v['time']) for v in compact.values()),
    }
    summary_payload = {
        'pulse_taint_config': str(pulse_taint_config),
        'infer_results_root': str(infer_results_root),
        'infer_run_dir': str(infer_run_dir),
        'infer_run_name': infer_run_dir.name,
        'signatures_root': str(signatures_root),
        'signature_output_dir': str(signature_output_dir),
        'signature_non_empty_dir': str(signature_non_empty_dir),
        'analysis_result_csv': str(result_csv),
        'analysis_no_issue_files': str(no_issue_txt),
        'result_by_target': compact,
        'totals': totals,
    }

    if summary_json is not None:
        summary_json = summary_json.resolve()
        summary_json.parent.mkdir(parents=True, exist_ok=True)
        summary_json.write_text(
            json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
        )

    print(f'Signatures generated at: {signature_output_dir}')
    print(json.dumps(summary_payload, ensure_ascii=False))


if __name__ == '__main__':
    typer.run(main)
