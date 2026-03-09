from typing import Dict, Generator, List, Optional, Set, Tuple

from paths import PROJECT_HOME, JULIET_TESTCASE_DIR, INFER_BIN, RESULT_DIR, GLOBAL_RESULT_DIR, PULSE_TAINT_CONFIG

import concurrent.futures
import csv
import datetime
import importlib.util
import os
from pathlib import Path
import re
import shlex
import subprocess
import time
import typer

TOTAL_CORES = os.cpu_count() or 4
MIN_CORES_PER_JOB = 2
MAX_PARALLEL_JOBS = max(1, TOTAL_CORES // MIN_CORES_PER_JOB)
CORES_PER_JOB = max(1, TOTAL_CORES // MAX_PARALLEL_JOBS)
VALID_EXTENSIONS = {'c', 'cpp'}
WINDOWS_SPECIFIC_MARKERS = ('w32', 'wchar_t')


CaseGroup = Tuple[str, str, str, str, str, str]  # (directory, cwe_num, cwe_name, variant, flow_id, extension)


def get_testcase_filename_regex() -> str:
    return "^cwe" + \
        "(?P<cwe_number>\\d+)" + \
        "_" + \
        "(?P<cwe_name>.*)" + \
        "__" + \
        "(?P<functional_variant_name>.*)" + \
        "_" + \
        "(?P<flow_variant_id>\\d+)" + \
        "_?" + \
        "(?P<subfile_id>[a-z]{1}|(bad)|(good(\\d)+)|(base)|(goodB2G)|(goodG2B))?" + \
        "\\." + \
        "(?P<extension>c|cpp|java|h)$"


TESTCASE_FILENAME_REGEX = re.compile(get_testcase_filename_regex(), re.IGNORECASE)


def find_cwe_dir(cwe_number: int) -> Optional[str]:
    prefix = f'CWE{cwe_number}_'
    for entry in os.listdir(JULIET_TESTCASE_DIR):
        if entry.startswith(prefix):
            return entry
    return None


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
    group_key: CaseGroup = (os.path.dirname(file_path), cwe_num, cwe_name,
                            functional_variant_name, flow_variant_id, extension)
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


def build_infer_command(target_files: List[str], extension: str,
                        cores: int = CORES_PER_JOB) -> str:
    testcasesupport_dir = os.path.join(PROJECT_HOME, 'juliet-test-suite-v1.3',
                                       'C', 'testcasesupport')
    io_c = os.path.join(testcasesupport_dir, 'io.c')

    compiler = 'clang++' if extension == 'cpp' else 'clang'
    link_flag = ' -lm' if extension == 'cpp' else ''

    quoted_files = ' '.join(shlex.quote(file) for file in target_files)
    compile_cmd = (
        f'{compiler} -I {shlex.quote(testcasesupport_dir)} -D INCLUDEMAIN '
        f'{shlex.quote(io_c)} {quoted_files}{link_flag}'
    )
    return f'{INFER_BIN} run -j {cores} --pulse-taint-config {PULSE_TAINT_CONFIG} -- {compile_cmd}'


def run_case(result_path: str, infer_cmd: str,
             representative_file: str) -> Dict[str, object]:
    """Run a single infer case. Returns a result dict (thread/process safe)."""
    os.makedirs(result_path, exist_ok=True)
    result = subprocess.run(
        infer_cmd,
        shell=True,
        cwd=result_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

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


def run_infer_all(cwe_dir,
                  result_dir,
                  max_cases: Optional[int] = None,
                  executed_cases: Optional[List[int]] = None,
                  processed_groups: Optional[set] = None):
    if executed_cases is None:
        executed_cases = [0]
    if processed_groups is None:
        processed_groups = set()

    summary: Dict[str, object] = {
        'issue': 0,
        'no_issue': 0,
        'error': 0,
        'no_issue_files': []
    }
    start_time = time.time()
    target_dir = os.path.join(JULIET_TESTCASE_DIR, cwe_dir)

    futures = []
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=MAX_PARALLEL_JOBS) as executor:
        for file_path in iter_candidate_files(target_dir):
            if max_cases is not None and executed_cases[0] >= max_cases:
                break

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
            infer_cmd = build_infer_command(target_files, extension)
            futures.append(
                executor.submit(run_case, result_path, infer_cmd, file_path))
            executed_cases[0] += 1

        _collect_results(futures, summary)

    summary['time'] = time.time() - start_time
    return summary


def run_infer_for_files(files: List[str], result_dir: str,
                        max_cases: Optional[int] = None):
    summary: Dict[str, object] = {
        'issue': 0,
        'no_issue': 0,
        'error': 0,
        'no_issue_files': []
    }
    start_time = time.time()
    executed_cases = [0]
    processed_targets: Set[Tuple[str, ...]] = set()

    futures = []
    with concurrent.futures.ProcessPoolExecutor(
            max_workers=MAX_PARALLEL_JOBS) as executor:
        for file_path in files:
            if max_cases is not None and executed_cases[0] >= max_cases:
                break

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
            infer_cmd = build_infer_command(target_files, extension)
            futures.append(
                executor.submit(run_case, result_path, infer_cmd, abs_file))
            executed_cases[0] += 1

        _collect_results(futures, summary)

    summary['time'] = time.time() - start_time
    return summary


def generate_result_csv(result_map, result_dir):
    csv_path = os.path.join(result_dir, 'result.csv')
    with open(csv_path, 'w') as csvfile:
        writer = csv.writer(csvfile)

        writer.writerow([
            'CWE NUMBER', 'ALL_TESTCASES', 'TIME(s)', 'ISSUE', 'NO ISSUE',
            'ERROR'
        ])

        for cwe_number in result_map:
            cwe_number_info = result_map[cwe_number]

            elapsed_sec = cwe_number_info['time']
            issue = cwe_number_info['issue']
            no_issue = cwe_number_info['no_issue']
            error = cwe_number_info['error']
            total_cases = issue + no_issue + error

            writer.writerow([cwe_number, total_cases, elapsed_sec, issue, no_issue, error])


def generate_no_issue_files(result_map, result_dir):
    txt_path = os.path.join(result_dir, 'no_issue_files.txt')
    with open(txt_path, 'w') as f:
        for cwe_number in result_map:
            no_issue_files = result_map[cwe_number]['no_issue_files']

            for file in no_issue_files:
                f.write(file)
                f.write('\n')


def load_signature_module():
    module_path = os.path.join(PROJECT_HOME, 'tools', 'generate-signature.py')
    spec = importlib.util.spec_from_file_location('generate_signature_module',
                                                  module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Failed to load signature module: {module_path}')

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main(cwes: Optional[List[int]] = typer.Argument(None),
         generate_csv: bool = typer.Option(False),
         generate_signature: bool = typer.Option(
             False, help='Generate signatures after infer run'),
         global_result: bool = typer.Option(False),
         files: List[str] = typer.Option(
             [], '--files', help='Run infer for specific files (repeatable)'),
         max_cases: Optional[int] = typer.Option(
             None, help='Maximum number of testcases to run for each CWE')):

    if not os.path.exists(PULSE_TAINT_CONFIG):
        raise typer.BadParameter(
            f'Pulse taint config not found: {PULSE_TAINT_CONFIG}')

    result_dir = GLOBAL_RESULT_DIR if global_result else RESULT_DIR
    os.makedirs(result_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')
    juliet_result_dir = os.path.join(result_dir, f'juliet-result-{timestamp}')
    os.makedirs(juliet_result_dir, exist_ok=True)

    result_map: Dict[object, Dict[str, object]] = {}
    if files:
        result_map['FILES'] = run_infer_for_files(files,
                                                  juliet_result_dir,
                                                  max_cases=max_cases)
    else:
        if not cwes:
            raise typer.BadParameter('Provide cwes or use --files')
        for cwe_number in cwes:
            cwe_dir = find_cwe_dir(cwe_number)
            if cwe_dir is None:
                continue
            result_map[cwe_number] = run_infer_all(cwe_dir,
                                                   juliet_result_dir,
                                                   max_cases=max_cases)

    if generate_csv:
        generate_result_csv(result_map, juliet_result_dir)

    generate_no_issue_files(result_map, juliet_result_dir)

    if generate_signature:
        signature_module = load_signature_module()
        signature_output_dir = signature_module.generate_signatures(
            input_dir=Path(juliet_result_dir),
            output_root=Path(RESULT_DIR) / 'signatures')
        print(f'Signatures generated at: {signature_output_dir}')


if __name__ == '__main__':
    typer.run(main)
