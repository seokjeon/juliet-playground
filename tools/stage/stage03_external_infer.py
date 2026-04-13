from __future__ import annotations

import datetime
import json
import re
import shlex
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any

from shared.external_inputs import load_build_targets_csv
from shared.jsonio import write_stage_summary
from shared.paths import INFER_BIN

from stage.stage03_signature import generate_signatures

MAKE_PARALLEL_RE = re.compile(r'(?<!\S)-j(?:\s+\S+|[^\s]*)')


def split_build_command(build_command: str) -> tuple[list[str], list[str]]:
    segments = [segment.strip() for segment in build_command.split('&&') if segment.strip()]
    if not segments:
        raise ValueError(f'Unsupported empty build command: {build_command!r}')
    infer_args = shlex.split(segments[-1])
    if not infer_args:
        raise ValueError(f'Unsupported build command: {build_command!r}')
    return segments[:-1], infer_args


def build_infer_command(
    *,
    infer_args: list[str],
    pulse_taint_config: Path,
    results_dir: Path,
    infer_jobs: int = 1,
) -> list[str]:
    if infer_jobs < 1:
        raise ValueError(f'infer_jobs must be >= 1 (got {infer_jobs})')
    return [
        INFER_BIN,
        'run',
        '-j',
        str(infer_jobs),
        '--keep-going',
        '--results-dir',
        str(results_dir),
        '--force-delete-results-dir',
        '--pulse-taint-config',
        str(pulse_taint_config),
        '--',
        *infer_args,
    ]


def _single_job_fallback_command(build_command: str) -> str | None:
    if 'make' not in build_command:
        return None
    replaced = MAKE_PARALLEL_RE.sub('-j1', build_command, count=1)
    if replaced == build_command:
        return None
    return replaced


def _load_report_alarms(report_path: Path) -> list[dict[str, Any]]:
    with report_path.open('r', encoding='utf-8') as f:
        payload = json.load(f)
    if not isinstance(payload, list):
        raise ValueError(f'Expected list payload in report.json: {report_path}')
    return [alarm for alarm in payload if isinstance(alarm, dict)]


def _recover_report_from_results_dir(
    *,
    results_dir: Path,
    pulse_taint_config: Path,
    workdir: Path,
    testcase_dir: Path,
    attempt_index: int,
) -> dict[str, Any]:
    analyze_stdout_log = testcase_dir / f'infer_recover_attempt_{attempt_index}.analyze.stdout.log'
    analyze_stderr_log = testcase_dir / f'infer_recover_attempt_{attempt_index}.analyze.stderr.log'
    report_stdout_log = testcase_dir / f'infer_recover_attempt_{attempt_index}.report.stdout.log'
    report_stderr_log = testcase_dir / f'infer_recover_attempt_{attempt_index}.report.stderr.log'

    analyze_result = subprocess.run(
        [
            INFER_BIN,
            'analyze',
            '--results-dir',
            str(results_dir),
            '--pulse-taint-config',
            str(pulse_taint_config),
        ],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    analyze_stdout_log.write_text(analyze_result.stdout or '', encoding='utf-8')
    analyze_stderr_log.write_text(analyze_result.stderr or '', encoding='utf-8')

    report_result = subprocess.run(
        [
            INFER_BIN,
            'report',
            '--results-dir',
            str(results_dir),
        ],
        cwd=workdir,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    report_stdout_log.write_text(report_result.stdout or '', encoding='utf-8')
    report_stderr_log.write_text(report_result.stderr or '', encoding='utf-8')

    report_path = results_dir / 'report.json'
    return {
        'analyze_returncode': int(analyze_result.returncode),
        'report_returncode': int(report_result.returncode),
        'analyze_stdout_log': str(analyze_stdout_log),
        'analyze_stderr_log': str(analyze_stderr_log),
        'report_stdout_log': str(report_stdout_log),
        'report_stderr_log': str(report_stderr_log),
        'report_json_exists': report_path.exists(),
    }


def _result_payload(
    *,
    testcase_key: str,
    status: str,
    elapsed_seconds: float,
    attempts: list[dict[str, Any]],
    taint_alarms_total: int,
) -> dict[str, Any]:
    return {
        'testcase_key': testcase_key,
        'status': status,
        'elapsed_seconds': round(elapsed_seconds, 6),
        'taint_alarms_total': taint_alarms_total,
        'attempts': attempts,
    }


def run_external_infer_and_signature(
    *,
    build_targets_csv: Path,
    pulse_taint_config: Path,
    infer_results_root: Path,
    signatures_root: Path,
    summary_json: Path | None = None,
    infer_jobs: int = 1,
) -> dict[str, Any]:
    pulse_taint_config = pulse_taint_config.resolve()
    if not pulse_taint_config.exists():
        raise FileNotFoundError(f'Pulse taint config not found: {pulse_taint_config}')

    targets = load_build_targets_csv(build_targets_csv.resolve())
    infer_results_root = infer_results_root.resolve()
    signatures_root = signatures_root.resolve()
    infer_results_root.mkdir(parents=True, exist_ok=True)
    signatures_root.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')
    infer_run_dir = infer_results_root / f'infer-{timestamp}'
    infer_run_dir.mkdir(parents=True, exist_ok=True)

    stats = Counter()
    per_target: dict[str, dict[str, Any]] = {}

    for target in targets:
        testcase_dir = infer_run_dir / target.testcase_key
        testcase_dir.mkdir(parents=True, exist_ok=True)
        (testcase_dir / 'build_command.txt').write_text(
            target.build_command + '\n',
            encoding='utf-8',
        )

        attempts: list[dict[str, Any]] = []
        candidate_commands = [target.build_command]
        fallback_command = _single_job_fallback_command(target.build_command)
        if fallback_command and fallback_command not in candidate_commands:
            candidate_commands.append(fallback_command)

        start_time = time.time()
        report_path = testcase_dir / 'infer-out' / 'report.json'
        taint_alarms_total = 0
        status = 'error'

        for attempt_index, build_command in enumerate(candidate_commands, start=1):
            pre_commands, infer_args = split_build_command(build_command)
            pre_logs: list[dict[str, Any]] = []
            prebuild_failed = False
            for pre_index, pre_command in enumerate(pre_commands, start=1):
                pre_result = subprocess.run(
                    ['/bin/bash', '-lc', pre_command],
                    cwd=target.workdir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=False,
                )
                pre_stdout_log = testcase_dir / (
                    f'prebuild_attempt_{attempt_index}_step_{pre_index}.stdout.log'
                )
                pre_stderr_log = testcase_dir / (
                    f'prebuild_attempt_{attempt_index}_step_{pre_index}.stderr.log'
                )
                pre_stdout_log.write_text(pre_result.stdout or '', encoding='utf-8')
                pre_stderr_log.write_text(pre_result.stderr or '', encoding='utf-8')
                pre_logs.append(
                    {
                        'command': pre_command,
                        'returncode': int(pre_result.returncode),
                        'stdout_log': str(pre_stdout_log),
                        'stderr_log': str(pre_stderr_log),
                    }
                )
                if pre_result.returncode != 0:
                    prebuild_failed = True
                    break

            if prebuild_failed:
                attempts.append(
                    {
                        'index': attempt_index,
                        'build_command': build_command,
                        'pre_commands': pre_logs,
                        'infer_command': infer_args,
                        'returncode': 1,
                        'stdout_log': '',
                        'stderr_log': '',
                    }
                )
                continue

            command = build_infer_command(
                infer_args=infer_args,
                pulse_taint_config=pulse_taint_config,
                results_dir=testcase_dir / 'infer-out',
                infer_jobs=infer_jobs,
            )
            result = subprocess.run(
                command,
                cwd=target.workdir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            stdout_text = result.stdout or ''
            stderr_text = result.stderr or ''
            log_prefix = 'infer'
            if attempt_index > 1:
                log_prefix = f'infer_attempt_{attempt_index}'
            (testcase_dir / f'{log_prefix}.stdout.log').write_text(stdout_text, encoding='utf-8')
            (testcase_dir / f'{log_prefix}.stderr.log').write_text(stderr_text, encoding='utf-8')
            attempts.append(
                {
                    'index': attempt_index,
                    'build_command': build_command,
                    'pre_commands': pre_logs,
                    'infer_command': infer_args,
                    'returncode': int(result.returncode),
                    'stdout_log': str(testcase_dir / f'{log_prefix}.stdout.log'),
                    'stderr_log': str(testcase_dir / f'{log_prefix}.stderr.log'),
                }
            )

            if result.returncode != 0 or not report_path.exists():
                recovery = _recover_report_from_results_dir(
                    results_dir=testcase_dir / 'infer-out',
                    pulse_taint_config=pulse_taint_config,
                    workdir=target.workdir,
                    testcase_dir=testcase_dir,
                    attempt_index=attempt_index,
                )
                attempts[-1]['recovery'] = recovery
                if not report_path.exists():
                    continue

            alarms = _load_report_alarms(report_path)
            taint_alarms_total = sum(
                1 for alarm in alarms if str(alarm.get('bug_type') or '') == 'TAINT_ERROR'
            )
            status = 'issue' if taint_alarms_total > 0 else 'no_issue'
            break

        elapsed_seconds = time.time() - start_time
        per_target[target.testcase_key] = _result_payload(
            testcase_key=target.testcase_key,
            status=status,
            elapsed_seconds=elapsed_seconds,
            attempts=attempts,
            taint_alarms_total=taint_alarms_total,
        )
        stats[status] += 1
        stats['targets_total'] += 1
        stats['taint_alarms_total'] += taint_alarms_total

    signature_output_dir = generate_signatures(
        input_dir=infer_run_dir,
        output_root=signatures_root,
        infer_run_name=infer_run_dir.name,
    )
    signature_non_empty_dir = Path(signature_output_dir) / 'non_empty'

    artifacts = {
        'build_targets_csv': str(build_targets_csv.resolve()),
        'infer_run_dir': str(infer_run_dir),
        'signature_output_dir': str(signature_output_dir),
        'signature_non_empty_dir': str(signature_non_empty_dir),
    }
    summary_stats = {
        'issue': int(stats['issue']),
        'no_issue': int(stats['no_issue']),
        'error': int(stats['error']),
        'targets_total': int(stats['targets_total']),
        'taint_alarms_total': int(stats['taint_alarms_total']),
    }
    extra = {'targets': per_target}
    if summary_json is not None:
        write_stage_summary(
            summary_json.resolve(),
            artifacts=artifacts,
            stats=summary_stats,
            extra=extra,
            echo=False,
        )
    return {'artifacts': artifacts, 'stats': summary_stats, 'targets': per_target}
