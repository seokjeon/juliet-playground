#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from shared.paths import PULSE_TAINT_CONFIG, RESULT_DIR
from stage import infer as _infer_runner

build_infer_command = _infer_runner.build_infer_command
find_all_cwe_dirs = _infer_runner.find_all_cwe_dirs
find_cwe_dir = _infer_runner.find_cwe_dir
find_group_files = _infer_runner.find_group_files
get_testcase_filename_regex = _infer_runner.get_testcase_filename_regex
iter_candidate_files = _infer_runner.iter_candidate_files
parse_case_group = _infer_runner.parse_case_group
run_infer_all = _infer_runner.run_infer_all
run_infer_for_files = _infer_runner.run_infer_for_files


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
    return _infer_runner.main(
        cwes=cwes,
        global_result=global_result,
        all_cwes=all_cwes,
        files=files,
        pulse_taint_config=pulse_taint_config,
        infer_results_root=infer_results_root,
        signatures_root=signatures_root,
        summary_json=summary_json,
    )


if __name__ == '__main__':
    typer.run(main)
