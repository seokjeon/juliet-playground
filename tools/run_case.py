#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import run_external_trace_pipeline as _run_external_trace_pipeline
from shared.external_case import (
    TRACK_NAMES,
    infer_project_name_from_repo,
    prepare_case_run_inputs,
    resolve_case_run_paths,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run a case-managed external-project trace pipeline run.'
    )
    parser.add_argument('--case', type=Path, required=True)
    parser.add_argument('--track', type=str, choices=sorted(TRACK_NAMES), required=True)
    parser.add_argument('--run', type=str, required=True)
    parser.add_argument('--project-name', type=str, default=None)
    parser.add_argument(
        '--infer-jobs',
        type=int,
        default=1,
        help='Number of parallel jobs to pass to `infer run -j`.',
    )
    parser.add_argument(
        '--artifact-root',
        type=Path,
        default=None,
        help='Deprecated compatibility flag. Case-managed outputs are always stored under '
        'runs/<run>/outputs.',
    )
    parser.add_argument('--overwrite', action='store_true')
    return parser.parse_args()


def run_case(args: argparse.Namespace) -> int:
    paths = resolve_case_run_paths(
        args.case,
        track=args.track,
        run_id=args.run,
    )
    input_paths = prepare_case_run_inputs(paths)

    project_name = args.project_name or infer_project_name_from_repo(paths.repo_dir)
    pipeline_args = argparse.Namespace(
        source_root=paths.repo_dir,
        build_targets=input_paths.build_targets_csv,
        manual_line_truth=input_paths.manual_line_truth_csv,
        pulse_taint_config=input_paths.pulse_taint_config,
        output_root=paths.run_dir,
        run_id='outputs',
        project_name=project_name,
        infer_jobs=args.infer_jobs,
        overwrite=args.overwrite,
    )
    result = _run_external_trace_pipeline.run_external_trace_pipeline(pipeline_args)

    print(f'Case run completed: {paths.case_id}/{paths.track}/{paths.run_id}')
    print(f'  - case_run_dir: {paths.run_dir}')
    print(f'  - outputs_dir: {paths.outputs_dir}')
    return result


def main() -> int:
    args = parse_args()
    try:
        return run_case(args)
    except (ValueError, FileExistsError, FileNotFoundError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
