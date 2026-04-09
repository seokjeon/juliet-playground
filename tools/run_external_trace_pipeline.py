#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import sys
from pathlib import Path

from shared.artifact_layout import build_dataset_export_paths, build_slice_stage_paths
from shared.fs import prepare_output_dir
from shared.paths import EXTERNAL_RUNS_DIR, PULSE_TAINT_CONFIG
from stage import stage03_external_infer as _stage03_external_infer
from stage import stage05b_manual_line_filter as _stage05b_manual_line_filter
from stage import stage06_trace_slices as _stage06_trace_slices
from stage import stage07_external_test_dataset_export as _stage07_external_test_dataset_export


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run the external-project fast path: Infer -> manual-line trace filter -> '
        'test-only dataset export.'
    )
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--build-targets', type=Path, required=True)
    parser.add_argument('--manual-line-truth', type=Path, required=True)
    parser.add_argument(
        '--pulse-taint-config',
        type=Path,
        default=Path(PULSE_TAINT_CONFIG),
    )
    parser.add_argument(
        '--output-root',
        type=Path,
        default=Path(EXTERNAL_RUNS_DIR),
    )
    parser.add_argument('--run-id', type=str, default=None)
    parser.add_argument('--project-name', type=str, default=None)
    parser.add_argument('--overwrite', action='store_true')
    return parser.parse_args()


def _now_ts() -> str:
    return datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')


def _default_project_name(source_root: Path) -> str:
    if source_root.name == 'raw_code' and source_root.parent.name:
        return source_root.parent.name
    return source_root.name


def _build_paths(run_dir: Path) -> dict[str, Path]:
    dataset_paths = build_dataset_export_paths(run_dir / '07_dataset_export')
    trace_slice_paths = build_slice_stage_paths(run_dir / '06_trace_slices')
    return {
        'run_dir': run_dir,
        'infer_results_root': run_dir / '03_infer-results',
        'signatures_root': run_dir / '03_signatures',
        'infer_summary_json': run_dir / '03_infer_summary.json',
        'manual_filter_dir': run_dir / '05b_manual_line_filter',
        'trace_slice_dir': trace_slice_paths['output_dir'],
        'trace_slice_output_dir': trace_slice_paths['slice_dir'],
        'dataset_dir': dataset_paths['output_dir'],
    }


def run_external_trace_pipeline(args: argparse.Namespace) -> int:
    source_root = args.source_root.resolve()
    if not source_root.exists():
        raise ValueError(f'Source root not found: {source_root}')

    build_targets = args.build_targets.resolve()
    manual_line_truth = args.manual_line_truth.resolve()
    pulse_taint_config = args.pulse_taint_config.resolve()
    project_name = args.project_name or _default_project_name(source_root)

    run_id = args.run_id or f'run-{_now_ts()}'
    run_dir = (args.output_root.resolve() / run_id).resolve()
    prepare_output_dir(run_dir, args.overwrite)
    paths = _build_paths(run_dir)

    stage03 = _stage03_external_infer.run_external_infer_and_signature(
        build_targets_csv=build_targets,
        pulse_taint_config=pulse_taint_config,
        infer_results_root=paths['infer_results_root'],
        signatures_root=paths['signatures_root'],
        summary_json=paths['infer_summary_json'],
    )
    signature_non_empty_dir = Path(stage03['artifacts']['signature_non_empty_dir'])

    stage05 = _stage05b_manual_line_filter.filter_traces_by_manual_lines(
        signatures_dir=signature_non_empty_dir,
        manual_line_truth_csv=manual_line_truth,
        source_root=source_root,
        output_dir=paths['manual_filter_dir'],
    )
    traces_jsonl = Path(stage05['artifacts']['traces_jsonl'])
    if stage05['stats']['traces_kept'] <= 0:
        raise RuntimeError(
            'No traces matched the manual vulnerable lines; stopping before slice/export.'
        )

    stage06 = _stage06_trace_slices.generate_trace_slices(
        traces_jsonl=traces_jsonl,
        output_dir=paths['trace_slice_dir'],
        source_root=source_root,
    )
    slice_dir = Path(stage06['artifacts']['slice_dir'])

    stage07 = _stage07_external_test_dataset_export.export_external_test_dataset(
        traces_jsonl=traces_jsonl,
        slice_dir=slice_dir,
        output_dir=paths['dataset_dir'],
        source_root=source_root,
        project_name=project_name,
    )
    if stage07['stats']['counts']['rows_written'] <= 0:
        raise RuntimeError('External test dataset export wrote zero rows.')

    print(f'External trace pipeline completed: {run_dir}')
    print(f'  - dataset_csv: {Path(stage07["artifacts"]["csv_path"])}')
    print(f'  - trace_row_manifest: {Path(stage07["artifacts"]["trace_row_manifest_jsonl"])}')
    return 0


def main() -> int:
    args = parse_args()
    try:
        return run_external_trace_pipeline(args)
    except (ValueError, FileExistsError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
