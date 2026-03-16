#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from shared import step07_dedup as _step07_dedup
from stage import pipeline as _pipeline
from stage import rerun_step07 as _rerun_step07
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
dedupe_pairs_by_normalized_rows = _step07_dedup.dedupe_pairs_by_normalized_rows
export_dataset_from_pipeline = _stage07_dataset_export.export_dataset_from_pipeline
export_primary_dataset = _stage07_dataset_export.export_primary_dataset


def _print_result(result: Any) -> int:
    if hasattr(result, 'to_payload'):
        result = result.to_payload()
    if isinstance(result, dict):
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0
    return int(result or 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Unified runner for pipeline full/stage/rerun commands.'
    )
    subparsers = parser.add_subparsers(dest='command', required=True)

    full = subparsers.add_parser('full', help='Run the full pipeline.')
    full.add_argument('cwes', nargs='*', type=int)
    full.add_argument('--all', action='store_true', dest='all_cwes')
    full.add_argument('--files', action='append', default=[])
    full.add_argument(
        '--manifest',
        type=Path,
        default=Path(_pipeline.PROJECT_HOME)
        / 'experiments'
        / 'epic001_manifest_comment_scan'
        / 'inputs'
        / 'manifest.xml',
    )
    full.add_argument(
        '--source-root',
        type=Path,
        default=Path(_pipeline.PROJECT_HOME) / 'juliet-test-suite-v1.3' / 'C',
    )
    full.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(_pipeline.RESULT_DIR) / 'pipeline-runs',
    )
    full.add_argument('--run-id', type=str, default=None)
    full.add_argument(
        '--committed-taint-config',
        type=Path,
        default=Path(_pipeline.PULSE_TAINT_CONFIG),
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

    rerun = subparsers.add_parser('rerun-step07', help='Run rerun-step07 flow.')
    rerun.add_argument('--run-dir', type=Path, default=None)
    rerun.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(_rerun_step07.RESULT_DIR) / 'pipeline-runs',
    )
    rerun.add_argument('--output-dir', type=Path, default=None)
    rerun.add_argument('--dedup-mode', choices=['none', 'row'], default='row')
    rerun.add_argument('--overwrite', action='store_true')
    rerun.add_argument('--only-07', action='store_true')
    rerun.add_argument('--only-07b', action='store_true')
    rerun.add_argument('--old-prefix', type=str, default=None)
    rerun.add_argument('--new-prefix', type=str, default=None)

    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.command == 'full':
        return int(
            _pipeline.main(
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
            or 0
        )

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
        output_pairs_jsonl = (
            args.output_pairs_jsonl.resolve()
            if args.output_pairs_jsonl is not None
            else pair_dir / f'{_stage07b_patched_export.DATASET_BASENAME}_pairs.jsonl'
        )
        selection_summary_json = (
            args.selection_summary_json.resolve()
            if args.selection_summary_json is not None
            else pair_dir / f'{_stage07b_patched_export.DATASET_BASENAME}_selection_summary.json'
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

    if args.command == 'rerun-step07':
        return _print_result(
            _rerun_step07.run_rerun_step07(
                run_dir=args.run_dir,
                pipeline_root=args.pipeline_root,
                output_dir=args.output_dir,
                dedup_mode=args.dedup_mode,
                overwrite=args.overwrite,
                only_07=args.only_07,
                only_07b=args.only_07b,
                old_prefix=args.old_prefix,
                new_prefix=args.new_prefix,
            )
        )

    raise ValueError(f'Unsupported command: {args.command}')


if __name__ == '__main__':
    raise SystemExit(main())
