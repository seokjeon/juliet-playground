#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from shared import dataset_dedup as _dataset_dedup
from shared.artifact_layout import (
    TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    build_dataset_export_paths,
    build_pair_trace_paths,
    build_patched_pairing_paths,
    build_slice_stage_paths,
    build_trace_dataset_paths,
)
from shared.paths import PROJECT_HOME, PULSE_TAINT_CONFIG, RESULT_DIR
from stage import stage01_manifest as _stage01_manifest
from stage import stage02a_taint as _stage02a_taint
from stage import stage02b_flow as _stage02b_flow
from stage import stage03_infer as _stage03_infer
from stage import stage04_trace_flow as _stage04_trace_flow
from stage import stage05_pair_trace as _stage05_pair_trace
from stage import stage05_trace_dataset as _stage05_trace_dataset
from stage import stage06_slices as _stage06_slices
from stage import stage06_trace_slices as _stage06_trace_slices
from stage import stage07_dataset_export as _stage07_dataset_export
from stage import stage07_trace_dataset_export as _stage07_trace_dataset_export
from stage import stage07b_patched_export as _stage07b_patched_export
from stage import stage07c_vuln_patch_export as _stage07c_vuln_patch_export

compute_pair_split = _stage07_dataset_export.compute_pair_split
export_dataset_from_pipeline = _stage07_dataset_export.export_dataset_from_pipeline
export_primary_dataset = _stage07_dataset_export.export_primary_dataset
export_vuln_patch_dataset = _stage07c_vuln_patch_export.export_vuln_patch_dataset
export_trace_dataset_from_pipeline = (
    _stage07_trace_dataset_export.export_trace_dataset_from_pipeline
)
dedupe_pairs_by_normalized_rows = _dataset_dedup.dedupe_pairs_by_normalized_rows
export_patched_dataset = _stage07b_patched_export.export_patched_dataset


@dataclass(frozen=True)
class FullRunConfig:
    cwes: Optional[list[int]]
    all_cwes: bool
    files: list[str]
    manifest: Path
    source_root: Path
    pipeline_root: Path
    run_id: Optional[str]
    committed_taint_config: Path
    pair_split_seed: int
    pair_train_ratio: float
    dedup_mode: str
    enable_pair: bool
    prune_single_child_flows: bool


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Unified runner for the full pipeline.')
    subparsers = parser.add_subparsers(dest='command', required=True)

    full = subparsers.add_parser('full', help='Run the full pipeline.')
    full.add_argument('cwes', nargs='*', type=int)
    full.add_argument('--all', action='store_true', dest='all_cwes')
    full.add_argument('--files', action='append', default=[])
    full.add_argument(
        '--manifest',
        type=Path,
        default=Path(PROJECT_HOME)
        / 'experiments'
        / 'epic001_manifest_comment_scan'
        / 'inputs'
        / 'manifest.xml',
    )
    full.add_argument(
        '--source-root',
        type=Path,
        default=Path(PROJECT_HOME) / 'juliet-test-suite-v1.3' / 'C',
    )
    full.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
    )
    full.add_argument('--run-id', type=str, default=None)
    full.add_argument(
        '--committed-taint-config',
        type=Path,
        default=Path(PULSE_TAINT_CONFIG),
    )
    full.add_argument('--pair-split-seed', type=int, default=1234)
    full.add_argument('--pair-train-ratio', type=float, default=0.8)
    full.add_argument('--dedup-mode', choices=['none', 'row'], default='row')
    pair_mode = full.add_mutually_exclusive_group()
    pair_mode.add_argument('--enable-pair', dest='enable_pair', action='store_true')
    pair_mode.add_argument('--disable-pair', dest='enable_pair', action='store_false')
    full.add_argument(
        '--keep-single-child-flows',
        dest='prune_single_child_flows',
        action='store_false',
        help='Keep flow tags that have exactly one child after Stage 02b dedup.',
    )
    full.set_defaults(enable_pair=True, prune_single_child_flows=True)

    return parser.parse_args()


def now_ts() -> str:
    return datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')


def _build_full_run_paths(*, run_dir: Path, source_root: Path) -> dict[str, object]:
    run_dir = run_dir.resolve()
    source_root = source_root.resolve()

    manifest_dir = run_dir / '01_manifest'
    taint_dir = run_dir / '02a_taint'
    flow_dir = run_dir / '02b_flow'
    trace_dir = run_dir / '04_trace_flow'
    pair_paths = build_pair_trace_paths(run_dir / '05_pair_trace_ds')
    trace_paths = build_trace_dataset_paths(run_dir / '05_trace_ds')
    slice_paths = build_slice_stage_paths(run_dir / '06_slices')
    trace_slice_paths = build_slice_stage_paths(run_dir / '06_trace_slices')
    dataset_paths = build_dataset_export_paths(run_dir / '07_dataset_export')

    return {
        'run_dir': run_dir,
        'manifest_dir': manifest_dir,
        'taint_dir': taint_dir,
        'flow_dir': flow_dir,
        'infer_results_root': run_dir / '03_infer-results',
        'signatures_root': run_dir / '03_signatures',
        'infer_summary_json': run_dir / '03_infer_summary.json',
        'trace_dir': trace_dir,
        'manifest_with_comments_xml': manifest_dir / 'manifest_with_comments.xml',
        'generated_taint_config': taint_dir / 'pulse-taint-config.json',
        'trace_strict_jsonl': trace_dir / 'trace_flow_match_strict.jsonl',
        'stage02b': _stage02b_flow.build_stage02b_output_paths(flow_dir),
        'pair': pair_paths,
        'trace': trace_paths,
        'slices': slice_paths,
        'trace_slices': trace_slice_paths,
        'dataset': dataset_paths,
        'patched_pair': build_patched_pairing_paths(
            pair_paths['output_dir'],
            TRAIN_PATCHED_COUNTERPARTS_BASENAME,
        ),
        'patched_slices': build_slice_stage_paths(
            slice_paths['output_dir'] / TRAIN_PATCHED_COUNTERPARTS_BASENAME
        ),
        'patched_dataset': build_dataset_export_paths(
            dataset_paths['output_dir'],
            TRAIN_PATCHED_COUNTERPARTS_BASENAME,
        ),
    }


def _validate_full_inputs(config: FullRunConfig) -> None:
    if not config.manifest.exists():
        raise ValueError(f'Manifest not found: {config.manifest}')
    if not config.source_root.exists():
        raise ValueError(f'Source root not found: {config.source_root}')
    if not config.committed_taint_config.exists():
        raise ValueError(f'Committed taint config not found: {config.committed_taint_config}')
    if not config.files and not config.all_cwes and not config.cwes:
        raise ValueError('Provide cwes, use --all, or use --files')
    if not (0.0 < config.pair_train_ratio < 1.0):
        raise ValueError(f'pair_train_ratio must be between 0 and 1: {config.pair_train_ratio}')
    if config.dedup_mode not in {'none', 'row'}:
        raise ValueError(f'dedup_mode must be one of: none, row (got {config.dedup_mode})')


def _normalize_full_run_config(config: FullRunConfig) -> FullRunConfig:
    return FullRunConfig(
        cwes=config.cwes,
        all_cwes=config.all_cwes,
        files=list(config.files),
        manifest=config.manifest.resolve(),
        source_root=config.source_root.resolve(),
        pipeline_root=config.pipeline_root.resolve(),
        run_id=config.run_id or f'run-{now_ts()}',
        committed_taint_config=config.committed_taint_config.resolve(),
        pair_split_seed=config.pair_split_seed,
        pair_train_ratio=config.pair_train_ratio,
        dedup_mode=config.dedup_mode,
        enable_pair=config.enable_pair,
        prune_single_child_flows=config.prune_single_child_flows,
    )


def _require_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise RuntimeError(f'Expected {label} not found: {path}')


def _select_taint_config(
    *,
    generated_taint_config: Path,
    committed_taint_config: Path,
) -> tuple[Path, str]:
    if generated_taint_config.exists():
        return generated_taint_config, 'generated'
    return committed_taint_config.resolve(), 'fallback_committed'


def run_step01_manifest_comment_scan(
    *,
    paths: dict[str, object],
    manifest: Path,
    source_root: Path,
) -> dict[str, object]:
    output_xml = paths['manifest_with_comments_xml']
    result = _stage01_manifest.scan_manifest_comments(
        manifest=manifest,
        source_root=source_root,
        output_xml=output_xml,
    )
    _require_exists(output_xml, 'manifest_with_comments_xml')
    return result


def run_step02a_code_field_inventory(
    *,
    paths: dict[str, object],
    source_root: Path,
) -> dict[str, object]:
    result = _stage02a_taint.extract_unique_code_fields(
        input_xml=paths['manifest_with_comments_xml'],
        source_root=source_root,
        output_dir=paths['taint_dir'],
        pulse_taint_config_output=paths['generated_taint_config'],
    )
    _require_exists(paths['generated_taint_config'], 'generated_taint_config')
    return result


def run_step02b_flow_build(
    *,
    paths: dict[str, object],
    prune_single_child_flows: bool = True,
) -> dict[str, object]:
    result = _stage02b_flow.run_stage02b_flow(
        input_xml=paths['manifest_with_comments_xml'],
        output_dir=paths['flow_dir'],
        prune_single_child_flows=prune_single_child_flows,
    )
    _require_exists(
        paths['stage02b']['manifest_with_testcase_flows_xml'], 'manifest_with_testcase_flows_xml'
    )
    _require_exists(paths['stage02b']['summary_json'], '02b summary_json')
    return result


def run_step03_infer_and_signature(
    *,
    paths: dict[str, object],
    selected_taint_config: Path,
    files: list[str],
    all_cwes: bool,
    cwes: Optional[list[int]],
) -> dict[str, object]:
    result = _stage03_infer.run_infer_and_signature(
        cwes=cwes,
        global_result=False,
        all_cwes=all_cwes,
        files=files,
        pulse_taint_config=selected_taint_config,
        infer_results_root=paths['infer_results_root'],
        signatures_root=paths['signatures_root'],
        summary_json=paths['infer_summary_json'],
    )
    _require_exists(Path(result['artifacts']['signature_non_empty_dir']), 'signature_non_empty_dir')
    _require_exists(paths['infer_summary_json'], '03_infer_summary.json')
    return result


def run_step04_trace_flow(
    *,
    paths: dict[str, object],
    signature_non_empty_dir: Path,
) -> dict[str, object]:
    result = _stage04_trace_flow.filter_traces_by_flow(
        flow_xml=paths['stage02b']['manifest_with_testcase_flows_xml'],
        signatures_dir=signature_non_empty_dir,
        output_dir=paths['trace_dir'],
    )
    _require_exists(paths['trace_strict_jsonl'], 'trace_flow_match_strict.jsonl')
    return result


def run_step05_pair_trace(*, paths: dict[str, object]) -> dict[str, object]:
    result = _stage05_pair_trace.build_paired_trace_dataset(
        trace_jsonl=paths['trace_strict_jsonl'],
        output_dir=paths['pair']['output_dir'],
        overwrite=False,
        run_dir=paths['run_dir'],
    )
    for key in (
        'pairs_jsonl',
        'leftover_counterparts_jsonl',
        'paired_signatures_dir',
        'summary_json',
    ):
        _require_exists(paths['pair'][key], f'05_pair_trace_ds/{key}')
    return result


def run_step05_trace_dataset(*, paths: dict[str, object]) -> dict[str, object]:
    result = _stage05_trace_dataset.build_trace_dataset(
        trace_jsonl=paths['trace_strict_jsonl'],
        output_dir=paths['trace']['output_dir'],
        overwrite=False,
    )
    for key in ('traces_jsonl', 'summary_json'):
        _require_exists(paths['trace'][key], f'05_trace_ds/{key}')
    return result


def run_step06_slices(*, paths: dict[str, object]) -> dict[str, object]:
    result = _stage06_slices.generate_slices(
        signature_db_dir=paths['pair']['paired_signatures_dir'],
        output_dir=paths['slices']['output_dir'],
        overwrite=False,
    )
    for key in ('slice_dir', 'summary_json'):
        _require_exists(paths['slices'][key], f'06_slices/{key}')
    return result


def run_step06_trace_slices(*, paths: dict[str, object]) -> dict[str, object]:
    result = _stage06_trace_slices.generate_trace_slices(
        traces_jsonl=paths['trace']['traces_jsonl'],
        output_dir=paths['trace_slices']['output_dir'],
        overwrite=False,
    )
    for key in ('slice_dir', 'summary_json'):
        _require_exists(paths['trace_slices'][key], f'06_trace_slices/{key}')
    return result


def run_step07_dataset_export(
    *,
    paths: dict[str, object],
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
) -> dict[str, object]:
    result = export_primary_dataset(
        pairs_jsonl=paths['pair']['pairs_jsonl'],
        paired_signatures_dir=paths['pair']['paired_signatures_dir'],
        slice_dir=paths['slices']['slice_dir'],
        output_dir=paths['dataset']['output_dir'],
        split_seed=pair_split_seed,
        train_ratio=pair_train_ratio,
        dedup_mode=dedup_mode,
    )
    for key in ('csv_path', 'normalized_slices_dir', 'split_manifest_json', 'summary_json'):
        _require_exists(paths['dataset'][key], f'07_dataset_export/{key}')
    return result


def run_step07_trace_dataset_export(
    *,
    paths: dict[str, object],
    pair_split_seed: int,
    pair_train_ratio: float,
    dedup_mode: str,
) -> dict[str, object]:
    result = export_trace_dataset_from_pipeline(
        traces_jsonl=paths['trace']['traces_jsonl'],
        slice_dir=paths['trace_slices']['slice_dir'],
        output_dir=paths['dataset']['output_dir'],
        split_seed=pair_split_seed,
        train_ratio=pair_train_ratio,
        dedup_mode=dedup_mode,
    )
    for key in ('csv_path', 'normalized_slices_dir', 'split_manifest_json', 'summary_json'):
        _require_exists(paths['dataset'][key], f'07_dataset_export/{key}')
    return result


def run_step07b_train_patched_counterparts(
    *,
    paths: dict[str, object],
    dedup_mode: str,
) -> dict[str, object]:
    result = export_patched_dataset(
        run_dir=paths['run_dir'],
        dedup_mode=dedup_mode,
    )
    for path in (
        paths['patched_pair']['pairs_jsonl'],
        paths['patched_pair']['signatures_dir'],
        paths['patched_slices']['slice_dir'],
        paths['patched_dataset']['csv_path'],
        paths['patched_dataset']['normalized_slices_dir'],
        paths['patched_dataset']['split_manifest_json'],
        paths['patched_dataset']['summary_json'],
    ):
        _require_exists(path, path.name)
    return result


def run_step07c_vuln_patch_export(*, paths: dict[str, object]) -> dict[str, object]:
    output_dir = Path(paths['dataset']['output_dir']) / 'vuln_patch'
    result = export_vuln_patch_dataset(
        source_csv_path=paths['dataset']['csv_path'],
        output_dir=output_dir,
    )
    for key in ('csv_path', 'summary_json'):
        _require_exists(Path(result['artifacts'][key]), f'vuln_patch/{key}')
    return result


def run_full_pipeline(config: FullRunConfig) -> int:
    _validate_full_inputs(config)
    config = _normalize_full_run_config(config)

    assert config.run_id is not None
    run_dir = (config.pipeline_root / config.run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)
    paths = _build_full_run_paths(run_dir=run_dir, source_root=config.source_root)

    try:
        run_step01_manifest_comment_scan(
            paths=paths,
            manifest=config.manifest,
            source_root=config.source_root,
        )
        run_step02a_code_field_inventory(
            paths=paths,
            source_root=config.source_root,
        )
        run_step02b_flow_build(
            paths=paths,
            prune_single_child_flows=config.prune_single_child_flows,
        )

        selected_taint_config, _ = _select_taint_config(
            generated_taint_config=paths['generated_taint_config'],
            committed_taint_config=config.committed_taint_config,
        )
        stage03 = run_step03_infer_and_signature(
            paths=paths,
            selected_taint_config=selected_taint_config,
            files=config.files,
            all_cwes=config.all_cwes,
            cwes=config.cwes,
        )
        run_step04_trace_flow(
            paths=paths,
            signature_non_empty_dir=Path(stage03['artifacts']['signature_non_empty_dir']),
        )
        if config.enable_pair:
            run_step05_pair_trace(paths=paths)
            run_step06_slices(paths=paths)
            run_step07_dataset_export(
                paths=paths,
                pair_split_seed=config.pair_split_seed,
                pair_train_ratio=config.pair_train_ratio,
                dedup_mode=config.dedup_mode,
            )
            run_step07b_train_patched_counterparts(
                paths=paths,
                dedup_mode=config.dedup_mode,
            )
        else:
            run_step05_trace_dataset(paths=paths)
            run_step06_trace_slices(paths=paths)
            run_step07_trace_dataset_export(
                paths=paths,
                pair_split_seed=config.pair_split_seed,
                pair_train_ratio=config.pair_train_ratio,
                dedup_mode=config.dedup_mode,
            )
            run_step07c_vuln_patch_export(paths=paths)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


def main() -> int:
    args = parse_args()
    try:
        return run_full_pipeline(
            FullRunConfig(
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
                enable_pair=args.enable_pair,
                prune_single_child_flows=args.prune_single_child_flows,
            )
        )
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
