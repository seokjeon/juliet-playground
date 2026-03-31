#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import run_pdbert as _run_pdbert
from shared import bench_runner as _bench_runner

EXTERNAL_PDBERT_NAMESPACE = 'juliet-playground-external'
EVAL_ONLY_TARGET_NAME = 'eval_only'


@dataclass(frozen=True)
class PDBERTEvalOnlyConfig:
    dataset_csv: Path
    row_manifest: Path | None
    model_dir: Path
    vpbench_root: Path
    container_name: str
    eval_name: str
    overwrite: bool
    dry_run: bool
    storage_path_parts: tuple[str, ...] = ()
    output_name: str = 'testonly'


@dataclass(frozen=True)
class PDBERTEvalOnlyPaths:
    target_name: str
    display_name: str
    task_name: str
    source_csv: Path
    host_dataset_dir: Path
    host_output_dir: Path
    host_dataset_csv: Path
    host_prepare_log: Path
    host_test_log: Path
    host_analyze_log: Path
    host_runtime_test_config: Path
    host_eval_result_csv: Path
    host_analysis_json: Path
    host_feature_npz: Path
    host_feature_tsne_image: Path
    host_feature_tsne_cache_json: Path
    host_prepare_script: Path
    host_train_eval_script: Path
    host_analyze_script: Path
    host_raw_baseline_script: Path
    host_test_config_template: Path
    host_joined_predictions_csv: Path
    container_dataset_dir: Path
    container_output_dir: Path
    container_dataset_csv: Path
    container_runtime_test_config: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run PDBERT prepare/test/analyze for an external test-only dataset CSV using '
        'an existing trained model.'
    )
    parser.add_argument('--dataset-csv', type=Path, required=True)
    parser.add_argument('--model-dir', type=Path, required=True)
    parser.add_argument('--row-manifest', type=Path, default=None)
    parser.add_argument('--vpbench-root', type=Path, default=_run_pdbert.DEFAULT_VPBENCH_ROOT)
    parser.add_argument('--container-name', type=str, default=_run_pdbert.DEFAULT_CONTAINER_NAME)
    parser.add_argument('--eval-name', type=str, default=None)
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    return parser.parse_args()


def _default_eval_name(dataset_csv: Path) -> str:
    if dataset_csv.parent.name == '07_dataset_export':
        return dataset_csv.parent.parent.name
    return dataset_csv.parent.name or dataset_csv.stem


def normalize_config(config: PDBERTEvalOnlyConfig) -> PDBERTEvalOnlyConfig:
    return PDBERTEvalOnlyConfig(
        dataset_csv=config.dataset_csv.resolve(),
        row_manifest=config.row_manifest.resolve() if config.row_manifest is not None else None,
        model_dir=config.model_dir.resolve(),
        vpbench_root=config.vpbench_root.resolve(),
        container_name=config.container_name,
        eval_name=config.eval_name,
        storage_path_parts=tuple(config.storage_path_parts),
        output_name=config.output_name,
        overwrite=config.overwrite,
        dry_run=config.dry_run,
    )


def validate_config(config: PDBERTEvalOnlyConfig) -> None:
    if not config.dataset_csv.exists():
        raise ValueError(f'Dataset CSV not found: {config.dataset_csv}')
    if config.row_manifest is not None and not config.row_manifest.exists():
        raise ValueError(f'Row manifest not found: {config.row_manifest}')
    if not config.vpbench_root.exists():
        raise ValueError(f'VP-Bench root not found: {config.vpbench_root}')
    if not config.model_dir.exists():
        raise ValueError(f'PDBERT model dir not found: {config.model_dir}')


def build_eval_only_paths(config: PDBERTEvalOnlyConfig) -> PDBERTEvalOnlyPaths:
    storage_path_parts = (
        tuple(config.storage_path_parts)
        if config.storage_path_parts
        else (EXTERNAL_PDBERT_NAMESPACE, config.eval_name)
    )
    dataset_relative_parts = (config.output_name, 'realvul_test', 'Real_Vul')
    output_relative_parts = (config.output_name,)
    display_name = config.output_name if config.storage_path_parts else config.eval_name
    task_name = 'vul_detect/' + '/'.join((*storage_path_parts, config.output_name))

    base_host_dataset_dir = config.vpbench_root / 'downloads' / 'PDBERT' / 'data' / 'datasets' / 'extrinsic' / 'vul_detect'
    base_host_output_dir = config.vpbench_root / 'downloads' / 'PDBERT' / 'data' / 'models' / 'extrinsic' / 'vul_detect'
    for path_part in storage_path_parts:
        base_host_dataset_dir /= path_part
        base_host_output_dir /= path_part

    host_dataset_dir = base_host_dataset_dir.joinpath(*dataset_relative_parts)
    host_output_dir = base_host_output_dir.joinpath(*output_relative_parts)
    container_dataset_dir = _run_pdbert.CONTAINER_DATASET_BASE.joinpath(
        *storage_path_parts,
        *dataset_relative_parts,
    )
    container_output_dir = _run_pdbert.CONTAINER_MODEL_BASE.joinpath(
        *storage_path_parts,
        *output_relative_parts,
    )

    host_pdbert_root = config.vpbench_root / 'baseline' / 'PDBERT'
    host_configs_dir = host_pdbert_root / 'downstream' / 'configs' / 'vul_detect'
    host_experiment_dir = config.vpbench_root / 'experiment' / 'scripts' / 'pdbert'
    host_runtime_dir = host_dataset_dir / '_run_pdbert_eval_only'
    host_feature_npz, host_feature_tsne_image, host_feature_tsne_cache_json = (
        _run_pdbert._feature_artifact_paths(host_output_dir)
    )

    return PDBERTEvalOnlyPaths(
        target_name=config.output_name if config.storage_path_parts else EVAL_ONLY_TARGET_NAME,
        display_name=display_name,
        task_name=task_name,
        source_csv=config.dataset_csv,
        host_dataset_dir=host_dataset_dir,
        host_output_dir=host_output_dir,
        host_dataset_csv=host_dataset_dir / 'Real_Vul_data.csv',
        host_prepare_log=host_runtime_dir / 'prepare.log',
        host_test_log=host_runtime_dir / 'test.log',
        host_analyze_log=host_runtime_dir / 'analyze.log',
        host_runtime_test_config=host_runtime_dir / 'pdbert_test_runtime.jsonnet',
        host_eval_result_csv=host_output_dir / 'eval_result.csv',
        host_analysis_json=host_output_dir / 'prediction_analysis.json',
        host_feature_npz=host_feature_npz,
        host_feature_tsne_image=host_feature_tsne_image,
        host_feature_tsne_cache_json=host_feature_tsne_cache_json,
        host_prepare_script=host_pdbert_root / 'prepare_dataset.py',
        host_train_eval_script=host_pdbert_root / 'downstream' / 'train_eval_from_config.py',
        host_analyze_script=host_experiment_dir / 'analyze_prediction.py',
        host_raw_baseline_script=host_experiment_dir / 'prepare_raw_baseline.py',
        host_test_config_template=host_configs_dir / 'pdbert_vpbench.jsonnet',
        host_joined_predictions_csv=host_output_dir / 'predictions_joined.csv',
        container_dataset_dir=container_dataset_dir,
        container_output_dir=container_output_dir,
        container_dataset_csv=container_dataset_dir / 'Real_Vul_data.csv',
        container_runtime_test_config=container_dataset_dir
        / '_run_pdbert_eval_only'
        / 'pdbert_test_runtime.jsonnet',
    )


def validate_paths(paths: PDBERTEvalOnlyPaths) -> None:
    required_paths = {
        'PDBERT prepare_dataset.py': paths.host_prepare_script,
        'PDBERT train_eval_from_config.py': paths.host_train_eval_script,
        'PDBERT analyze_prediction.py': paths.host_analyze_script,
        'PDBERT test config template': paths.host_test_config_template,
    }
    for label, path in required_paths.items():
        if not path.exists():
            raise ValueError(f'{label} not found: {path}')


def ensure_output_targets(paths: PDBERTEvalOnlyPaths, *, overwrite: bool) -> None:
    _bench_runner.ensure_output_targets(
        [paths], overwrite=overwrite, runner_name='PDBERT eval-only'
    )


def _remove_output_targets_via_container(container_name: str, paths: PDBERTEvalOnlyPaths) -> None:
    _bench_runner.remove_output_targets_via_container(
        container_name=container_name,
        paths=paths,
        runner_name='PDBERT eval-only',
    )


def cleanup_output_targets(paths: PDBERTEvalOnlyPaths, *, container_name: str) -> None:
    _bench_runner.cleanup_output_targets(
        [paths],
        remove_host_output_path_fn=_bench_runner.remove_host_output_path,
        remove_container_targets_fn=lambda selected: _remove_output_targets_via_container(
            container_name,
            selected,
        ),
    )


def stage_runtime_config(paths: PDBERTEvalOnlyPaths) -> None:
    _run_pdbert.write_runtime_config(
        paths.host_test_config_template,
        paths.host_runtime_test_config,
        paths.container_dataset_dir,
    )


def _best_effort_join_predictions(
    *,
    dataset_csv: Path,
    row_manifest: Path | None,
    eval_result_csv: Path,
    output_path: Path,
) -> bool:
    if row_manifest is None or not row_manifest.exists() or not eval_result_csv.exists():
        return False

    with dataset_csv.open('r', encoding='utf-8', newline='') as f:
        dataset_rows = list(csv.DictReader(f))
    with eval_result_csv.open('r', encoding='utf-8', newline='') as f:
        eval_rows = list(csv.DictReader(f))
    if not eval_rows:
        return False

    manifest_rows = [
        json.loads(line)
        for line in row_manifest.read_text(encoding='utf-8').splitlines()
        if line.strip()
    ]
    manifest_by_row_id = {str(row.get('row_id') or ''): row for row in manifest_rows}
    dataset_by_row_id = {
        str(row.get('unique_id') or row.get('file_name') or ''): row for row in dataset_rows
    }

    eval_key = next(
        (
            key
            for key in ('unique_id', 'file_name', 'row_id', 'id')
            if key in (eval_rows[0].keys() if eval_rows else {})
        ),
        None,
    )
    if eval_key is None:
        return False

    joined_rows: list[dict[str, Any]] = []
    for eval_row in eval_rows:
        row_id = str(eval_row.get(eval_key) or '').strip()
        if not row_id:
            continue
        dataset_row = dataset_by_row_id.get(row_id)
        manifest_row = manifest_by_row_id.get(row_id)
        if dataset_row is None and manifest_row is None:
            continue

        joined: dict[str, Any] = {'row_id': row_id}
        if dataset_row is not None:
            for key, value in dataset_row.items():
                joined[f'dataset_{key}'] = value
        if manifest_row is not None:
            for key, value in manifest_row.items():
                if key == 'row_id':
                    continue
                joined[f'manifest_{key}'] = (
                    json.dumps(value, ensure_ascii=False)
                    if isinstance(value, (dict, list))
                    else value
                )
        for key, value in eval_row.items():
            joined[f'eval_{key}'] = value
        joined_rows.append(joined)

    if not joined_rows:
        return False

    fieldnames = []
    for row in joined_rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(joined_rows)
    return True


def print_planned_commands(config: PDBERTEvalOnlyConfig, paths: PDBERTEvalOnlyPaths) -> None:
    print(f'Dataset CSV: {paths.source_csv}')
    print(f'Model dir: {config.model_dir}')
    print(
        '[analyze/setup] '
        + ' '.join(
            _run_pdbert.build_analyze_setup_command(
                paths,
                container_name=config.container_name,
            )
        )
    )
    for phase, command in (
        ('prepare', _run_pdbert.build_prepare_command(config, paths)),
        ('test', _run_pdbert.build_train_eval_command(config, paths, phase='test')),
        ('analyze', _run_pdbert.build_analyze_command(config, paths)),
    ):
        print(f'[{paths.target_name}/{phase}] {" ".join(command)}')


def print_completion_summary(paths: PDBERTEvalOnlyPaths) -> None:
    print('PDBERT eval-only run completed.')
    print(f'  - staged_csv: {paths.host_dataset_csv}')
    print(f'  - model_dir: {paths.host_output_dir}')
    print(f'  - eval_result: {paths.host_eval_result_csv}')
    print(f'  - analysis_json: {paths.host_analysis_json}')
    print(f'  - feature_npz: {paths.host_feature_npz}')
    print(f'  - tsne_image: {paths.host_feature_tsne_image}')
    print(f'  - joined_predictions: {paths.host_joined_predictions_csv}')
    print(f'  - logs: {paths.host_prepare_log.parent}')


def run_pdbert_eval_only(config: PDBERTEvalOnlyConfig) -> int:
    validate_config(config)
    paths = build_eval_only_paths(config)
    validate_paths(paths)
    _run_pdbert.require_model_artifacts(config.model_dir, label=str(config.model_dir))
    _bench_runner.validate_stage07_csv(
        paths.source_csv,
        required_dataset_types=_run_pdbert.TEST_ONLY_REQUIRED_DATASET_TYPES,
    )
    ensure_output_targets(paths, overwrite=config.overwrite)

    if config.dry_run:
        print_planned_commands(config, paths)
        return 0

    _run_pdbert.check_container_running(config.container_name)
    if config.overwrite:
        cleanup_output_targets(paths, container_name=config.container_name)

    _run_pdbert.stage_source_csv(paths)
    stage_runtime_config(paths)
    _run_pdbert.stage_model_artifacts(config.model_dir, paths.host_output_dir)
    _run_pdbert.require_exists(paths.host_output_dir / 'config.json', 'config.json')
    _run_pdbert.require_exists(paths.host_output_dir / 'model.tar.gz', 'model.tar.gz')

    prepare_command = _run_pdbert.build_prepare_command(config, paths)
    print(f'Running PDBERT prepare for {paths.display_name}...')
    _run_pdbert.run_logged_command(prepare_command, paths.host_prepare_log)
    _run_pdbert.require_exists(paths.host_dataset_dir / 'test.json', 'test.json')

    test_command = _run_pdbert.build_train_eval_command(config, paths, phase='test')
    print(f'Running PDBERT test for {paths.display_name}...')
    _run_pdbert.run_logged_command(test_command, paths.host_test_log)
    _run_pdbert.require_exists(paths.host_output_dir / 'config.json', 'config.json')
    _run_pdbert.require_exists(paths.host_output_dir / 'model.tar.gz', 'model.tar.gz')

    analyze_command = _run_pdbert.build_analyze_command(config, paths)
    _run_pdbert.copy_analyze_script_to_container(paths, config.container_name)
    print(f'Running PDBERT analyze for {paths.display_name}...')
    _run_pdbert.run_logged_command(analyze_command, paths.host_analyze_log)
    _run_pdbert.require_exists(paths.host_eval_result_csv, 'eval_result.csv')
    _run_pdbert.require_exists(paths.host_analysis_json, 'prediction_analysis.json')
    _run_pdbert.require_exists(paths.host_feature_npz, 'test_last_hidden_state_vectors.npz')

    joined = _best_effort_join_predictions(
        dataset_csv=paths.host_dataset_csv,
        row_manifest=config.row_manifest,
        eval_result_csv=paths.host_eval_result_csv,
        output_path=paths.host_joined_predictions_csv,
    )
    if not joined:
        print(
            'Skipped predictions_joined.csv (row manifest missing or eval_result.csv has no row id).'
        )

    print_completion_summary(paths)
    return 0


def main() -> int:
    args = parse_args()
    eval_name = args.eval_name or _default_eval_name(args.dataset_csv.resolve())
    config = normalize_config(
        PDBERTEvalOnlyConfig(
            dataset_csv=args.dataset_csv,
            row_manifest=args.row_manifest,
            model_dir=args.model_dir,
            vpbench_root=args.vpbench_root,
            container_name=args.container_name,
            eval_name=eval_name,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
    )
    try:
        return run_pdbert_eval_only(config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
