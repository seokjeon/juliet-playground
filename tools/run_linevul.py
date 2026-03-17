#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from shared.artifact_layout import build_dataset_export_paths
from shared.paths import RESULT_DIR
from shared.pipeline_runs import find_latest_pipeline_run_dir

JULIET_LINEVUL_NAMESPACE = 'juliet-playground'
DEFAULT_VPBENCH_ROOT = Path('/home/sojeon/Desktop/VP-Bench')
DEFAULT_CONTAINER_NAME = 'linevul'
DEFAULT_TOKENIZER_NAME = 'microsoft/codebert-base'
DEFAULT_MODEL_NAME = 'microsoft/codebert-base'
DEFAULT_TRAIN_BATCH_SIZE = 64
DEFAULT_EVAL_BATCH_SIZE = 8
DEFAULT_NUM_TRAIN_EPOCHS = 10
REQUIRED_COLUMNS = {
    'processed_func',
    'vulnerable_line_numbers',
    'dataset_type',
    'target',
}
REQUIRED_DATASET_TYPES = {'train_val', 'test'}
CONTAINER_DATASET_BASE = Path('/app/RealVul/Dataset')
CONTAINER_EXPERIMENT_BASE = Path('/app/RealVul/Experiments/LineVul')
CONTAINER_LINE_VUL_SCRIPT = CONTAINER_EXPERIMENT_BASE / 'line_vul.py'


@dataclass(frozen=True)
class LineVulRunConfig:
    run_dir: Path | None
    pipeline_root: Path
    vpbench_root: Path
    container_name: str
    tokenizer_name: str
    model_name: str
    train_batch_size: int
    eval_batch_size: int
    num_train_epochs: int
    overwrite: bool
    dry_run: bool


@dataclass(frozen=True)
class LineVulPaths:
    run_dir: Path
    run_name: str
    source_csv: Path
    host_dataset_dir: Path
    host_output_dir: Path
    host_dataset_csv: Path
    host_prepare_log: Path
    host_train_log: Path
    host_test_log: Path
    host_train_dataset_pkl: Path
    host_val_dataset_pkl: Path
    host_test_dataset_pkl: Path
    host_best_model_dir: Path
    host_test_predictions_csv: Path
    host_line_vul_script: Path
    container_dataset_dir: Path
    container_output_dir: Path
    container_dataset_csv: Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run VP-Bench LineVul prepare/train/test from a pipeline Stage 07 CSV.'
    )
    parser.add_argument('--run-dir', type=Path, default=None)
    parser.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
    )
    parser.add_argument('--vpbench-root', type=Path, default=DEFAULT_VPBENCH_ROOT)
    parser.add_argument('--container-name', type=str, default=DEFAULT_CONTAINER_NAME)
    parser.add_argument('--tokenizer-name', type=str, default=DEFAULT_TOKENIZER_NAME)
    parser.add_argument('--model-name', type=str, default=DEFAULT_MODEL_NAME)
    parser.add_argument('--train-batch-size', type=int, default=DEFAULT_TRAIN_BATCH_SIZE)
    parser.add_argument('--eval-batch-size', type=int, default=DEFAULT_EVAL_BATCH_SIZE)
    parser.add_argument('--num-train-epochs', type=int, default=DEFAULT_NUM_TRAIN_EPOCHS)
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    return parser.parse_args()


def normalize_config(config: LineVulRunConfig) -> LineVulRunConfig:
    return LineVulRunConfig(
        run_dir=config.run_dir.resolve() if config.run_dir is not None else None,
        pipeline_root=config.pipeline_root.resolve(),
        vpbench_root=config.vpbench_root.resolve(),
        container_name=config.container_name,
        tokenizer_name=config.tokenizer_name,
        model_name=config.model_name,
        train_batch_size=config.train_batch_size,
        eval_batch_size=config.eval_batch_size,
        num_train_epochs=config.num_train_epochs,
        overwrite=config.overwrite,
        dry_run=config.dry_run,
    )


def validate_config(config: LineVulRunConfig) -> None:
    if config.train_batch_size <= 0:
        raise ValueError(f'train_batch_size must be > 0: {config.train_batch_size}')
    if config.eval_batch_size <= 0:
        raise ValueError(f'eval_batch_size must be > 0: {config.eval_batch_size}')
    if config.num_train_epochs <= 0:
        raise ValueError(f'num_train_epochs must be > 0: {config.num_train_epochs}')


def resolve_run_dir(config: LineVulRunConfig) -> Path:
    if config.run_dir is not None:
        if not config.run_dir.exists():
            raise ValueError(f'Pipeline run dir not found: {config.run_dir}')
        return config.run_dir
    try:
        return find_latest_pipeline_run_dir(config.pipeline_root)
    except FileNotFoundError as exc:
        raise ValueError(str(exc)) from exc


def build_linevul_paths(config: LineVulRunConfig, run_dir: Path) -> LineVulPaths:
    dataset_paths = build_dataset_export_paths(run_dir / '07_dataset_export')
    source_csv = dataset_paths['csv_path']
    run_name = run_dir.name
    host_dataset_dir = (
        config.vpbench_root
        / 'downloads'
        / 'RealVul'
        / 'datasets'
        / JULIET_LINEVUL_NAMESPACE
        / run_name
    )
    host_output_dir = (
        config.vpbench_root
        / 'baseline'
        / 'RealVul'
        / 'Experiments'
        / 'LineVul'
        / JULIET_LINEVUL_NAMESPACE
        / run_name
    )
    container_dataset_dir = CONTAINER_DATASET_BASE / JULIET_LINEVUL_NAMESPACE / run_name
    container_output_dir = CONTAINER_EXPERIMENT_BASE / JULIET_LINEVUL_NAMESPACE / run_name
    return LineVulPaths(
        run_dir=run_dir,
        run_name=run_name,
        source_csv=source_csv,
        host_dataset_dir=host_dataset_dir,
        host_output_dir=host_output_dir,
        host_dataset_csv=host_dataset_dir / 'Real_Vul_data.csv',
        host_prepare_log=host_output_dir / 'prepare.log',
        host_train_log=host_output_dir / 'train.log',
        host_test_log=host_output_dir / 'test.log',
        host_train_dataset_pkl=host_dataset_dir / 'train_dataset.pkl',
        host_val_dataset_pkl=host_dataset_dir / 'val_dataset.pkl',
        host_test_dataset_pkl=host_dataset_dir / 'test_dataset.pkl',
        host_best_model_dir=host_output_dir / 'best_model',
        host_test_predictions_csv=host_output_dir / 'test_pred_with_code.csv',
        host_line_vul_script=(
            config.vpbench_root / 'baseline' / 'RealVul' / 'Experiments' / 'LineVul' / 'line_vul.py'
        ),
        container_dataset_dir=container_dataset_dir,
        container_output_dir=container_output_dir,
        container_dataset_csv=container_dataset_dir / 'Real_Vul_data.csv',
    )


def validate_paths(paths: LineVulPaths) -> None:
    if not paths.run_dir.exists():
        raise ValueError(f'Pipeline run dir not found: {paths.run_dir}')
    if not paths.source_csv.exists():
        raise ValueError(f'Stage 07 dataset CSV not found: {paths.source_csv}')
    if not paths.host_line_vul_script.exists():
        raise ValueError(f'VP-Bench line_vul.py not found: {paths.host_line_vul_script}')


def validate_stage07_csv(path: Path) -> dict[str, int]:
    with path.open(newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        fieldnames = set(reader.fieldnames or [])
        missing_columns = sorted(REQUIRED_COLUMNS - fieldnames)
        if missing_columns:
            raise ValueError(
                f'Stage 07 dataset CSV missing required columns: {", ".join(missing_columns)}'
            )

        dataset_type_counts: dict[str, int] = {}
        row_count = 0
        for row in reader:
            row_count += 1
            dataset_type = str(row.get('dataset_type') or '').strip()
            dataset_type_counts[dataset_type] = dataset_type_counts.get(dataset_type, 0) + 1

    if row_count == 0:
        raise ValueError(f'Stage 07 dataset CSV is empty: {path}')

    missing_dataset_types = sorted(
        label for label in REQUIRED_DATASET_TYPES if dataset_type_counts.get(label, 0) == 0
    )
    if missing_dataset_types:
        raise ValueError(
            'Stage 07 dataset CSV must contain both train_val and test rows; '
            f'missing: {", ".join(missing_dataset_types)}'
        )
    return dataset_type_counts


def ensure_output_targets(paths: LineVulPaths, *, overwrite: bool) -> None:
    existing = [path for path in (paths.host_dataset_dir, paths.host_output_dir) if path.exists()]
    if existing and not overwrite:
        joined = ', '.join(str(path) for path in existing)
        raise ValueError(
            f'LineVul output already exists for run {paths.run_name}: {joined} '
            '(use --overwrite to replace it)'
        )
    if overwrite:
        for path in existing:
            shutil.rmtree(path)


def stage_source_csv(paths: LineVulPaths) -> None:
    paths.host_dataset_dir.mkdir(parents=True, exist_ok=True)
    paths.host_output_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(paths.source_csv, paths.host_dataset_csv)


def build_line_vul_command(
    config: LineVulRunConfig,
    paths: LineVulPaths,
    *,
    phase: str,
) -> list[str]:
    if phase == 'prepare':
        phase_flags = ['--prepare_dataset']
        train_batch_size = config.eval_batch_size
        eval_batch_size = config.eval_batch_size
    elif phase == 'train':
        phase_flags = ['--train']
        train_batch_size = config.train_batch_size
        eval_batch_size = config.train_batch_size
    elif phase == 'test':
        phase_flags = ['--test_predict']
        train_batch_size = config.eval_batch_size
        eval_batch_size = config.eval_batch_size
    else:
        raise ValueError(f'Unsupported LineVul phase: {phase}')

    return [
        'docker',
        'exec',
        config.container_name,
        'python',
        str(CONTAINER_LINE_VUL_SCRIPT),
        '--dataset_csv_path',
        str(paths.container_dataset_csv),
        '--dataset_path',
        str(paths.container_dataset_dir),
        '--output_dir',
        str(paths.container_output_dir),
        '--tokenizer_name',
        config.tokenizer_name,
        '--model_name',
        config.model_name,
        '--per_device_train_batch_size',
        str(train_batch_size),
        '--per_device_eval_batch_size',
        str(eval_batch_size),
        '--num_train_epochs',
        str(config.num_train_epochs),
        *phase_flags,
    ]


def check_container_running(container_name: str) -> None:
    result = subprocess.run(
        ['docker', 'inspect', '--format', '{{.State.Running}}', container_name],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or 'unknown docker inspect error'
        raise RuntimeError(f'Failed to inspect Docker container {container_name}: {message}')
    if result.stdout.strip().lower() != 'true':
        raise RuntimeError(f'Docker container is not running: {container_name}')


def run_logged_command(command: Sequence[str], log_path: Path) -> None:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open('w', encoding='utf-8') as log_fp:
        log_fp.write(f'$ {" ".join(command)}\n')
        log_fp.flush()
        process = subprocess.Popen(
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        try:
            for line in process.stdout:
                print(line, end='')
                log_fp.write(line)
                log_fp.flush()
        finally:
            process.stdout.close()
        return_code = process.wait()
    if return_code != 0:
        raise subprocess.CalledProcessError(return_code, list(command))


def require_exists(path: Path, label: str) -> None:
    if not path.exists():
        raise RuntimeError(f'Expected {label} not found: {path}')


def print_planned_commands(commands: list[tuple[str, list[str]]], paths: LineVulPaths) -> None:
    print(f'Pipeline run: {paths.run_dir}')
    print(f'Stage 07 CSV: {paths.source_csv}')
    print(f'Host dataset dir: {paths.host_dataset_dir}')
    print(f'Host output dir: {paths.host_output_dir}')
    print(f'Container dataset dir: {paths.container_dataset_dir}')
    print(f'Container output dir: {paths.container_output_dir}')
    for phase, command in commands:
        print(f'[{phase}] {" ".join(command)}')


def print_completion_summary(paths: LineVulPaths) -> None:
    print('LineVul run completed.')
    print(f'  - staged_csv: {paths.host_dataset_csv}')
    print(f'  - dataset_pickles: {paths.host_dataset_dir}')
    print(f'  - best_model: {paths.host_best_model_dir}')
    print(f'  - test_predictions: {paths.host_test_predictions_csv}')
    print(f'  - logs: {paths.host_output_dir}')


def run_linevul_from_pipeline(config: LineVulRunConfig) -> int:
    validate_config(config)
    run_dir = resolve_run_dir(config)
    paths = build_linevul_paths(config, run_dir)
    validate_paths(paths)
    validate_stage07_csv(paths.source_csv)
    ensure_output_targets(paths, overwrite=config.overwrite)

    commands = [
        ('prepare', build_line_vul_command(config, paths, phase='prepare')),
        ('train', build_line_vul_command(config, paths, phase='train')),
        ('test', build_line_vul_command(config, paths, phase='test')),
    ]

    if config.dry_run:
        print_planned_commands(commands, paths)
        return 0

    check_container_running(config.container_name)
    stage_source_csv(paths)

    print(f'Running LineVul prepare for {paths.run_name}...')
    run_logged_command(commands[0][1], paths.host_prepare_log)
    require_exists(paths.host_train_dataset_pkl, 'train_dataset.pkl')
    require_exists(paths.host_val_dataset_pkl, 'val_dataset.pkl')
    require_exists(paths.host_test_dataset_pkl, 'test_dataset.pkl')

    print(f'Running LineVul train for {paths.run_name}...')
    run_logged_command(commands[1][1], paths.host_train_log)
    require_exists(paths.host_best_model_dir / 'config.json', 'best_model/config.json')

    print(f'Running LineVul test for {paths.run_name}...')
    run_logged_command(commands[2][1], paths.host_test_log)
    require_exists(paths.host_test_predictions_csv, 'test_pred_with_code.csv')

    print_completion_summary(paths)
    return 0


def main() -> int:
    args = parse_args()
    config = normalize_config(
        LineVulRunConfig(
            run_dir=args.run_dir,
            pipeline_root=args.pipeline_root,
            vpbench_root=args.vpbench_root,
            container_name=args.container_name,
            tokenizer_name=args.tokenizer_name,
            model_name=args.model_name,
            train_batch_size=args.train_batch_size,
            eval_batch_size=args.eval_batch_size,
            num_train_epochs=args.num_train_epochs,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
    )
    try:
        return run_linevul_from_pipeline(config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
