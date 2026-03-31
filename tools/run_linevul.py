#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from shared import bench_runner as _bench_runner
from shared.artifact_layout import build_dataset_export_paths
from shared.paths import RESULT_DIR

JULIET_LINEVUL_NAMESPACE = 'juliet-playground'
EXTENDED_REALVUL_NAMESPACE = 'extended_realvul'
DEFAULT_VPBENCH_ROOT = Path('/home/mjbin/lab/VP-Bench')
DEFAULT_CONTAINER_NAME = 'linevul'
DEFAULT_TOKENIZER_NAME = 'microsoft/codebert-base'
DEFAULT_MODEL_NAME = 'microsoft/codebert-base'
DEFAULT_TRAIN_BATCH_SIZE = 8
DEFAULT_EVAL_BATCH_SIZE = 8
DEFAULT_NUM_TRAIN_EPOCHS = 10
PRIMARY_TARGET_NAME = 'primary'
VULN_PATCH_TARGET_NAME = 'vuln_patch'
EXTENDED_REALVUL_TARGET_NAME = EXTENDED_REALVUL_NAMESPACE
TRAINING_LOSS_LOG_NAME = 'training_loss.log'
TRAINING_LOSS_PLOT_NAME = 'train_loss_by_epoch.png'
TRAIN_EPOCH_LOSS_PREFIX = 'TRAIN_EPOCH_LOSS '
EXTENDED_REALVUL_LOG_NAME = 'extended_realvul.log'
EXTENDED_REALVUL_DATASET_NAME = 'all_projects_vul_patch_dataset_test.csv'
EXTENDED_REALVUL_MODEL_ARCHIVE_NAME = 'linevul_best_model.tar.gz'
EXTENDED_REALVUL_MODEL_DIRNAME = 'after_fine_tuned_model'
EXTENDED_REALVUL_DATASET_URL = (
    'https://github.com/seokjeon/VP-Bench/releases/download/'
    'VP-Bench_Test_Dataset/all_projects_vul_patch_dataset_test.csv'
)
EXTENDED_REALVUL_MODEL_URL = (
    'https://github.com/seokjeon/VP-Bench/releases/download/trained_model/linevul_best_model.tar.gz'
)
REQUIRED_MODEL_ARTIFACT_NAMES = ('config.json', 'pytorch_model.bin')
COMBINED_TEST_TSNE_BASENAME = 'combined_test_last_hidden_state_vectors'
REQUIRED_COLUMNS = _bench_runner.REQUIRED_COLUMNS
PRIMARY_REQUIRED_DATASET_TYPES = _bench_runner.PRIMARY_REQUIRED_DATASET_TYPES
TEST_ONLY_REQUIRED_DATASET_TYPES = _bench_runner.TEST_ONLY_REQUIRED_DATASET_TYPES
CONTAINER_DATASET_BASE = Path('/app/RealVul/Dataset')
CONTAINER_EXPERIMENT_BASE = Path('/app/RealVul/Experiments/LineVul')
CONTAINER_LINE_VUL_SCRIPT = CONTAINER_EXPERIMENT_BASE / 'line_vul.py'
CONTAINER_BASELINE_MODEL_DIR = CONTAINER_EXPERIMENT_BASE / 'best_model'


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
    extended_realvul: bool
    overwrite: bool
    dry_run: bool


@dataclass(frozen=True)
class LineVulPaths:
    run_dir: Path
    run_name: str
    target_name: str
    display_name: str
    source_csv: Path
    host_dataset_dir: Path
    host_output_dir: Path
    host_dataset_csv: Path
    host_prepare_log: Path
    host_train_log: Path
    host_test_log: Path
    host_raw_test_log: Path
    host_extended_eval_log: Path
    host_train_dataset_pkl: Path
    host_val_dataset_pkl: Path
    host_test_dataset_pkl: Path
    host_training_loss_log: Path
    host_training_loss_plot: Path
    host_best_model_dir: Path
    host_fine_tuned_model_archive: Path
    host_fine_tuned_model_dir: Path
    host_test_predictions_csv: Path
    host_raw_test_output_dir: Path
    host_raw_test_predictions_csv: Path
    host_line_vul_script: Path
    container_dataset_dir: Path
    container_output_dir: Path
    container_raw_test_output_dir: Path
    container_dataset_csv: Path
    container_fine_tuned_model_dir: Path
    container_baseline_model_dir: Path


@dataclass(frozen=True)
class LineVulCommandStep:
    paths: LineVulPaths
    phase: str
    command: list[str]

    @property
    def label(self) -> str:
        return f'{self.paths.target_name}/{self.phase}'


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
    parser.add_argument('--extended-realvul', action='store_true')
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
        extended_realvul=config.extended_realvul,
        overwrite=config.overwrite,
        dry_run=config.dry_run,
    )


def validate_config(config: LineVulRunConfig) -> None:
    if not config.vpbench_root.exists():
        raise ValueError(f'VP-Bench root not found: {config.vpbench_root}')
    if config.train_batch_size <= 0:
        raise ValueError(f'train_batch_size must be > 0: {config.train_batch_size}')
    if config.eval_batch_size <= 0:
        raise ValueError(f'eval_batch_size must be > 0: {config.eval_batch_size}')
    if config.num_train_epochs <= 0:
        raise ValueError(f'num_train_epochs must be > 0: {config.num_train_epochs}')
    if config.extended_realvul and config.run_dir is not None:
        raise ValueError('--run-dir is not used with --extended-realvul')


def resolve_run_dir(config: LineVulRunConfig) -> Path:
    return _bench_runner.resolve_run_dir(
        run_dir=config.run_dir,
        pipeline_root=config.pipeline_root,
    )


validate_stage07_csv = _bench_runner.validate_stage07_csv
_existing_output_targets = _bench_runner.existing_output_targets
_remove_host_output_path = _bench_runner.remove_host_output_path
stage_source_csv = _bench_runner.stage_source_csv
check_container_running = _bench_runner.check_container_running
run_logged_command = _bench_runner.run_logged_command
require_exists = _bench_runner.require_exists


def extended_realvul_download_root(config: LineVulRunConfig) -> Path:
    return config.vpbench_root / 'downloads' / 'LineVul' / EXTENDED_REALVUL_NAMESPACE


def extended_realvul_source_csv(config: LineVulRunConfig) -> Path:
    return extended_realvul_download_root(config) / EXTENDED_REALVUL_DATASET_NAME


def extended_realvul_model_archive_path(config: LineVulRunConfig) -> Path:
    return extended_realvul_download_root(config) / EXTENDED_REALVUL_MODEL_ARCHIVE_NAME


def _artifact_image_and_cache(npz_path: Path) -> tuple[Path, Path]:
    base_path = npz_path.with_suffix('')
    return Path(f'{base_path}.jpeg'), Path(f'{base_path}-tsne-features.json')


def combined_feature_artifact_paths(paths: LineVulPaths) -> tuple[Path, Path]:
    base_path = paths.host_output_dir / COMBINED_TEST_TSNE_BASENAME
    return Path(f'{base_path}.jpeg'), Path(f'{base_path}-tsne-features.json')


def find_latest_hidden_state_output(output_dir: Path, *, split_name: str = 'test') -> Path | None:
    candidates = sorted(
        output_dir.glob(f'*_{split_name}_last_hidden_state_vectors.npz'),
        key=lambda path: path.name,
    )
    if not candidates:
        return None
    return candidates[-1]


def download_file(url: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(f'{output_path.name}.tmp')
    try:
        with urllib.request.urlopen(url) as response, temp_path.open('wb') as f:
            shutil.copyfileobj(response, f)
        temp_path.replace(output_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def ensure_extended_realvul_dataset(config: LineVulRunConfig) -> Path:
    dataset_csv = extended_realvul_source_csv(config)
    if dataset_csv.exists():
        return dataset_csv
    print(f'Downloading Extended RealVul LineVul dataset to {dataset_csv}...')
    download_file(EXTENDED_REALVUL_DATASET_URL, dataset_csv)
    return dataset_csv


def require_model_artifacts(model_dir: Path, *, label: str) -> None:
    for artifact_name in REQUIRED_MODEL_ARTIFACT_NAMES:
        require_exists(model_dir / artifact_name, f'{label}/{artifact_name}')


def _find_model_dir(root_dir: Path) -> Path:
    candidates: list[Path] = []
    for path in [root_dir, *sorted(root_dir.rglob('*'))]:
        if not path.is_dir():
            continue
        if all((path / artifact_name).exists() for artifact_name in REQUIRED_MODEL_ARTIFACT_NAMES):
            candidates.append(path)
    if not candidates:
        raise RuntimeError(f'No extracted LineVul model dir found under {root_dir}')
    shortest_path = min(candidates, key=lambda path: (len(path.parts), str(path)))
    return shortest_path


def _copy_directory_contents(source_dir: Path, target_dir: Path) -> None:
    target_dir.mkdir(parents=True, exist_ok=True)
    for source_path in sorted(source_dir.iterdir(), key=lambda path: path.name):
        destination = target_dir / source_path.name
        if destination.exists() or destination.is_symlink():
            if destination.is_dir() and not destination.is_symlink():
                shutil.rmtree(destination)
            else:
                destination.unlink()
        if source_path.is_dir():
            shutil.copytree(source_path, destination)
        else:
            shutil.copy2(source_path, destination)


def stage_downloaded_model_archive(model_archive: Path, target_dir: Path) -> None:
    temp_extract_dir = target_dir.parent / f'.{target_dir.name}.extracting'
    if temp_extract_dir.exists():
        shutil.rmtree(temp_extract_dir)
    temp_extract_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tarfile.open(model_archive, 'r:*') as archive:
            archive.extractall(temp_extract_dir)
        extracted_model_dir = _find_model_dir(temp_extract_dir)
        if target_dir.exists():
            shutil.rmtree(target_dir)
        _copy_directory_contents(extracted_model_dir, target_dir)
    finally:
        if temp_extract_dir.exists():
            shutil.rmtree(temp_extract_dir)


def ensure_extended_realvul_model(config: LineVulRunConfig, paths: LineVulPaths) -> Path:
    if paths.host_fine_tuned_model_dir.exists():
        require_model_artifacts(
            paths.host_fine_tuned_model_dir,
            label=str(paths.host_fine_tuned_model_dir),
        )
        return paths.host_fine_tuned_model_dir

    archive_path = paths.host_fine_tuned_model_archive
    if not archive_path.exists():
        print(f'Downloading Extended RealVul LineVul model to {archive_path}...')
        download_file(EXTENDED_REALVUL_MODEL_URL, archive_path)
    stage_downloaded_model_archive(archive_path, paths.host_fine_tuned_model_dir)
    require_model_artifacts(paths.host_fine_tuned_model_dir, label=str(paths.host_fine_tuned_model_dir))
    return paths.host_fine_tuned_model_dir


def require_extended_realvul_outputs(paths: LineVulPaths) -> None:
    require_exists(paths.host_test_predictions_csv, 'test_pred_with_code.csv')
    require_exists(paths.host_raw_test_predictions_csv, 'raw_model_eval/test_pred_with_code.csv')

    fine_npz = find_latest_hidden_state_output(paths.host_output_dir)
    if fine_npz is None:
        raise RuntimeError(
            f'Expected fine-tuned test hidden-state export not found: {paths.host_output_dir}'
        )
    raw_npz = find_latest_hidden_state_output(paths.host_raw_test_output_dir)
    if raw_npz is None:
        raise RuntimeError(
            'Expected raw-model test hidden-state export not found: '
            f'{paths.host_raw_test_output_dir}'
        )

    for npz_path in (fine_npz, raw_npz):
        require_exists(npz_path, str(npz_path))
        image_path, cache_path = _artifact_image_and_cache(npz_path)
        require_exists(image_path, image_path.name)
        require_exists(cache_path, cache_path.name)

    combined_image, combined_cache = combined_feature_artifact_paths(paths)
    require_exists(combined_image, combined_image.name)
    require_exists(combined_cache, combined_cache.name)


def build_linevul_paths(
    config: LineVulRunConfig,
    run_dir: Path,
    *,
    target_name: str,
) -> LineVulPaths:
    if target_name == PRIMARY_TARGET_NAME:
        dataset_paths = build_dataset_export_paths(run_dir / '07_dataset_export')
        source_csv = dataset_paths['csv_path']
        relative_parts: tuple[str, ...] = ()
        run_name = run_dir.name
    elif target_name == VULN_PATCH_TARGET_NAME:
        source_csv = run_dir / '07_dataset_export' / 'vuln_patch' / 'Real_Vul_data.csv'
        relative_parts = (VULN_PATCH_TARGET_NAME,)
        run_name = run_dir.name
    elif target_name == EXTENDED_REALVUL_TARGET_NAME:
        source_csv = extended_realvul_source_csv(config)
        relative_parts = ()
        run_name = EXTENDED_REALVUL_NAMESPACE
    else:
        raise ValueError(f'Unsupported LineVul target: {target_name}')

    display_name = '/'.join((run_name, *relative_parts)) if relative_parts else run_name
    if target_name == EXTENDED_REALVUL_TARGET_NAME:
        host_dataset_dir = (
            config.vpbench_root / 'downloads' / 'RealVul' / 'datasets' / EXTENDED_REALVUL_NAMESPACE
        )
        host_output_dir = (
            config.vpbench_root
            / 'baseline'
            / 'RealVul'
            / 'Experiments'
            / 'LineVul'
            / EXTENDED_REALVUL_NAMESPACE
        )
        container_dataset_dir = CONTAINER_DATASET_BASE / EXTENDED_REALVUL_NAMESPACE
        container_output_dir = CONTAINER_EXPERIMENT_BASE / EXTENDED_REALVUL_NAMESPACE
    else:
        base_host_dataset_dir = (
            config.vpbench_root
            / 'downloads'
            / 'RealVul'
            / 'datasets'
            / JULIET_LINEVUL_NAMESPACE
            / run_name
        )
        base_host_output_dir = (
            config.vpbench_root
            / 'baseline'
            / 'RealVul'
            / 'Experiments'
            / 'LineVul'
            / JULIET_LINEVUL_NAMESPACE
            / run_name
        )
        host_dataset_dir = base_host_dataset_dir.joinpath(*relative_parts)
        host_output_dir = base_host_output_dir.joinpath(*relative_parts)
        container_dataset_dir = (CONTAINER_DATASET_BASE / JULIET_LINEVUL_NAMESPACE / run_name).joinpath(
            *relative_parts
        )
        container_output_dir = (
            CONTAINER_EXPERIMENT_BASE / JULIET_LINEVUL_NAMESPACE / run_name
        ).joinpath(*relative_parts)
    return LineVulPaths(
        run_dir=run_dir,
        run_name=run_name,
        target_name=target_name,
        display_name=display_name,
        source_csv=source_csv,
        host_dataset_dir=host_dataset_dir,
        host_output_dir=host_output_dir,
        host_dataset_csv=host_dataset_dir / 'Real_Vul_data.csv',
        host_prepare_log=host_output_dir / 'prepare.log',
        host_train_log=host_output_dir / 'train.log',
        host_test_log=host_output_dir / 'test.log',
        host_raw_test_log=host_output_dir / 'raw_model_test.log',
        host_extended_eval_log=host_output_dir / EXTENDED_REALVUL_LOG_NAME,
        host_train_dataset_pkl=host_dataset_dir / 'train_dataset.pkl',
        host_val_dataset_pkl=host_dataset_dir / 'val_dataset.pkl',
        host_test_dataset_pkl=host_dataset_dir / 'test_dataset.pkl',
        host_training_loss_log=host_output_dir / TRAINING_LOSS_LOG_NAME,
        host_training_loss_plot=host_output_dir / TRAINING_LOSS_PLOT_NAME,
        host_best_model_dir=host_output_dir / 'best_model',
        host_fine_tuned_model_archive=extended_realvul_model_archive_path(config),
        host_fine_tuned_model_dir=host_output_dir / EXTENDED_REALVUL_MODEL_DIRNAME,
        host_test_predictions_csv=host_output_dir / 'test_pred_with_code.csv',
        host_raw_test_output_dir=host_output_dir / 'raw_model_eval',
        host_raw_test_predictions_csv=(host_output_dir / 'raw_model_eval' / 'test_pred_with_code.csv'),
        host_line_vul_script=(
            config.vpbench_root / 'baseline' / 'RealVul' / 'Experiments' / 'LineVul' / 'line_vul.py'
        ),
        container_dataset_dir=container_dataset_dir,
        container_output_dir=container_output_dir,
        container_raw_test_output_dir=container_output_dir / 'raw_model_eval',
        container_dataset_csv=container_dataset_dir / 'Real_Vul_data.csv',
        container_fine_tuned_model_dir=container_output_dir / EXTENDED_REALVUL_MODEL_DIRNAME,
        container_baseline_model_dir=CONTAINER_BASELINE_MODEL_DIR,
    )


def validate_paths(
    paths: LineVulPaths,
    *,
    allow_missing_source: bool = False,
) -> None:
    if paths.target_name != EXTENDED_REALVUL_TARGET_NAME and not paths.run_dir.exists():
        raise ValueError(f'Pipeline run dir not found: {paths.run_dir}')
    if not allow_missing_source and not paths.source_csv.exists():
        raise ValueError(f'Stage 07 dataset CSV not found: {paths.source_csv}')
    if not paths.host_line_vul_script.exists():
        raise ValueError(f'VP-Bench line_vul.py not found: {paths.host_line_vul_script}')


def discover_linevul_targets(config: LineVulRunConfig, run_dir: Path) -> list[LineVulPaths]:
    if config.extended_realvul:
        return [
            build_linevul_paths(
                config,
                run_dir,
                target_name=EXTENDED_REALVUL_TARGET_NAME,
            )
        ]
    primary_paths = build_linevul_paths(config, run_dir, target_name=PRIMARY_TARGET_NAME)
    vuln_patch_paths = build_linevul_paths(config, run_dir, target_name=VULN_PATCH_TARGET_NAME)
    targets = [primary_paths]
    if vuln_patch_paths.source_csv.exists():
        targets.append(vuln_patch_paths)
    return targets


def ensure_output_targets(paths_list: Sequence[LineVulPaths], *, overwrite: bool) -> None:
    _bench_runner.ensure_output_targets(paths_list, overwrite=overwrite, runner_name='LineVul')


def _remove_output_targets_via_container(container_name: str, paths: LineVulPaths) -> None:
    _bench_runner.remove_output_targets_via_container(
        container_name=container_name,
        paths=paths,
        runner_name='LineVul',
        subprocess_run=subprocess.run,
    )


def cleanup_output_targets(paths_list: Sequence[LineVulPaths], *, container_name: str) -> None:
    _bench_runner.cleanup_output_targets(
        paths_list,
        remove_host_output_path_fn=_remove_host_output_path,
        remove_container_targets_fn=lambda paths: _remove_output_targets_via_container(
            container_name,
            paths,
        ),
    )


def stage_reused_best_model(source_paths: LineVulPaths, target_paths: LineVulPaths) -> None:
    require_exists(source_paths.host_best_model_dir / 'config.json', 'best_model/config.json')
    target_paths.host_output_dir.mkdir(parents=True, exist_ok=True)

    if target_paths.host_best_model_dir.is_symlink() or target_paths.host_best_model_dir.is_file():
        target_paths.host_best_model_dir.unlink()
    elif target_paths.host_best_model_dir.exists():
        shutil.rmtree(target_paths.host_best_model_dir)

    try:
        relative_target = Path(
            os.path.relpath(
                source_paths.host_best_model_dir,
                start=target_paths.host_best_model_dir.parent,
            )
        )
        target_paths.host_best_model_dir.symlink_to(
            relative_target,
            target_is_directory=True,
        )
    except OSError:
        shutil.copytree(source_paths.host_best_model_dir, target_paths.host_best_model_dir)


def _load_epoch_training_losses(paths: LineVulPaths) -> list[tuple[float, float]]:
    if not paths.host_training_loss_log.exists():
        raise RuntimeError(
            f'Expected LineVul training loss log not found: {paths.host_training_loss_log}'
        )

    epoch_losses_by_epoch: dict[float, float] = {}
    with paths.host_training_loss_log.open(encoding='utf-8') as f:
        for line_no, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or not line.startswith(TRAIN_EPOCH_LOSS_PREFIX):
                continue

            payload_text = line[len(TRAIN_EPOCH_LOSS_PREFIX) :]
            try:
                payload = json.loads(payload_text)
            except json.JSONDecodeError as exc:
                raise RuntimeError(
                    'Failed to parse LineVul training loss entry '
                    f'at {paths.host_training_loss_log}:{line_no}: {exc.msg}'
                ) from exc

            if 'epoch' not in payload or 'loss' not in payload:
                raise RuntimeError(
                    'Expected epoch/loss keys in LineVul training loss entry '
                    f'at {paths.host_training_loss_log}:{line_no}'
                )

            epoch_losses_by_epoch[float(payload['epoch'])] = float(payload['loss'])

    epoch_losses = sorted(epoch_losses_by_epoch.items())
    if not epoch_losses:
        raise RuntimeError(
            'Expected LineVul epoch training losses not found after training: '
            f'{paths.host_training_loss_log}'
        )
    return epoch_losses


def write_training_loss_plot(paths: LineVulPaths) -> Path:
    import matplotlib

    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    epoch_losses = _load_epoch_training_losses(paths)
    plot_path = paths.host_training_loss_plot
    plot_path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(8, 5))
    epochs = [epoch for epoch, _ in epoch_losses]
    losses = [loss for _, loss in epoch_losses]
    ax.plot(epochs, losses, marker='o', linewidth=2)
    ax.set_xlabel('Epoch')
    ax.set_ylabel('Training Loss')
    ax.set_title('Training Loss by Epoch')
    ax.grid(True, alpha=0.3)
    if len(epochs) <= 20:
        ax.set_xticks(epochs)
    fig.tight_layout()
    fig.savefig(plot_path, dpi=200)
    plt.close(fig)
    return plot_path


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
        output_dir = paths.container_output_dir
    elif phase == 'train':
        phase_flags = ['--train']
        train_batch_size = config.train_batch_size
        eval_batch_size = config.train_batch_size
        output_dir = paths.container_output_dir
    elif phase == 'test':
        phase_flags = ['--test_predict']
        train_batch_size = config.eval_batch_size
        eval_batch_size = config.eval_batch_size
        output_dir = paths.container_output_dir
    elif phase == 'raw_test':
        phase_flags = ['--test_predict', '--eval_model_name', config.model_name]
        train_batch_size = config.eval_batch_size
        eval_batch_size = config.eval_batch_size
        output_dir = paths.container_raw_test_output_dir
        model_name = config.model_name
    elif phase == 'extended_eval':
        phase_flags = [
            '--extended-realvul',
            '--baseline_model_name',
            str(paths.container_baseline_model_dir),
        ]
        train_batch_size = config.eval_batch_size
        eval_batch_size = config.eval_batch_size
        output_dir = paths.container_output_dir
        model_name = str(paths.container_fine_tuned_model_dir)
    else:
        raise ValueError(f'Unsupported LineVul phase: {phase}')

    if phase != 'extended_eval':
        model_name = config.model_name

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
        str(output_dir),
        '--tokenizer_name',
        config.tokenizer_name,
        '--model_name',
        model_name,
        '--per_device_train_batch_size',
        str(train_batch_size),
        '--per_device_eval_batch_size',
        str(eval_batch_size),
        '--num_train_epochs',
        str(config.num_train_epochs),
        *phase_flags,
    ]


def build_command_steps(
    config: LineVulRunConfig,
    paths_list: Sequence[LineVulPaths],
) -> list[LineVulCommandStep]:
    commands: list[LineVulCommandStep] = []
    for paths in paths_list:
        if paths.target_name == EXTENDED_REALVUL_TARGET_NAME:
            phases = ('extended_eval',)
        elif paths.target_name == PRIMARY_TARGET_NAME:
            phases = ('prepare', 'train', 'test')
        elif paths.target_name == VULN_PATCH_TARGET_NAME:
            phases = ('prepare', 'test', 'raw_test')
        else:
            raise ValueError(f'Unsupported LineVul target: {paths.target_name}')

        for phase in phases:
            commands.append(
                LineVulCommandStep(
                    paths=paths,
                    phase=phase,
                    command=build_line_vul_command(config, paths, phase=phase),
                )
            )
    return commands


def print_planned_commands(
    config: LineVulRunConfig,
    commands: Sequence[LineVulCommandStep],
    paths_list: Sequence[LineVulPaths],
) -> None:
    if not paths_list:
        return
    if config.extended_realvul:
        print(f'Extended RealVul dataset URL: {EXTENDED_REALVUL_DATASET_URL}')
        print(f'Extended RealVul dataset CSV: {paths_list[0].source_csv}')
        print(f'Extended RealVul model URL: {EXTENDED_REALVUL_MODEL_URL}')
        print(f'Extended RealVul model archive: {paths_list[0].host_fine_tuned_model_archive}')
        print(f'Extended RealVul fine-tuned model dir: {paths_list[0].host_fine_tuned_model_dir}')
        print(f'Extended RealVul baseline model dir: {paths_list[0].container_baseline_model_dir}')
    else:
        print(f'Pipeline run: {paths_list[0].run_dir}')
    for paths in paths_list:
        print(f'Target [{paths.target_name}] Stage 07 CSV: {paths.source_csv}')
        print(f'Target [{paths.target_name}] Host dataset dir: {paths.host_dataset_dir}')
        print(f'Target [{paths.target_name}] Host output dir: {paths.host_output_dir}')
        if paths.target_name == PRIMARY_TARGET_NAME:
            print(
                f'Target [{paths.target_name}] Host training loss log: '
                f'{paths.host_training_loss_log}'
            )
            print(
                f'Target [{paths.target_name}] Host training loss plot: '
                f'{paths.host_training_loss_plot}'
            )
        print(f'Target [{paths.target_name}] Container dataset dir: {paths.container_dataset_dir}')
        print(f'Target [{paths.target_name}] Container output dir: {paths.container_output_dir}')
        if paths.target_name == EXTENDED_REALVUL_TARGET_NAME:
            print(
                f'Target [{paths.target_name}] Container fine-tuned model dir: '
                f'{paths.container_fine_tuned_model_dir}'
            )
            print(
                f'Target [{paths.target_name}] Container baseline model dir: '
                f'{paths.container_baseline_model_dir}'
            )
    for step in commands:
        print(f'[{step.label}] {" ".join(step.command)}')


def print_completion_summary(paths_list: Sequence[LineVulPaths]) -> None:
    print('LineVul run completed.')
    for paths in paths_list:
        print(f'  - [{paths.target_name}] staged_csv: {paths.host_dataset_csv}')
        print(f'  - [{paths.target_name}] dataset_pickles: {paths.host_dataset_dir}')
        if paths.target_name == PRIMARY_TARGET_NAME:
            print(f'  - [{paths.target_name}] training_loss_log: {paths.host_training_loss_log}')
            print(f'  - [{paths.target_name}] training_loss_plot: {paths.host_training_loss_plot}')
        if paths.target_name != EXTENDED_REALVUL_TARGET_NAME:
            print(f'  - [{paths.target_name}] best_model: {paths.host_best_model_dir}')
        print(f'  - [{paths.target_name}] test_predictions: {paths.host_test_predictions_csv}')
        if paths.target_name == VULN_PATCH_TARGET_NAME:
            print(f'  - [{paths.target_name}] raw_model_test_predictions: {paths.host_raw_test_predictions_csv}')
        if paths.target_name == EXTENDED_REALVUL_TARGET_NAME:
            fine_npz = find_latest_hidden_state_output(paths.host_output_dir)
            raw_npz = find_latest_hidden_state_output(paths.host_raw_test_output_dir)
            combined_image, combined_cache = combined_feature_artifact_paths(paths)
            if fine_npz is not None:
                fine_image, _ = _artifact_image_and_cache(fine_npz)
                print(f'  - [{paths.target_name}] fine_tuned_model: {paths.host_fine_tuned_model_dir}')
                print(f'  - [{paths.target_name}] fine_feature_npz: {fine_npz}')
                print(f'  - [{paths.target_name}] fine_tsne_image: {fine_image}')
            if raw_npz is not None:
                raw_image, _ = _artifact_image_and_cache(raw_npz)
                print(f'  - [{paths.target_name}] raw_model_test_predictions: {paths.host_raw_test_predictions_csv}')
                print(f'  - [{paths.target_name}] raw_feature_npz: {raw_npz}')
                print(f'  - [{paths.target_name}] raw_tsne_image: {raw_image}')
            print(f'  - [{paths.target_name}] combined_tsne_image: {combined_image}')
            print(f'  - [{paths.target_name}] combined_tsne_cache: {combined_cache}')
        print(f'  - [{paths.target_name}] logs: {paths.host_output_dir}')


def run_extended_realvul_eval(config: LineVulRunConfig) -> int:
    validate_config(config)
    paths = build_linevul_paths(
        config,
        config.vpbench_root,
        target_name=EXTENDED_REALVUL_TARGET_NAME,
    )
    validate_paths(paths, allow_missing_source=True)
    commands = build_command_steps(config, [paths])

    if config.dry_run:
        print_planned_commands(config, commands, [paths])
        return 0

    ensure_extended_realvul_dataset(config)
    validate_stage07_csv(paths.source_csv, required_dataset_types=TEST_ONLY_REQUIRED_DATASET_TYPES)
    ensure_output_targets([paths], overwrite=config.overwrite)

    check_container_running(config.container_name)
    if config.overwrite:
        cleanup_output_targets([paths], container_name=config.container_name)
    stage_source_csv(paths)
    ensure_extended_realvul_model(config, paths)

    step = commands[0]
    print(f'Running LineVul extended_realvul evaluation for {paths.display_name}...')
    run_logged_command(step.command, paths.host_extended_eval_log)
    require_extended_realvul_outputs(paths)
    print_completion_summary([paths])
    return 0


def run_linevul_from_pipeline(config: LineVulRunConfig) -> int:
    validate_config(config)
    run_dir = resolve_run_dir(config)
    paths_list = discover_linevul_targets(config, run_dir)
    primary_paths = paths_list[0]
    vuln_patch_paths = next(
        (paths for paths in paths_list if paths.target_name == VULN_PATCH_TARGET_NAME),
        None,
    )

    for paths in paths_list:
        validate_paths(paths)
        required_dataset_types = (
            PRIMARY_REQUIRED_DATASET_TYPES
            if paths.target_name == PRIMARY_TARGET_NAME
            else TEST_ONLY_REQUIRED_DATASET_TYPES
        )
        validate_stage07_csv(paths.source_csv, required_dataset_types=required_dataset_types)

    ensure_output_targets(paths_list, overwrite=config.overwrite)
    commands = build_command_steps(config, paths_list)

    if config.dry_run:
        print_planned_commands(config, commands, paths_list)
        return 0

    check_container_running(config.container_name)
    if config.overwrite:
        cleanup_output_targets(paths_list, container_name=config.container_name)
    for paths in paths_list:
        stage_source_csv(paths)

    primary_prepare_step = next(
        step
        for step in commands
        if step.paths.target_name == PRIMARY_TARGET_NAME and step.phase == 'prepare'
    )
    print(f'Running LineVul prepare for {primary_prepare_step.paths.display_name}...')
    run_logged_command(primary_prepare_step.command, primary_paths.host_prepare_log)
    require_exists(primary_paths.host_train_dataset_pkl, 'train_dataset.pkl')
    require_exists(primary_paths.host_val_dataset_pkl, 'val_dataset.pkl')
    require_exists(primary_paths.host_test_dataset_pkl, 'test_dataset.pkl')

    primary_train_step = next(
        step
        for step in commands
        if step.paths.target_name == PRIMARY_TARGET_NAME and step.phase == 'train'
    )
    print(f'Running LineVul train for {primary_train_step.paths.display_name}...')
    run_logged_command(primary_train_step.command, primary_paths.host_train_log)
    require_exists(primary_paths.host_best_model_dir / 'config.json', 'best_model/config.json')
    require_exists(primary_paths.host_training_loss_log, TRAINING_LOSS_LOG_NAME)
    plot_path = write_training_loss_plot(primary_paths)
    print(f'Wrote LineVul training loss plot to {plot_path}')

    primary_test_step = next(
        step
        for step in commands
        if step.paths.target_name == PRIMARY_TARGET_NAME and step.phase == 'test'
    )
    print(f'Running LineVul test for {primary_test_step.paths.display_name}...')
    run_logged_command(primary_test_step.command, primary_paths.host_test_log)
    require_exists(primary_paths.host_test_predictions_csv, 'test_pred_with_code.csv')

    if vuln_patch_paths is not None:
        stage_reused_best_model(primary_paths, vuln_patch_paths)

        vuln_patch_prepare_step = next(
            step
            for step in commands
            if step.paths.target_name == VULN_PATCH_TARGET_NAME and step.phase == 'prepare'
        )
        print(f'Running LineVul prepare for {vuln_patch_prepare_step.paths.display_name}...')
        run_logged_command(vuln_patch_prepare_step.command, vuln_patch_paths.host_prepare_log)
        require_exists(vuln_patch_paths.host_test_dataset_pkl, 'test_dataset.pkl')

        vuln_patch_test_step = next(
            step
            for step in commands
            if step.paths.target_name == VULN_PATCH_TARGET_NAME and step.phase == 'test'
        )
        print(f'Running LineVul test for {vuln_patch_test_step.paths.display_name}...')
        run_logged_command(vuln_patch_test_step.command, vuln_patch_paths.host_test_log)
        require_exists(
            vuln_patch_paths.host_best_model_dir / 'config.json', 'best_model/config.json'
        )
        require_exists(vuln_patch_paths.host_test_predictions_csv, 'test_pred_with_code.csv')

        vuln_patch_raw_test_step = next(
            step
            for step in commands
            if step.paths.target_name == VULN_PATCH_TARGET_NAME and step.phase == 'raw_test'
        )
        print(f'Running LineVul raw-model test for {vuln_patch_raw_test_step.paths.display_name}...')
        run_logged_command(vuln_patch_raw_test_step.command, vuln_patch_paths.host_raw_test_log)
        require_exists(
            vuln_patch_paths.host_raw_test_predictions_csv,
            'raw-model test_pred_with_code.csv',
        )

    print_completion_summary(paths_list)
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
            extended_realvul=args.extended_realvul,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
    )
    try:
        if config.extended_realvul:
            return run_extended_realvul_eval(config)
        return run_linevul_from_pipeline(config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
