#!/usr/bin/env python3
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Sequence

from shared import bench_runner as _bench_runner
from shared.artifact_layout import build_dataset_export_paths
from shared.paths import RESULT_DIR

JULIET_PDBERT_NAMESPACE = 'juliet-playground'
EXTENDED_REALVUL_NAMESPACE = 'extended_realvul'
DEFAULT_VPBENCH_ROOT = Path('../VP-Bench')
DEFAULT_CONTAINER_NAME = 'pdbert'
DEFAULT_RAW_MODEL_DIR = Path('../VP-Bench/downloads/PDBERT/data/models/pdbert-base')
DEFAULT_METRIC_AVERAGE = 'binary'
DEFAULT_ANALYZE_BATCH_SIZE = 32
DEFAULT_CUDA_DEVICE = 0
PRIMARY_TARGET_NAME = 'primary'
VULN_PATCH_TARGET_NAME = 'vuln_patch'
EXTENDED_REALVUL_TARGET_NAME = EXTENDED_REALVUL_NAMESPACE
AFTER_FINE_TUNED_TARGET_NAME = 'after_fine_tuned'
BEFORE_FINE_TUNED_TARGET_NAME = 'before_fine_tuned'
EXTENDED_REALVUL_DATASET_NAME = 'all_projects_vul_patch_dataset.csv'
EXTENDED_REALVUL_DATASET_URL = (
    'https://github.com/seokjeon/VP-Bench/releases/download/'
    'VP-Bench_Test_Dataset/all_projects_vul_patch_dataset.csv'
)
EXTENDED_REALVUL_MODEL_URL = (
    'https://github.com/seokjeon/VP-Bench/releases/download/trained_model/pdbert.tar.gz'
)
REQUIRED_COLUMNS = _bench_runner.REQUIRED_COLUMNS
PRIMARY_REQUIRED_DATASET_TYPES = _bench_runner.PRIMARY_REQUIRED_DATASET_TYPES
TEST_ONLY_REQUIRED_DATASET_TYPES = _bench_runner.TEST_ONLY_REQUIRED_DATASET_TYPES
MODEL_ARTIFACT_NAMES = ('config.json', 'model.tar.gz', 'vocabulary', 'archive')
REQUIRED_MODEL_ARTIFACT_NAMES = ('config.json', 'model.tar.gz')
PRETRAINED_MODEL_ARTIFACT_NAMES = ('config.json', 'pytorch_model.bin')
PRETRAINED_TOKENIZER_JSON_ARTIFACT_NAME = 'tokenizer.json'
PRETRAINED_BPE_TOKENIZER_ARTIFACT_NAMES = ('vocab.json', 'merges.txt')
TRAINING_LOSS_PLOT_NAME = 'training_loss_by_epoch.png'
RAW_MODEL_EVAL_DIRNAME = 'raw_model_eval'
RAW_PRETRAINED_SOURCE_DIRNAME = '_raw_pretrained_model'
RAW_MODEL_SOURCE_ARCHIVE = 'archive'
RAW_MODEL_SOURCE_PRETRAINED_BACKBONE = 'pretrained_backbone'
TEST_HIDDEN_STATE_BASENAME = 'test_last_hidden_state_vectors'
CONTAINER_PDBERT_ROOT = Path('/PDBERT')
CONTAINER_DATASET_BASE = CONTAINER_PDBERT_ROOT / 'data' / 'datasets' / 'extrinsic' / 'vul_detect'
CONTAINER_MODEL_BASE = CONTAINER_PDBERT_ROOT / 'data' / 'models' / 'extrinsic' / 'vul_detect'
CONTAINER_PREPARE_SCRIPT = CONTAINER_PDBERT_ROOT / 'prepare_dataset.py'
CONTAINER_DOWNSTREAM_ROOT = CONTAINER_PDBERT_ROOT / 'downstream'
CONTAINER_ANALYZE_SCRIPT = Path('/tmp/pdbert_analyze_prediction.py')
CONTAINER_RAW_BASELINE_SCRIPT = Path('/tmp/pdbert_prepare_raw_baseline.py')
CONTAINER_HOME_DIR = Path('/tmp/pdbert-home')


@dataclass(frozen=True)
class PDBERTRunConfig:
    run_dir: Path | None
    pipeline_root: Path
    vpbench_root: Path
    container_name: str
    raw_model_dir: Path | None
    extended_realvul: bool
    overwrite: bool
    dry_run: bool


@dataclass(frozen=True)
class PDBERTPaths:
    run_dir: Path
    run_name: str
    target_name: str
    display_name: str
    task_name: str
    source_csv: Path
    host_dataset_dir: Path
    host_output_dir: Path
    host_dataset_csv: Path
    host_prepare_log: Path
    host_train_log: Path
    host_test_log: Path
    host_analyze_log: Path
    host_raw_test_log: Path
    host_raw_analyze_log: Path
    host_train_json: Path
    host_validate_json: Path
    host_test_json: Path
    host_runtime_train_config: Path
    host_runtime_test_config: Path
    host_model_archive: Path
    host_model_config_json: Path
    host_eval_result_csv: Path
    host_analysis_json: Path
    host_feature_npz: Path
    host_feature_tsne_image: Path
    host_feature_tsne_cache_json: Path
    host_raw_model_dir: Path
    host_raw_model_archive: Path
    host_raw_model_config_json: Path
    host_raw_eval_result_csv: Path
    host_raw_analysis_json: Path
    host_raw_feature_npz: Path
    host_raw_feature_tsne_image: Path
    host_raw_feature_tsne_cache_json: Path
    host_prepare_script: Path
    host_train_eval_script: Path
    host_analyze_script: Path
    host_raw_baseline_script: Path
    host_train_config_template: Path
    host_test_config_template: Path
    container_dataset_dir: Path
    container_output_dir: Path
    container_raw_model_dir: Path
    container_dataset_csv: Path
    container_runtime_train_config: Path
    container_runtime_test_config: Path


@dataclass(frozen=True)
class PDBERTCommandStep:
    paths: PDBERTPaths
    phase: str
    command: list[str]

    @property
    def label(self) -> str:
        return f'{self.paths.target_name}/{self.phase}'


def _docker_exec_base(container_name: str) -> list[str]:
    return [
        'docker',
        'exec',
        '--user',
        f'{os.getuid()}:{os.getgid()}',
        '--env',
        f'HOME={CONTAINER_HOME_DIR}',
        container_name,
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Run VP-Bench PDBERT prepare/train/test/analyze from a pipeline Stage 07 CSV.'
    )
    parser.add_argument('--run-dir', type=Path, default=None)
    parser.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
    )
    parser.add_argument('--vpbench-root', type=Path, default=DEFAULT_VPBENCH_ROOT)
    parser.add_argument('--container-name', type=str, default=DEFAULT_CONTAINER_NAME)
    parser.add_argument('--raw-model-dir', type=Path, default=DEFAULT_RAW_MODEL_DIR)
    parser.add_argument('--extended-realvul', action='store_true')
    parser.add_argument('--overwrite', action='store_true')
    parser.add_argument('--dry-run', action='store_true')
    return parser.parse_args()


def normalize_config(config: PDBERTRunConfig) -> PDBERTRunConfig:
    return PDBERTRunConfig(
        run_dir=config.run_dir.resolve() if config.run_dir is not None else None,
        pipeline_root=config.pipeline_root.resolve(),
        vpbench_root=config.vpbench_root.resolve(),
        container_name=config.container_name,
        raw_model_dir=config.raw_model_dir.resolve() if config.raw_model_dir is not None else None,
        extended_realvul=config.extended_realvul,
        overwrite=config.overwrite,
        dry_run=config.dry_run,
    )


def validate_config(config: PDBERTRunConfig) -> None:
    if not config.vpbench_root.exists():
        raise ValueError(f'VP-Bench root not found: {config.vpbench_root}')
    if not config.extended_realvul and config.run_dir is None and not config.pipeline_root.exists():
        raise ValueError(f'Pipeline root not found: {config.pipeline_root}')
    if config.raw_model_dir is not None and not config.raw_model_dir.exists():
        raise ValueError(f'Raw PDBERT model dir not found: {config.raw_model_dir}')


def resolve_run_dir(config: PDBERTRunConfig) -> Path:
    return _bench_runner.resolve_run_dir(
        run_dir=config.run_dir,
        pipeline_root=config.pipeline_root,
    )


validate_stage07_csv = _bench_runner.validate_stage07_csv
_existing_output_targets = _bench_runner.existing_output_targets
_remove_host_output_path = _bench_runner.remove_host_output_path
check_container_running = _bench_runner.check_container_running
run_logged_command = _bench_runner.run_logged_command
require_exists = _bench_runner.require_exists


def stage_source_csv(paths: _bench_runner.RunnerPathSpec) -> None:
    _bench_runner.stage_source_csv(paths)
    alias_csv = paths.host_dataset_dir / f'{paths.host_dataset_dir.name}_dataset.csv'
    if alias_csv == paths.host_dataset_csv:
        return
    shutil.copy2(paths.host_dataset_csv, alias_csv)


def _target_output_relative_parts(target_name: str) -> tuple[str, ...]:
    if target_name == PRIMARY_TARGET_NAME:
        return (PRIMARY_TARGET_NAME,)
    if target_name == VULN_PATCH_TARGET_NAME:
        return (VULN_PATCH_TARGET_NAME,)
    raise ValueError(f'Unsupported PDBERT target: {target_name}')


def _target_dataset_relative_parts(target_name: str) -> tuple[str, ...]:
    if target_name == PRIMARY_TARGET_NAME:
        return (PRIMARY_TARGET_NAME, 'vpbench', 'Real_Vul')
    if target_name == VULN_PATCH_TARGET_NAME:
        return (VULN_PATCH_TARGET_NAME, 'realvul_test', 'Real_Vul')
    raise ValueError(f'Unsupported PDBERT target: {target_name}')


def _is_extended_realvul_target(target_name: str) -> bool:
    return target_name == EXTENDED_REALVUL_TARGET_NAME


def _target_requires_training(target_name: str) -> bool:
    return target_name == PRIMARY_TARGET_NAME


def _target_supports_raw_eval(target_name: str) -> bool:
    return target_name in {VULN_PATCH_TARGET_NAME, EXTENDED_REALVUL_TARGET_NAME}


def _target_uses_reused_model(target_name: str) -> bool:
    return target_name == VULN_PATCH_TARGET_NAME


def _target_uses_downloaded_model(target_name: str) -> bool:
    return _is_extended_realvul_target(target_name)


def _required_dataset_types_for_target(target_name: str) -> tuple[str, ...]:
    if _target_requires_training(target_name):
        return PRIMARY_REQUIRED_DATASET_TYPES
    return TEST_ONLY_REQUIRED_DATASET_TYPES


def _feature_artifact_paths(output_dir: Path) -> tuple[Path, Path, Path]:
    base_path = output_dir / TEST_HIDDEN_STATE_BASENAME
    return (
        base_path.with_suffix('.npz'),
        Path(f'{base_path}.jpeg'),
        Path(f'{base_path}-tsne-features.json'),
    )


def _raw_pretrained_source_dir(paths: PDBERTPaths, *, container: bool = False) -> Path:
    base_dir = paths.container_raw_model_dir if container else paths.host_raw_model_dir
    return base_dir / RAW_PRETRAINED_SOURCE_DIRNAME


def raw_model_setup_log_path(paths: PDBERTPaths) -> Path:
    return paths.host_prepare_log.parent / 'raw_model_setup.log'


def detect_raw_model_source_type(raw_model_dir: Path) -> str:
    if all(
        (raw_model_dir / artifact_name).exists() for artifact_name in REQUIRED_MODEL_ARTIFACT_NAMES
    ):
        return RAW_MODEL_SOURCE_ARCHIVE
    if all(
        (raw_model_dir / artifact_name).exists()
        for artifact_name in PRETRAINED_MODEL_ARTIFACT_NAMES
    ):
        return RAW_MODEL_SOURCE_PRETRAINED_BACKBONE
    raise ValueError(
        'Raw PDBERT model dir must be either an AllenNLP archive dir '
        f'with {REQUIRED_MODEL_ARTIFACT_NAMES} or a pretrained backbone dir '
        f'with {PRETRAINED_MODEL_ARTIFACT_NAMES}: {raw_model_dir}'
    )


def validate_raw_model_dir(raw_model_dir: Path) -> str:
    source_type = detect_raw_model_source_type(raw_model_dir)
    if source_type == RAW_MODEL_SOURCE_ARCHIVE:
        require_model_artifacts(raw_model_dir, label='raw model dir')
    else:
        require_pretrained_model_artifacts(raw_model_dir, label='raw model dir')
    return source_type


def build_pdbert_paths(
    config: PDBERTRunConfig,
    run_dir: Path,
    *,
    target_name: str,
) -> PDBERTPaths:
    if _is_extended_realvul_target(target_name):
        source_csv = extended_realvul_source_csv(config)
        run_name = EXTENDED_REALVUL_NAMESPACE
        display_name = EXTENDED_REALVUL_NAMESPACE
        task_name = f'vul_detect/{EXTENDED_REALVUL_NAMESPACE}'
        host_dataset_dir = (
            config.vpbench_root
            / 'downloads'
            / 'PDBERT'
            / 'data'
            / 'datasets'
            / 'extrinsic'
            / 'vul_detect'
            / EXTENDED_REALVUL_NAMESPACE
            / 'realvul_test'
            / 'Real_Vul'
        )
        host_output_dir = _extended_realvul_model_root(config)
        container_dataset_dir = (
            CONTAINER_DATASET_BASE / EXTENDED_REALVUL_NAMESPACE / 'realvul_test' / 'Real_Vul'
        )
        container_output_dir = CONTAINER_MODEL_BASE / EXTENDED_REALVUL_NAMESPACE
        run_dir = source_csv.parent
    elif target_name == PRIMARY_TARGET_NAME:
        dataset_paths = build_dataset_export_paths(run_dir / '07_dataset_export')
        source_csv = dataset_paths['csv_path']
        dataset_relative_parts = _target_dataset_relative_parts(target_name)
        output_relative_parts = _target_output_relative_parts(target_name)
        run_name = run_dir.name
        display_name = (
            run_name if target_name == PRIMARY_TARGET_NAME else f'{run_name}/{target_name}'
        )
        task_name = f'vul_detect/{JULIET_PDBERT_NAMESPACE}/{run_name}/{target_name}'

        base_host_dataset_dir = (
            config.vpbench_root
            / 'downloads'
            / 'PDBERT'
            / 'data'
            / 'datasets'
            / 'extrinsic'
            / 'vul_detect'
            / JULIET_PDBERT_NAMESPACE
            / run_name
        )
        base_host_output_dir = (
            config.vpbench_root
            / 'downloads'
            / 'PDBERT'
            / 'data'
            / 'models'
            / 'extrinsic'
            / 'vul_detect'
            / JULIET_PDBERT_NAMESPACE
            / run_name
        )
        host_dataset_dir = base_host_dataset_dir.joinpath(*dataset_relative_parts)
        host_output_dir = base_host_output_dir.joinpath(*output_relative_parts)
        container_dataset_dir = (
            CONTAINER_DATASET_BASE / JULIET_PDBERT_NAMESPACE / run_name
        ).joinpath(*dataset_relative_parts)
        container_output_dir = (CONTAINER_MODEL_BASE / JULIET_PDBERT_NAMESPACE / run_name).joinpath(
            *output_relative_parts
        )
    elif target_name == VULN_PATCH_TARGET_NAME:
        source_csv = run_dir / '07_dataset_export' / 'vuln_patch' / 'Real_Vul_data.csv'
        dataset_relative_parts = _target_dataset_relative_parts(target_name)
        output_relative_parts = _target_output_relative_parts(target_name)
        run_name = run_dir.name
        display_name = f'{run_name}/{target_name}'
        task_name = f'vul_detect/{JULIET_PDBERT_NAMESPACE}/{run_name}/{target_name}'

        base_host_dataset_dir = (
            config.vpbench_root
            / 'downloads'
            / 'PDBERT'
            / 'data'
            / 'datasets'
            / 'extrinsic'
            / 'vul_detect'
            / JULIET_PDBERT_NAMESPACE
            / run_name
        )
        base_host_output_dir = (
            config.vpbench_root
            / 'downloads'
            / 'PDBERT'
            / 'data'
            / 'models'
            / 'extrinsic'
            / 'vul_detect'
            / JULIET_PDBERT_NAMESPACE
            / run_name
        )
        host_dataset_dir = base_host_dataset_dir.joinpath(*dataset_relative_parts)
        host_output_dir = base_host_output_dir.joinpath(*output_relative_parts)
        container_dataset_dir = (
            CONTAINER_DATASET_BASE / JULIET_PDBERT_NAMESPACE / run_name
        ).joinpath(*dataset_relative_parts)
        container_output_dir = (CONTAINER_MODEL_BASE / JULIET_PDBERT_NAMESPACE / run_name).joinpath(
            *output_relative_parts
        )
    else:
        raise ValueError(f'Unsupported PDBERT target: {target_name}')

    host_pdbert_root = config.vpbench_root / 'baseline' / 'PDBERT'
    host_configs_dir = host_pdbert_root / 'downstream' / 'configs' / 'vul_detect'
    host_experiment_dir = config.vpbench_root / 'experiment' / 'scripts' / 'pdbert'

    host_runtime_dir = host_dataset_dir / '_run_pdbert'
    container_runtime_dir = container_dataset_dir / '_run_pdbert'
    host_raw_model_dir = host_output_dir / RAW_MODEL_EVAL_DIRNAME
    container_raw_model_dir = container_output_dir / RAW_MODEL_EVAL_DIRNAME
    host_feature_npz, host_feature_tsne_image, host_feature_tsne_cache_json = (
        _feature_artifact_paths(host_output_dir)
    )
    (
        host_raw_feature_npz,
        host_raw_feature_tsne_image,
        host_raw_feature_tsne_cache_json,
    ) = _feature_artifact_paths(host_raw_model_dir)

    return PDBERTPaths(
        run_dir=run_dir,
        run_name=run_name,
        target_name=target_name,
        display_name=display_name,
        task_name=task_name,
        source_csv=source_csv,
        host_dataset_dir=host_dataset_dir,
        host_output_dir=host_output_dir,
        host_dataset_csv=host_dataset_dir / 'Real_Vul_data.csv',
        host_prepare_log=host_runtime_dir / 'prepare.log',
        host_train_log=host_runtime_dir / 'train.log',
        host_test_log=host_runtime_dir / 'test.log',
        host_analyze_log=host_runtime_dir / 'analyze.log',
        host_raw_test_log=host_runtime_dir / 'raw_model_test.log',
        host_raw_analyze_log=host_runtime_dir / 'raw_model_analyze.log',
        host_train_json=host_dataset_dir / 'train.json',
        host_validate_json=host_dataset_dir / 'validate.json',
        host_test_json=host_dataset_dir / 'test.json',
        host_runtime_train_config=host_runtime_dir / 'pdbert_train_runtime.jsonnet',
        host_runtime_test_config=host_runtime_dir / 'pdbert_test_runtime.jsonnet',
        host_model_archive=host_output_dir / 'model.tar.gz',
        host_model_config_json=host_output_dir / 'config.json',
        host_eval_result_csv=host_output_dir / 'eval_result.csv',
        host_analysis_json=host_output_dir / 'prediction_analysis.json',
        host_feature_npz=host_feature_npz,
        host_feature_tsne_image=host_feature_tsne_image,
        host_feature_tsne_cache_json=host_feature_tsne_cache_json,
        host_raw_model_dir=host_raw_model_dir,
        host_raw_model_archive=host_raw_model_dir / 'model.tar.gz',
        host_raw_model_config_json=host_raw_model_dir / 'config.json',
        host_raw_eval_result_csv=host_raw_model_dir / 'eval_result.csv',
        host_raw_analysis_json=host_raw_model_dir / 'prediction_analysis.json',
        host_raw_feature_npz=host_raw_feature_npz,
        host_raw_feature_tsne_image=host_raw_feature_tsne_image,
        host_raw_feature_tsne_cache_json=host_raw_feature_tsne_cache_json,
        host_prepare_script=host_pdbert_root / 'prepare_dataset.py',
        host_train_eval_script=host_pdbert_root / 'downstream' / 'train_eval_from_config.py',
        host_analyze_script=host_experiment_dir / 'analyze_prediction.py',
        host_raw_baseline_script=host_experiment_dir / 'prepare_raw_baseline.py',
        host_train_config_template=host_configs_dir / 'pdbert_realvul.jsonnet',
        host_test_config_template=host_configs_dir / 'pdbert_vpbench.jsonnet',
        container_dataset_dir=container_dataset_dir,
        container_output_dir=container_output_dir,
        container_raw_model_dir=container_raw_model_dir,
        container_dataset_csv=container_dataset_dir / 'Real_Vul_data.csv',
        container_runtime_train_config=container_runtime_dir / 'pdbert_train_runtime.jsonnet',
        container_runtime_test_config=container_runtime_dir / 'pdbert_test_runtime.jsonnet',
    )

# extended_realvul 데이터셋 경로
def extended_realvul_source_csv(config: PDBERTRunConfig) -> Path:
    return (
        config.vpbench_root
        / 'downloads'
        / 'PDBERT'
        / 'data'
        / 'datasets'
        / 'extrinsic'
        / 'vul_detect'
        / EXTENDED_REALVUL_NAMESPACE
        / EXTENDED_REALVUL_DATASET_NAME
    )


def download_extended_realvul_dataset(url: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(f'{output_path.name}.tmp')
    try:
        with urllib.request.urlopen(url) as response, temp_path.open('wb') as f:
            shutil.copyfileobj(response, f)
        temp_path.replace(output_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def ensure_extended_realvul_dataset(config: PDBERTRunConfig) -> Path:
    dataset_csv = extended_realvul_source_csv(config)
    if dataset_csv.exists():
        return dataset_csv
    print(f'Downloading Extended RealVul dataset CSV to {dataset_csv}...')
    download_extended_realvul_dataset(EXTENDED_REALVUL_DATASET_URL, dataset_csv)
    return dataset_csv


# extended_realvul 데이터셋 경로
def extended_realvul_source_csv(config: PDBERTRunConfig) -> Path:
    return (
        config.vpbench_root
        / 'downloads'
        / 'PDBERT'
        / 'data'
        / 'datasets'
        / 'extrinsic'
        / 'vul_detect'
        / EXTENDED_REALVUL_NAMESPACE
        / EXTENDED_REALVUL_DATASET_NAME
    )


def download_extended_realvul_dataset(url: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(f'{output_path.name}.tmp')
    try:
        with urllib.request.urlopen(url) as response, temp_path.open('wb') as f:
            shutil.copyfileobj(response, f)
        temp_path.replace(output_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def ensure_extended_realvul_dataset(config: PDBERTRunConfig) -> Path:
    dataset_csv = extended_realvul_source_csv(config)
    if dataset_csv.exists():
        return dataset_csv
    print(f'Downloading Extended RealVul dataset CSV to {dataset_csv}...')
    download_extended_realvul_dataset(EXTENDED_REALVUL_DATASET_URL, dataset_csv)
    return dataset_csv


def validate_paths(
    paths: PDBERTPaths,
    *,
    raw_model_source_type: str | None = None,
) -> None:
    if not _is_extended_realvul_target(paths.target_name) and not paths.run_dir.exists():
        raise ValueError(f'Pipeline run dir not found: {paths.run_dir}')
    if not paths.source_csv.exists():
        raise ValueError(f'Stage 07 dataset CSV not found: {paths.source_csv}')
    required_paths = {
        'PDBERT prepare_dataset.py': paths.host_prepare_script,
        'PDBERT train_eval_from_config.py': paths.host_train_eval_script,
        'PDBERT analyze_prediction.py': paths.host_analyze_script,
        'PDBERT train config template': paths.host_train_config_template,
        'PDBERT test config template': paths.host_test_config_template,
    }
    if (
        _target_supports_raw_eval(paths.target_name)
        and raw_model_source_type == RAW_MODEL_SOURCE_PRETRAINED_BACKBONE
    ):
        required_paths['PDBERT prepare_raw_baseline.py'] = paths.host_raw_baseline_script
    for label, path in required_paths.items():
        if not path.exists():
            raise ValueError(f'{label} not found: {path}')


def download_extended_realvul_model(url: str, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = output_path.with_name(f'{output_path.name}.tmp')
    try:
        with urllib.request.urlopen(url) as response, temp_path.open('wb') as f:
            shutil.copyfileobj(response, f)
        temp_path.replace(output_path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def load_archive_config_json(model_archive: Path) -> dict[str, Any]:
    with tarfile.open(model_archive, 'r:*') as archive:
        config_member = next(
            (
                member
                for member in archive.getmembers()
                if member.isfile() and Path(member.name).name == 'config.json'
            ),
            None,
        )
        if config_member is None:
            raise RuntimeError(f'config.json not found in model archive: {model_archive}')
        extracted = archive.extractfile(config_member)
        if extracted is None:
            raise RuntimeError(f'Failed to extract config.json from model archive: {model_archive}')
        return json.loads(extracted.read().decode('utf-8'))


def rewrite_model_config_for_eval(
    config_dict: dict[str, Any],
    *,
    container_dataset_dir: Path,
    container_output_dir: Path,
) -> dict[str, Any]:
    rewritten = json.loads(json.dumps(config_dict))
    rewritten['train_data_path'] = str(container_dataset_dir / 'train.json')
    rewritten['validation_data_path'] = str(container_dataset_dir / 'validate.json')

    trainer = rewritten.get('trainer')
    if isinstance(trainer, dict):
        callbacks = trainer.get('callbacks')
        if isinstance(callbacks, list):
            for callback in callbacks:
                if isinstance(callback, dict):
                    serialization_dir = str(container_output_dir)
                    if not serialization_dir.endswith('/'):
                        serialization_dir += '/'
                    callback['serialization_dir'] = serialization_dir

    return rewritten


def stage_downloaded_model_artifacts(
    model_url: str,
    model_dir: Path,
    *,
    container_dataset_dir: Path,
    container_output_dir: Path,
) -> None:
    model_dir.mkdir(parents=True, exist_ok=True)
    model_archive = model_dir / 'model.tar.gz'
    model_config_json = model_dir / 'config.json'

    download_extended_realvul_model(model_url, model_archive)
    temp_archive_path = model_archive.with_name(f'{model_archive.name}.normalized')
    with tarfile.open(model_archive, 'r:*') as archive:
        inner_member = next(
            (
                member
                for member in archive.getmembers()
                if member.isfile() and member.name == 'archive/model.tar.gz'
            ),
            None,
        )
        if inner_member is not None:
            extracted = archive.extractfile(inner_member)
            if extracted is None:
                raise RuntimeError(
                    f'Failed to extract archive/model.tar.gz from model archive: {model_archive}'
                )
            with temp_archive_path.open('wb') as f:
                shutil.copyfileobj(extracted, f)
    if temp_archive_path.exists():
        model_archive.unlink()
        temp_archive_path.replace(model_archive)

    config_dict = load_archive_config_json(model_archive)
    rewritten_config = rewrite_model_config_for_eval(
        config_dict,
        container_dataset_dir=container_dataset_dir,
        container_output_dir=container_output_dir,
    )
    model_config_json.write_text(
        json.dumps(rewritten_config, ensure_ascii=False, indent=4) + '\n',
        encoding='utf-8',
    )


def _load_pdbert_eval_only_module():
    module_name = '_run_pdbert_eval_only_runtime'
    current_module = sys.modules[__name__]
    sys.modules['run_pdbert'] = current_module
    existing_module = sys.modules.get(module_name)
    if existing_module is not None:
        existing_module._run_pdbert = current_module
        return existing_module

    module_path = Path(__file__).with_name('run_pdbert_eval_only.py')
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f'Failed to load run_pdbert_eval_only module from {module_path}')
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _extended_realvul_model_root(config: PDBERTRunConfig) -> Path:
    return (
        config.vpbench_root
        / 'downloads'
        / 'PDBERT'
        / 'data'
        / 'models'
        / 'extrinsic'
        / 'vul_detect'
        / EXTENDED_REALVUL_NAMESPACE
    )


def _extended_realvul_eval_only_config(
    config: PDBERTRunConfig,
    *,
    model_dir: Path,
    output_name: str,
):
    eval_only = _load_pdbert_eval_only_module()
    return eval_only.normalize_config(
        eval_only.PDBERTEvalOnlyConfig(
            dataset_csv=extended_realvul_source_csv(config),
            row_manifest=None,
            model_dir=model_dir,
            vpbench_root=config.vpbench_root,
            container_name=config.container_name,
            eval_name=EXTENDED_REALVUL_NAMESPACE,
            storage_path_parts=(EXTENDED_REALVUL_NAMESPACE,),
            output_name=output_name,
            overwrite=config.overwrite,
            dry_run=config.dry_run,
        )
    )


def discover_pdbert_targets(config: PDBERTRunConfig, run_dir: Path) -> list[PDBERTPaths]:
    if config.extended_realvul:
        return [
            build_pdbert_paths(
                config,
                run_dir,
                target_name=EXTENDED_REALVUL_TARGET_NAME,
            )
        ]
    primary_paths = build_pdbert_paths(config, run_dir, target_name=PRIMARY_TARGET_NAME)
    vuln_patch_paths = build_pdbert_paths(config, run_dir, target_name=VULN_PATCH_TARGET_NAME)
    targets = [primary_paths]
    if vuln_patch_paths.source_csv.exists():
        targets.append(vuln_patch_paths)
    return targets


def ensure_output_targets(paths_list: Sequence[PDBERTPaths], *, overwrite: bool) -> None:
    _bench_runner.ensure_output_targets(paths_list, overwrite=overwrite, runner_name='PDBERT')


def _remove_output_targets_via_container(container_name: str, paths: PDBERTPaths) -> None:
    _bench_runner.remove_output_targets_via_container(
        container_name=container_name,
        paths=paths,
        runner_name='PDBERT',
        subprocess_run=subprocess.run,
    )


def cleanup_output_targets(paths_list: Sequence[PDBERTPaths], *, container_name: str) -> None:
    _bench_runner.cleanup_output_targets(
        paths_list,
        remove_host_output_path_fn=_remove_host_output_path,
        remove_container_targets_fn=lambda paths: _remove_output_targets_via_container(
            container_name,
            paths,
        ),
    )


def _rewrite_data_base_path(template_text: str, data_base_path: Path) -> str:
    normalized = str(data_base_path)
    if not normalized.endswith('/'):
        normalized += '/'
    rewritten, count = re.subn(
        r"local data_base_path = '.*?';",
        f"local data_base_path = '{normalized}';",
        template_text,
        count=1,
    )
    if count != 1:
        raise ValueError('Failed to rewrite data_base_path in PDBERT config template')
    return rewritten


def write_runtime_config(template_path: Path, output_path: Path, data_base_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    template_text = template_path.read_text(encoding='utf-8')
    output_path.write_text(
        _rewrite_data_base_path(template_text, data_base_path),
        encoding='utf-8',
    )


def stage_runtime_configs(paths: PDBERTPaths) -> None:
    write_runtime_config(
        paths.host_train_config_template,
        paths.host_runtime_train_config,
        paths.container_dataset_dir,
    )
    write_runtime_config(
        paths.host_test_config_template,
        paths.host_runtime_test_config,
        paths.container_dataset_dir,
    )


def _copy_or_symlink_path(source_path: Path, target_path: Path) -> None:
    if target_path.is_symlink() or target_path.is_file():
        target_path.unlink()
    elif target_path.exists():
        shutil.rmtree(target_path)

    try:
        relative_target = Path(os.path.relpath(source_path, start=target_path.parent))
        target_path.symlink_to(relative_target, target_is_directory=source_path.is_dir())
    except OSError:
        if source_path.is_dir():
            shutil.copytree(source_path, target_path)
        else:
            shutil.copy2(source_path, target_path)


def require_model_artifacts(model_dir: Path, *, label: str) -> None:
    for artifact_name in REQUIRED_MODEL_ARTIFACT_NAMES:
        require_exists(model_dir / artifact_name, f'{label}/{artifact_name}')


def require_pretrained_model_artifacts(model_dir: Path, *, label: str) -> None:
    for artifact_name in PRETRAINED_MODEL_ARTIFACT_NAMES:
        require_exists(model_dir / artifact_name, f'{label}/{artifact_name}')
    tokenizer_json_path = model_dir / PRETRAINED_TOKENIZER_JSON_ARTIFACT_NAME
    has_tokenizer_json = tokenizer_json_path.exists()
    has_bpe_tokenizer_files = all(
        (model_dir / artifact_name).exists()
        for artifact_name in PRETRAINED_BPE_TOKENIZER_ARTIFACT_NAMES
    )
    if not has_tokenizer_json and not has_bpe_tokenizer_files:
        raise ValueError(
            f'{label} must contain {PRETRAINED_TOKENIZER_JSON_ARTIFACT_NAME} or '
            f'{PRETRAINED_BPE_TOKENIZER_ARTIFACT_NAMES}: {model_dir}'
        )


def stage_model_artifacts(source_dir: Path, target_dir: Path) -> None:
    require_model_artifacts(source_dir, label=str(source_dir))
    target_dir.mkdir(parents=True, exist_ok=True)
    for artifact_name in MODEL_ARTIFACT_NAMES:
        source_path = source_dir / artifact_name
        if not source_path.exists() and not source_path.is_symlink():
            continue
        _copy_or_symlink_path(source_path, target_dir / artifact_name)


def stage_reused_model_artifacts(source_paths: PDBERTPaths, target_paths: PDBERTPaths) -> None:
    stage_model_artifacts(source_paths.host_output_dir, target_paths.host_output_dir)


def stage_raw_model_artifacts(raw_model_dir: Path, target_paths: PDBERTPaths) -> None:
    stage_model_artifacts(raw_model_dir, target_paths.host_raw_model_dir)


def stage_pretrained_backbone_artifacts_to_dir(raw_model_dir: Path, target_dir: Path) -> Path:
    require_pretrained_model_artifacts(raw_model_dir, label=str(raw_model_dir))
    target_dir.mkdir(parents=True, exist_ok=True)
    target_source_dir = target_dir / RAW_PRETRAINED_SOURCE_DIRNAME
    target_source_dir.mkdir(parents=True, exist_ok=True)
    for source_path in sorted(raw_model_dir.iterdir(), key=lambda path: path.name):
        _copy_or_symlink_path(source_path, target_source_dir / source_path.name)
    return target_source_dir


def stage_pretrained_backbone_artifacts(raw_model_dir: Path, target_paths: PDBERTPaths) -> None:
    stage_pretrained_backbone_artifacts_to_dir(raw_model_dir, target_paths.host_raw_model_dir)


def training_loss_plot_path(paths: PDBERTPaths) -> Path:
    return paths.host_output_dir / TRAINING_LOSS_PLOT_NAME


def _load_epoch_training_losses(paths: PDBERTPaths) -> list[tuple[int, float]]:
    epoch_losses: list[tuple[int, float]] = []
    for metrics_path in sorted(paths.host_output_dir.glob('metrics_epoch_*.json')):
        match = re.fullmatch(r'metrics_epoch_(\d+)\.json', metrics_path.name)
        if match is None:
            continue
        with metrics_path.open(encoding='utf-8') as f:
            payload = json.load(f)

        if 'training_loss' not in payload:
            raise RuntimeError(f'Expected training_loss in metrics file: {metrics_path}')

        raw_epoch = payload.get('epoch', match.group(1))
        epoch_losses.append((int(raw_epoch) + 1, float(payload['training_loss'])))

    epoch_losses.sort(key=lambda item: item[0])
    if not epoch_losses:
        raise RuntimeError(
            'Expected PDBERT epoch metrics not found after training: '
            f'{paths.host_output_dir / "metrics_epoch_*.json"}'
        )
    return epoch_losses


def write_training_loss_plot(paths: PDBERTPaths) -> Path:
    import matplotlib

    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import scienceplots  # noqa: F401

    epoch_losses = _load_epoch_training_losses(paths)
    plot_path = training_loss_plot_path(paths)
    plot_path.parent.mkdir(parents=True, exist_ok=True)

    with plt.style.context(['science', 'no-latex']):
        fig, ax = plt.subplots(figsize=(8, 5))
        epochs = [epoch for epoch, _ in epoch_losses]
        losses = [loss for _, loss in epoch_losses]
        ax.plot(epochs, losses, marker='o', linewidth=2)
        ax.set_xlabel('Epoch')
        ax.set_ylabel('Training Loss')
        ax.set_title('PDBERT Training Loss by Epoch')
        ax.grid(True, alpha=0.3)
        if len(epochs) <= 20:
            ax.set_xticks(epochs)
        fig.tight_layout()
        fig.savefig(plot_path, dpi=200)
        plt.close(fig)

    return plot_path


def build_prepare_command(config: PDBERTRunConfig, paths: PDBERTPaths) -> list[str]:
    return [
        *_docker_exec_base(config.container_name),
        'python',
        str(CONTAINER_PREPARE_SCRIPT),
        '--path',
        str(paths.container_dataset_dir),
        '--output',
        str(paths.container_dataset_dir),
    ]


def _build_train_eval_inner_command(
    paths: PDBERTPaths,
    *,
    train_only: bool,
    model_dir: Path | None = None,
) -> str:
    config_path = (
        paths.container_runtime_train_config if train_only else paths.container_runtime_test_config
    )
    resolved_model_dir = paths.container_output_dir if model_dir is None else model_dir
    command = [
        'python',
        'train_eval_from_config.py',
        '-config',
        str(config_path),
        '-task_name',
        paths.task_name,
        '-data_path',
        str(paths.container_dataset_dir),
        '-model_dir',
        str(resolved_model_dir),
        '-average',
        DEFAULT_METRIC_AVERAGE,
        '--train-only' if train_only else '--test-only',
    ]
    return (
        'export PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:256 && '
        f'cd {shlex.quote(str(CONTAINER_DOWNSTREAM_ROOT))} && '
        f'{shlex.join(command)}'
    )


def build_train_eval_command(
    config: PDBERTRunConfig,
    paths: PDBERTPaths,
    *,
    phase: str,
) -> list[str]:
    if phase == 'train':
        inner_command = _build_train_eval_inner_command(paths, train_only=True)
    elif phase == 'test':
        inner_command = _build_train_eval_inner_command(paths, train_only=False)
    elif phase == 'raw_test':
        inner_command = _build_train_eval_inner_command(
            paths,
            train_only=False,
            model_dir=paths.container_raw_model_dir,
        )
    else:
        raise ValueError(f'Unsupported PDBERT phase: {phase}')
    return [*_docker_exec_base(config.container_name), 'bash', '-lc', inner_command]


def build_analyze_command(
    config: PDBERTRunConfig,
    paths: PDBERTPaths,
    *,
    model_dir: Path | None = None,
) -> list[str]:
    resolved_model_dir = paths.container_output_dir if model_dir is None else model_dir
    command = [
        'python',
        str(CONTAINER_ANALYZE_SCRIPT),
        '--data-path',
        str(paths.container_dataset_dir),
        '--model-dir',
        str(resolved_model_dir),
        '--batch-size',
        str(DEFAULT_ANALYZE_BATCH_SIZE),
        '--cuda',
        str(DEFAULT_CUDA_DEVICE),
    ]
    inner_command = (
        'export PYTORCH_CUDA_ALLOC_CONF=max_split_size_mb:256 && '
        f'cd {shlex.quote(str(CONTAINER_DOWNSTREAM_ROOT))} && '
        f'{shlex.join(command)}'
    )
    return [*_docker_exec_base(config.container_name), 'bash', '-lc', inner_command]


def build_analyze_setup_command(paths: PDBERTPaths, *, container_name: str) -> list[str]:
    return [
        'docker',
        'cp',
        str(_prepare_analyze_script_for_container(paths)),
        f'{container_name}:{CONTAINER_ANALYZE_SCRIPT}',
    ]


def _prepare_analyze_script_for_container(paths: PDBERTPaths) -> Path:
    source_path = paths.host_analyze_script
    patched_path = paths.host_prepare_log.parent / '_patched_analyze_prediction.py'
    text = source_path.read_text(encoding='utf-8')
    if 'from __future__ import annotations' not in text:
        if text.startswith('#!'):
            first_line, _, remainder = text.partition('\n')
            text = first_line + '\nfrom __future__ import annotations\n' + remainder
        else:
            text = 'from __future__ import annotations\n' + text
    patched_path.parent.mkdir(parents=True, exist_ok=True)
    patched_path.write_text(text, encoding='utf-8')
    return patched_path


def copy_analyze_script_to_container(paths: PDBERTPaths, container_name: str) -> None:
    command = build_analyze_setup_command(paths, container_name=container_name)
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or 'unknown docker cp error'
        raise RuntimeError(
            'Failed to copy PDBERT analyze script to container '
            f'{container_name} for {paths.display_name}: {message}'
        )


def build_raw_baseline_setup_command(paths: PDBERTPaths, *, container_name: str) -> list[str]:
    return [
        'docker',
        'cp',
        str(paths.host_raw_baseline_script),
        f'{container_name}:{CONTAINER_RAW_BASELINE_SCRIPT}',
    ]


def copy_raw_baseline_script_to_container(paths: PDBERTPaths, container_name: str) -> None:
    command = build_raw_baseline_setup_command(paths, container_name=container_name)
    result = subprocess.run(
        command,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or 'unknown docker cp error'
        raise RuntimeError(
            'Failed to copy PDBERT raw baseline script to container '
            f'{container_name} for {paths.display_name}: {message}'
        )


def build_raw_baseline_command_for_locations(
    config: PDBERTRunConfig,
    *,
    container_runtime_test_config: Path,
    container_serialization_dir: Path,
    container_pretrained_model_dir: Path,
) -> list[str]:
    command = [
        'python',
        str(CONTAINER_RAW_BASELINE_SCRIPT),
        '--config',
        str(container_runtime_test_config),
        '--serialization-dir',
        str(container_serialization_dir),
        '--pretrained-model-dir',
        str(container_pretrained_model_dir),
    ]
    inner_command = f'cd {shlex.quote(str(CONTAINER_DOWNSTREAM_ROOT))} && {shlex.join(command)}'
    return [*_docker_exec_base(config.container_name), 'bash', '-lc', inner_command]


def build_raw_baseline_command(
    config: PDBERTRunConfig,
    paths: PDBERTPaths,
) -> list[str]:
    return build_raw_baseline_command_for_locations(
        config,
        container_runtime_test_config=paths.container_runtime_test_config,
        container_serialization_dir=paths.container_raw_model_dir,
        container_pretrained_model_dir=_raw_pretrained_source_dir(paths, container=True),
    )


def build_command_steps(
    config: PDBERTRunConfig,
    paths_list: Sequence[PDBERTPaths],
) -> list[PDBERTCommandStep]:
    commands: list[PDBERTCommandStep] = []
    for paths in paths_list:
        if _target_requires_training(paths.target_name):
            phases = ('prepare', 'train', 'test', 'analyze')
        elif _target_supports_raw_eval(paths.target_name):
            phases = ['prepare', 'test', 'analyze']
            if config.raw_model_dir is not None:
                phases.extend(('raw_test', 'raw_analyze'))
        else:
            raise ValueError(f'Unsupported PDBERT target: {paths.target_name}')

        for phase in phases:
            if phase == 'prepare':
                command = build_prepare_command(config, paths)
            elif phase in {'train', 'test', 'raw_test'}:
                command = build_train_eval_command(config, paths, phase=phase)
            elif phase == 'raw_analyze':
                command = build_analyze_command(
                    config,
                    paths,
                    model_dir=paths.container_raw_model_dir,
                )
            else:
                command = build_analyze_command(config, paths)
            commands.append(PDBERTCommandStep(paths=paths, phase=phase, command=command))
    return commands


def print_planned_commands(
    config: PDBERTRunConfig,
    commands: Sequence[PDBERTCommandStep],
    paths_list: Sequence[PDBERTPaths],
) -> None:
    if not paths_list:
        return
    print(
        '[analyze/setup] '
        + ' '.join(build_analyze_setup_command(paths_list[0], container_name=config.container_name))
    )
    raw_model_source_type = (
        detect_raw_model_source_type(config.raw_model_dir)
        if config.raw_model_dir is not None
        else None
    )
    if paths_list[0].target_name == EXTENDED_REALVUL_TARGET_NAME:
        print(f'Extended RealVul dataset CSV: {paths_list[0].source_csv}')
    else:
        print(f'Pipeline run: {paths_list[0].run_dir}')
    if config.raw_model_dir is not None:
        print(f'Raw model source dir: {config.raw_model_dir}')
        print(f'Raw model source type: {raw_model_source_type}')
    for paths in paths_list:
        print(f'Target [{paths.target_name}] Stage 07 CSV: {paths.source_csv}')
        print(f'Target [{paths.target_name}] Host dataset dir: {paths.host_dataset_dir}')
        print(f'Target [{paths.target_name}] Host output dir: {paths.host_output_dir}')
        if _target_uses_downloaded_model(paths.target_name):
            print(
                f'Target [{paths.target_name}] Fine-tuned model URL: {EXTENDED_REALVUL_MODEL_URL}'
            )
            print(
                '[downloaded-model/setup] '
                f'{EXTENDED_REALVUL_MODEL_URL} -> {paths.host_model_archive}'
            )
        if paths.target_name == PRIMARY_TARGET_NAME:
            print(
                f'Target [{paths.target_name}] Host training loss plot: '
                f'{training_loss_plot_path(paths)}'
            )
        print(f'Target [{paths.target_name}] Host feature export: {paths.host_feature_npz}')
        print(f'Target [{paths.target_name}] Host train config: {paths.host_runtime_train_config}')
        print(f'Target [{paths.target_name}] Host test config: {paths.host_runtime_test_config}')
        print(f'Target [{paths.target_name}] Container dataset dir: {paths.container_dataset_dir}')
        print(f'Target [{paths.target_name}] Container output dir: {paths.container_output_dir}')
        if _target_supports_raw_eval(paths.target_name) and config.raw_model_dir is not None:
            print(f'Target [{paths.target_name}] Host raw model dir: {paths.host_raw_model_dir}')
            print(
                f'Target [{paths.target_name}] Host raw feature export: {paths.host_raw_feature_npz}'
            )
            print(
                f'Target [{paths.target_name}] Container raw model dir: {paths.container_raw_model_dir}'
            )
            if raw_model_source_type == RAW_MODEL_SOURCE_PRETRAINED_BACKBONE:
                print(
                    f'Target [{paths.target_name}] Host raw pretrained source dir: '
                    f'{_raw_pretrained_source_dir(paths)}'
                )
                print(
                    '[raw-baseline/setup] '
                    + ' '.join(
                        build_raw_baseline_setup_command(
                            paths, container_name=config.container_name
                        )
                    )
                )
                print('[raw-baseline/build] ' + ' '.join(build_raw_baseline_command(config, paths)))
    for step in commands:
        print(f'[{step.label}] {" ".join(step.command)}')


def combined_feature_artifact_paths(paths: PDBERTPaths) -> tuple[Path, Path]:
    base_path = paths.host_output_dir / f'combined_{TEST_HIDDEN_STATE_BASENAME}'
    return Path(f'{base_path}.jpeg'), Path(f'{base_path}-tsne-features.json')


def print_completion_summary(
    paths_list: Sequence[PDBERTPaths],
    *,
    raw_model_source_type: str | None = None,
) -> None:
    print('PDBERT run completed.')
    for paths in paths_list:
        print(f'  - [{paths.target_name}] staged_csv: {paths.host_dataset_csv}')
        print(f'  - [{paths.target_name}] prepared_json_dir: {paths.host_dataset_dir}')
        print(f'  - [{paths.target_name}] model_dir: {paths.host_output_dir}')
        if paths.target_name == PRIMARY_TARGET_NAME:
            print(f'  - [{paths.target_name}] training_loss_plot: {training_loss_plot_path(paths)}')
        print(f'  - [{paths.target_name}] eval_result: {paths.host_eval_result_csv}')
        print(f'  - [{paths.target_name}] analysis_json: {paths.host_analysis_json}')
        print(f'  - [{paths.target_name}] feature_npz: {paths.host_feature_npz}')
        print(f'  - [{paths.target_name}] tsne_image: {paths.host_feature_tsne_image}')
        if _target_supports_raw_eval(paths.target_name):
            print(f'  - [{paths.target_name}] raw_model_dir: {paths.host_raw_model_dir}')
            if raw_model_source_type is not None:
                print(f'  - [{paths.target_name}] raw_model_source_type: {raw_model_source_type}')
            print(f'  - [{paths.target_name}] raw_eval_result: {paths.host_raw_eval_result_csv}')
            print(f'  - [{paths.target_name}] raw_analysis_json: {paths.host_raw_analysis_json}')
            print(f'  - [{paths.target_name}] raw_feature_npz: {paths.host_raw_feature_npz}')
            print(f'  - [{paths.target_name}] raw_tsne_image: {paths.host_raw_feature_tsne_image}')
        if _is_extended_realvul_target(paths.target_name):
            combined_image, combined_cache = combined_feature_artifact_paths(paths)
            print(f'  - [{paths.target_name}] combined_tsne_image: {combined_image}')
            print(f'  - [{paths.target_name}] combined_tsne_cache: {combined_cache}')
        print(f'  - [{paths.target_name}] logs: {paths.host_prepare_log.parent}')


def run_extended_realvul_eval(config: PDBERTRunConfig) -> int:
    if not config.dry_run:
        ensure_extended_realvul_dataset(config)
    raw_model_dir = config.raw_model_dir or (
        config.vpbench_root / 'downloads' / 'PDBERT' / 'data' / 'models' / 'pdbert-base'
    )
    return run_pdbert_from_pipeline(replace(config, raw_model_dir=raw_model_dir))


def _find_command_step(
    commands: Sequence[PDBERTCommandStep],
    *,
    target_name: str,
    phase: str,
) -> PDBERTCommandStep:
    return next(
        step for step in commands if step.paths.target_name == target_name and step.phase == phase
    )


def _require_prepare_outputs(paths: PDBERTPaths) -> None:
    if _target_requires_training(paths.target_name):
        require_exists(paths.host_train_json, 'train.json')
        require_exists(paths.host_validate_json, 'validate.json')
    require_exists(paths.host_test_json, 'test.json')


def _require_main_model_outputs(paths: PDBERTPaths) -> None:
    require_exists(paths.host_model_config_json, 'config.json')
    require_exists(paths.host_model_archive, 'model.tar.gz')


def _require_main_analysis_outputs(paths: PDBERTPaths) -> None:
    require_exists(paths.host_eval_result_csv, 'eval_result.csv')
    require_exists(paths.host_analysis_json, 'prediction_analysis.json')
    require_exists(paths.host_feature_npz, 'test_last_hidden_state_vectors.npz')


def _require_raw_model_outputs(paths: PDBERTPaths) -> None:
    require_exists(paths.host_raw_model_config_json, 'raw_model_eval/config.json')
    require_exists(paths.host_raw_model_archive, 'raw_model_eval/model.tar.gz')


def _require_raw_analysis_outputs(paths: PDBERTPaths) -> None:
    require_exists(paths.host_raw_eval_result_csv, 'raw_model_eval/eval_result.csv')
    require_exists(paths.host_raw_analysis_json, 'raw_model_eval/prediction_analysis.json')
    require_exists(paths.host_raw_feature_npz, 'raw_model_eval/test_last_hidden_state_vectors.npz')
    if _is_extended_realvul_target(paths.target_name):
        combined_image, combined_cache = combined_feature_artifact_paths(paths)
        require_exists(combined_image, 'combined_test_last_hidden_state_vectors.jpeg')
        require_exists(
            combined_cache,
            'combined_test_last_hidden_state_vectors-tsne-features.json',
        )


def _prepare_main_model_for_target(
    config: PDBERTRunConfig,
    paths: PDBERTPaths,
    *,
    primary_paths: PDBERTPaths | None,
) -> None:
    if _target_uses_reused_model(paths.target_name):
        if primary_paths is None:
            raise RuntimeError('Primary PDBERT outputs are required for reused-model targets.')
        stage_reused_model_artifacts(primary_paths, paths)
    elif _target_uses_downloaded_model(paths.target_name):
        stage_downloaded_model_artifacts(
            EXTENDED_REALVUL_MODEL_URL,
            paths.host_output_dir,
            container_dataset_dir=paths.container_dataset_dir,
            container_output_dir=paths.container_output_dir,
        )
    else:
        return
    _require_main_model_outputs(paths)


def _prepare_raw_model_for_target(
    config: PDBERTRunConfig,
    paths: PDBERTPaths,
    *,
    raw_model_source_type: str,
) -> None:
    if config.raw_model_dir is None:
        raise RuntimeError('Raw PDBERT model dir is required for raw-model evaluation.')
    if raw_model_source_type == RAW_MODEL_SOURCE_ARCHIVE:
        stage_raw_model_artifacts(config.raw_model_dir, paths)
    elif raw_model_source_type == RAW_MODEL_SOURCE_PRETRAINED_BACKBONE:
        stage_pretrained_backbone_artifacts(config.raw_model_dir, paths)
        copy_raw_baseline_script_to_container(paths, config.container_name)
        print(f'Preparing PDBERT raw baseline from pretrained backbone for {paths.display_name}...')
        run_logged_command(
            build_raw_baseline_command(config, paths),
            raw_model_setup_log_path(paths),
        )
    else:
        raise RuntimeError(f'Unsupported raw model source type: {raw_model_source_type}')
    _require_raw_model_outputs(paths)


def _run_prepare_phase(
    commands: Sequence[PDBERTCommandStep],
    paths: PDBERTPaths,
) -> None:
    step = _find_command_step(commands, target_name=paths.target_name, phase='prepare')
    print(f'Running PDBERT prepare for {paths.display_name}...')
    run_logged_command(step.command, paths.host_prepare_log)
    _require_prepare_outputs(paths)


def _run_train_phase(
    commands: Sequence[PDBERTCommandStep],
    paths: PDBERTPaths,
) -> None:
    step = _find_command_step(commands, target_name=paths.target_name, phase='train')
    print(f'Running PDBERT train for {paths.display_name}...')
    run_logged_command(step.command, paths.host_train_log)
    _require_main_model_outputs(paths)
    plot_path = write_training_loss_plot(paths)
    print(f'Wrote PDBERT training loss plot to {plot_path}')


def _run_test_phase(
    commands: Sequence[PDBERTCommandStep],
    paths: PDBERTPaths,
    *,
    phase: str = 'test',
) -> None:
    step = _find_command_step(commands, target_name=paths.target_name, phase=phase)
    label = 'raw-model test' if phase == 'raw_test' else 'test'
    print(f'Running PDBERT {label} for {paths.display_name}...')
    log_path = paths.host_raw_test_log if phase == 'raw_test' else paths.host_test_log
    run_logged_command(step.command, log_path)
    if phase == 'raw_test':
        _require_raw_model_outputs(paths)
    else:
        _require_main_model_outputs(paths)


def _run_analyze_phase(
    config: PDBERTRunConfig,
    commands: Sequence[PDBERTCommandStep],
    paths: PDBERTPaths,
    *,
    phase: str = 'analyze',
) -> None:
    step = _find_command_step(commands, target_name=paths.target_name, phase=phase)
    copy_analyze_script_to_container(paths, config.container_name)
    label = 'raw-model analyze' if phase == 'raw_analyze' else 'analyze'
    print(f'Running PDBERT {label} for {paths.display_name}...')
    run_logged_command(
        step.command,
        paths.host_raw_analyze_log if phase == 'raw_analyze' else paths.host_analyze_log,
    )
    if phase == 'raw_analyze':
        _require_raw_analysis_outputs(paths)
    else:
        _require_main_analysis_outputs(paths)


def _run_target_pipeline(
    config: PDBERTRunConfig,
    commands: Sequence[PDBERTCommandStep],
    paths: PDBERTPaths,
    *,
    primary_paths: PDBERTPaths | None,
    raw_model_source_type: str | None,
) -> None:
    if not _target_requires_training(paths.target_name):
        _prepare_main_model_for_target(config, paths, primary_paths=primary_paths)

    _run_prepare_phase(commands, paths)

    if _target_requires_training(paths.target_name):
        _run_train_phase(commands, paths)

    _run_test_phase(commands, paths)
    _run_analyze_phase(config, commands, paths)

    if _target_supports_raw_eval(paths.target_name) and raw_model_source_type is not None:
        _prepare_raw_model_for_target(
            config,
            paths,
            raw_model_source_type=raw_model_source_type,
        )
        _run_test_phase(commands, paths, phase='raw_test')
        _run_analyze_phase(config, commands, paths, phase='raw_analyze')


def run_pdbert_from_pipeline(config: PDBERTRunConfig) -> int:
    validate_config(config)
    run_dir = config.vpbench_root if config.extended_realvul else resolve_run_dir(config)
    paths_list = discover_pdbert_targets(config, run_dir)
    primary_paths = next(
        (paths for paths in paths_list if paths.target_name == PRIMARY_TARGET_NAME),
        None,
    )
    vuln_patch_paths = next(
        (paths for paths in paths_list if paths.target_name == VULN_PATCH_TARGET_NAME),
        None,
    )
    raw_model_source_type: str | None = None
    if vuln_patch_paths is not None and config.raw_model_dir is None:
        raise ValueError(
            'Raw PDBERT model dir is required when vuln_patch Stage 07 dataset exists: '
            'use --raw-model-dir'
        )
    if config.raw_model_dir is not None:
        raw_model_source_type = validate_raw_model_dir(config.raw_model_dir)

    for paths in paths_list:
        validate_paths(paths, raw_model_source_type=raw_model_source_type)
        required_dataset_types = _required_dataset_types_for_target(paths.target_name)
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
        stage_runtime_configs(paths)

    for paths in paths_list:
        _run_target_pipeline(
            config,
            commands,
            paths,
            primary_paths=primary_paths,
            raw_model_source_type=raw_model_source_type,
        )

    print_completion_summary(paths_list, raw_model_source_type=raw_model_source_type)
    return 0


def main() -> int:
    args = parse_args()
    config = normalize_config(
        PDBERTRunConfig(
            run_dir=args.run_dir,
            pipeline_root=args.pipeline_root,
            vpbench_root=args.vpbench_root,
            container_name=args.container_name,
            raw_model_dir=args.raw_model_dir,
            extended_realvul=args.extended_realvul,
            overwrite=args.overwrite,
            dry_run=args.dry_run,
        )
    )
    try:
        if config.extended_realvul:
            return run_extended_realvul_eval(config)
        return run_pdbert_from_pipeline(config)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
