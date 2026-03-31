from __future__ import annotations

import csv
import json
import os
import tarfile
from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def _make_vpbench_root(root: Path) -> Path:
    (root / 'downloads' / 'RealVul' / 'datasets').mkdir(parents=True, exist_ok=True)
    experiments_dir = root / 'baseline' / 'RealVul' / 'Experiments' / 'LineVul'
    experiments_dir.mkdir(parents=True, exist_ok=True)
    write_text(experiments_dir / 'line_vul.py', '# stub line_vul entrypoint\n')
    return root


def _write_stage07_csv(
    path: Path,
    *,
    include_processed_func: bool = True,
    include_test_rows: bool = True,
) -> None:
    fieldnames = [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'source_signature_path',
        'commit_hash',
        'dataset_type',
    ]
    if include_processed_func:
        fieldnames.append('processed_func')

    rows = [
        {
            'file_name': '1',
            'unique_id': '1',
            'target': '1',
            'vulnerable_line_numbers': '1',
            'project': 'Juliet',
            'source_signature_path': 'sig-a.json',
            'commit_hash': '',
            'dataset_type': 'train_val',
            'processed_func': 'int bad(void) {\n    return 1;\n}\n',
        },
        {
            'file_name': '2',
            'unique_id': '2',
            'target': '0',
            'vulnerable_line_numbers': '',
            'project': 'Juliet',
            'source_signature_path': 'sig-b.json',
            'commit_hash': '',
            'dataset_type': 'test',
            'processed_func': 'int good(void) {\n    return 0;\n}\n',
        },
    ]
    if not include_test_rows:
        rows = rows[:1]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            payload = dict(row)
            if not include_processed_func:
                payload.pop('processed_func')
            writer.writerow(payload)


def _write_vuln_patch_csv(
    path: Path,
    *,
    include_processed_func: bool = True,
    dataset_type: str = 'test',
) -> None:
    fieldnames = [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'source_signature_path',
        'commit_hash',
        'dataset_type',
    ]
    if include_processed_func:
        fieldnames.append('processed_func')

    rows = [
        {
            'file_name': '10',
            'unique_id': '10',
            'target': '1',
            'vulnerable_line_numbers': '1',
            'project': 'Juliet',
            'source_signature_path': 'sig-vuln.json',
            'commit_hash': '',
            'dataset_type': dataset_type,
            'processed_func': 'int bad_variant(void) {\n    return 1;\n}\n',
        },
        {
            'file_name': '11',
            'unique_id': '11',
            'target': '0',
            'vulnerable_line_numbers': '',
            'project': 'Juliet',
            'source_signature_path': 'sig-patch.json',
            'commit_hash': '',
            'dataset_type': dataset_type,
            'processed_func': 'int good_variant(void) {\n    return 0;\n}\n',
        },
    ]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            payload = dict(row)
            if not include_processed_func:
                payload.pop('processed_func')
            writer.writerow(payload)


def _write_training_loss_log(path: Path, entries: list[tuple[float, float]]) -> None:
    rows = [
        f'TRAIN_EPOCH_LOSS {json.dumps({"epoch": epoch, "loss": loss})}\n'
        for epoch, loss in entries
    ]
    write_text(path, ''.join(rows))


def _write_extended_realvul_csv(path: Path) -> None:
    fieldnames = [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'dataset_type',
        'processed_func',
    ]
    rows = [
        {
            'file_name': '20',
            'unique_id': '20',
            'target': '1',
            'vulnerable_line_numbers': '2',
            'project': 'RealVul',
            'dataset_type': 'test',
            'processed_func': 'int ext_bad(void) {\n    return 1;\n}\n',
        },
        {
            'file_name': '21',
            'unique_id': '21',
            'target': '0',
            'vulnerable_line_numbers': '',
            'project': 'RealVul',
            'dataset_type': 'test',
            'processed_func': 'int ext_good(void) {\n    return 0;\n}\n',
        },
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _make_linevul_model_archive(path: Path) -> Path:
    model_dir = path.parent / 'linevul_release' / 'nested-model'
    write_text(model_dir / 'config.json', '{}\n')
    write_text(model_dir / 'pytorch_model.bin', 'weights\n')
    write_text(model_dir / 'training_args.bin', 'args\n')
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'w:gz') as archive:
        archive.add(model_dir.parent, arcname='linevul_release')
    return path


def test_run_linevul_uses_latest_run_in_dry_run_mode(tmp_path, capsys):
    module = load_module_from_path('test_run_linevul_dry_run', REPO_ROOT / 'tools/run_linevul.py')

    pipeline_root = tmp_path / 'pipeline-runs'
    older_csv = pipeline_root / 'run-older' / '07_dataset_export' / 'Real_Vul_data.csv'
    newer_csv = pipeline_root / 'run-newer' / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(older_csv)
    _write_stage07_csv(newer_csv)
    os.utime(older_csv.parent.parent, (1, 1))
    os.utime(newer_csv.parent.parent, (2, 2))

    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--pipeline-root',
            str(pipeline_root),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 0
    captured = capsys.readouterr()
    assert 'run-newer' in captured.out
    assert '--prepare_dataset' in captured.out
    assert '--train' in captured.out
    assert '--test_predict' in captured.out
    assert 'training_loss.log' in captured.out
    assert 'train_loss_by_epoch.png' in captured.out
    assert not (
        vpbench_root / 'downloads' / 'RealVul' / 'datasets' / 'juliet-playground' / 'run-newer'
    ).exists()


def test_run_linevul_dry_run_includes_optional_vuln_patch_eval(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_dry_run_with_vuln_patch',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    _write_stage07_csv(run_dir / '07_dataset_export' / 'Real_Vul_data.csv')
    _write_vuln_patch_csv(run_dir / '07_dataset_export' / 'vuln_patch' / 'Real_Vul_data.csv')
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 0
    captured = capsys.readouterr()
    assert '[primary/prepare]' in captured.out
    assert '[primary/train]' in captured.out
    assert '[primary/test]' in captured.out
    assert '[vuln_patch/prepare]' in captured.out
    assert '[vuln_patch/test]' in captured.out
    assert '[vuln_patch/raw_test]' in captured.out
    assert 'vuln_patch' in captured.out


def test_stage_downloaded_model_archive_extracts_nested_model_dir(tmp_path):
    module = load_module_from_path(
        'test_run_linevul_stage_downloaded_model_archive',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    archive_path = _make_linevul_model_archive(tmp_path / 'downloads' / 'linevul_best_model.tar.gz')
    target_dir = tmp_path / 'output' / 'after_fine_tuned_model'

    module.stage_downloaded_model_archive(archive_path, target_dir)

    assert target_dir.joinpath('config.json').exists()
    assert target_dir.joinpath('pytorch_model.bin').exists()
    assert target_dir.joinpath('training_args.bin').exists()


def test_run_linevul_extended_realvul_dry_run_prints_download_and_eval_steps(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_extended_realvul_dry_run',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--extended-realvul',
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 0
    captured = capsys.readouterr()
    assert 'Extended RealVul dataset URL' in captured.out
    assert module.EXTENDED_REALVUL_DATASET_URL in captured.out
    assert module.EXTENDED_REALVUL_MODEL_URL in captured.out
    assert '[extended_realvul/extended_eval]' in captured.out
    assert '--extended-realvul' in captured.out
    assert '--baseline_model_name' in captured.out


def test_run_linevul_extended_realvul_downloads_assets_and_runs_single_command(
    tmp_path, monkeypatch
):
    module = load_module_from_path(
        'test_run_linevul_extended_realvul_execute',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    archive_source = _make_linevul_model_archive(tmp_path / 'fixtures' / 'linevul_best_model.tar.gz')
    config = module.normalize_config(
        module.LineVulRunConfig(
            run_dir=None,
            pipeline_root=tmp_path / 'pipeline-runs',
            vpbench_root=vpbench_root,
            container_name='linevul',
            tokenizer_name=module.DEFAULT_TOKENIZER_NAME,
            model_name=module.DEFAULT_MODEL_NAME,
            train_batch_size=module.DEFAULT_TRAIN_BATCH_SIZE,
            eval_batch_size=module.DEFAULT_EVAL_BATCH_SIZE,
            num_train_epochs=module.DEFAULT_NUM_TRAIN_EPOCHS,
            extended_realvul=True,
            overwrite=False,
            dry_run=False,
        )
    )

    paths = module.build_linevul_paths(
        config,
        vpbench_root,
        target_name=module.EXTENDED_REALVUL_TARGET_NAME,
    )

    download_calls: list[tuple[str, Path]] = []
    commands: list[tuple[list[str], Path]] = []

    def fake_download_file(url: str, output_path: Path) -> None:
        download_calls.append((url, output_path))
        if url == module.EXTENDED_REALVUL_DATASET_URL:
            _write_extended_realvul_csv(output_path)
        elif url == module.EXTENDED_REALVUL_MODEL_URL:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(archive_source.read_bytes())
        else:
            raise AssertionError(f'unexpected download url: {url}')

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        write_text(paths.host_test_predictions_csv, 'label,pred\n1,1\n')
        fine_npz = paths.host_output_dir / '20260401-000000-000000_test_last_hidden_state_vectors.npz'
        fine_image, fine_cache = module._artifact_image_and_cache(fine_npz)
        write_text(fine_npz, 'fine npz\n')
        write_text(fine_image, 'fine image\n')
        write_text(fine_cache, '{}\n')
        write_text(paths.host_raw_test_predictions_csv, 'label,pred\n1,0\n')
        raw_npz = (
            paths.host_raw_test_output_dir / '20260401-000001-000000_test_last_hidden_state_vectors.npz'
        )
        raw_image, raw_cache = module._artifact_image_and_cache(raw_npz)
        write_text(raw_npz, 'raw npz\n')
        write_text(raw_image, 'raw image\n')
        write_text(raw_cache, '{}\n')
        combined_image, combined_cache = module.combined_feature_artifact_paths(paths)
        write_text(combined_image, 'combined image\n')
        write_text(combined_cache, '{}\n')

    monkeypatch.setattr(module, 'download_file', fake_download_file)
    monkeypatch.setattr(module, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module, 'run_logged_command', fake_run_logged_command)

    result = run_module_main(
        module,
        [
            '--extended-realvul',
            '--vpbench-root',
            str(vpbench_root),
        ],
    )

    assert result == 0
    assert download_calls == [
        (module.EXTENDED_REALVUL_DATASET_URL, module.extended_realvul_source_csv(config)),
        (module.EXTENDED_REALVUL_MODEL_URL, paths.host_fine_tuned_model_archive),
    ]
    assert len(commands) == 1
    command, log_path = commands[0]
    assert log_path == paths.host_extended_eval_log
    assert '--extended-realvul' in command
    assert '--baseline_model_name' in command
    assert str(paths.container_fine_tuned_model_dir) in command
    assert paths.host_dataset_csv.exists()
    assert paths.host_fine_tuned_model_dir.joinpath('config.json').exists()
    assert paths.host_fine_tuned_model_dir.joinpath('pytorch_model.bin').exists()
    assert paths.host_test_predictions_csv.exists()
    assert paths.host_raw_test_predictions_csv.exists()
    combined_image, combined_cache = module.combined_feature_artifact_paths(paths)
    assert combined_image.exists()
    assert combined_cache.exists()


def test_run_linevul_stages_csv_and_runs_prepare_train_test(tmp_path, monkeypatch):
    module = load_module_from_path('test_run_linevul_execute', REPO_ROOT / 'tools/run_linevul.py')

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_csv = run_dir / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(source_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    host_dataset_dir = (
        vpbench_root / 'downloads' / 'RealVul' / 'datasets' / 'juliet-playground' / 'run-demo'
    )
    host_output_dir = (
        vpbench_root
        / 'baseline'
        / 'RealVul'
        / 'Experiments'
        / 'LineVul'
        / 'juliet-playground'
        / 'run-demo'
    )

    commands: list[tuple[list[str], Path]] = []

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if '--prepare_dataset' in command:
            write_text(host_dataset_dir / 'train_dataset.pkl', 'train\n')
            write_text(host_dataset_dir / 'val_dataset.pkl', 'val\n')
            write_text(host_dataset_dir / 'test_dataset.pkl', 'test\n')
        elif '--train' in command:
            write_text(host_output_dir / 'best_model' / 'config.json', '{}\n')
            _write_training_loss_log(
                host_output_dir / 'training_loss.log',
                [(1.0, 0.8125), (2.0, 0.4375)],
            )
        elif '--test_predict' in command:
            write_text(host_output_dir / 'test_pred_with_code.csv', 'label,pred\n1,1\n')

    monkeypatch.setattr(module, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module, 'run_logged_command', fake_run_logged_command)

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
        ],
    )

    assert result == 0
    assert commands and len(commands) == 3
    assert commands[0][1] == host_output_dir / 'prepare.log'
    assert commands[1][1] == host_output_dir / 'train.log'
    assert commands[2][1] == host_output_dir / 'test.log'

    prepare_command = commands[0][0]
    train_command = commands[1][0]
    test_command = commands[2][0]
    assert '--prepare_dataset' in prepare_command
    assert '--train' in train_command
    assert '--test_predict' in test_command
    assert '--model_name' in train_command
    assert train_command[train_command.index('--model_name') + 1] == 'microsoft/codebert-base'
    assert train_command[train_command.index('--per_device_train_batch_size') + 1] == '8'
    assert train_command[train_command.index('--per_device_eval_batch_size') + 1] == '8'
    assert test_command[test_command.index('--per_device_eval_batch_size') + 1] == '8'

    assert host_dataset_dir.joinpath('Real_Vul_data.csv').exists()
    assert host_dataset_dir.joinpath('Real_Vul_data.csv').read_text(encoding='utf-8') == (
        source_csv.read_text(encoding='utf-8')
    )
    assert host_output_dir.joinpath('best_model', 'config.json').exists()
    assert host_output_dir.joinpath('training_loss.log').exists()
    assert host_output_dir.joinpath('train_loss_by_epoch.png').exists()
    assert host_output_dir.joinpath('test_pred_with_code.csv').exists()


def test_run_linevul_reuses_primary_best_model_for_vuln_patch_eval(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_run_linevul_execute_with_vuln_patch',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_csv = run_dir / '07_dataset_export' / 'Real_Vul_data.csv'
    vuln_patch_csv = run_dir / '07_dataset_export' / 'vuln_patch' / 'Real_Vul_data.csv'
    _write_stage07_csv(source_csv)
    _write_vuln_patch_csv(vuln_patch_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    host_dataset_dir = (
        vpbench_root / 'downloads' / 'RealVul' / 'datasets' / 'juliet-playground' / 'run-demo'
    )
    host_output_dir = (
        vpbench_root
        / 'baseline'
        / 'RealVul'
        / 'Experiments'
        / 'LineVul'
        / 'juliet-playground'
        / 'run-demo'
    )
    vuln_host_dataset_dir = host_dataset_dir / 'vuln_patch'
    vuln_host_output_dir = host_output_dir / 'vuln_patch'

    commands: list[tuple[list[str], Path]] = []

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if log_path == host_output_dir / 'prepare.log':
            write_text(host_dataset_dir / 'train_dataset.pkl', 'train\n')
            write_text(host_dataset_dir / 'val_dataset.pkl', 'val\n')
            write_text(host_dataset_dir / 'test_dataset.pkl', 'test\n')
        elif log_path == host_output_dir / 'train.log':
            write_text(host_output_dir / 'best_model' / 'config.json', '{"model":"primary"}\n')
            _write_training_loss_log(
                host_output_dir / 'training_loss.log',
                [(1.0, 0.91), (2.0, 0.53), (3.0, 0.22)],
            )
        elif log_path == host_output_dir / 'test.log':
            write_text(host_output_dir / 'test_pred_with_code.csv', 'label,pred\n1,1\n')
        elif log_path == vuln_host_output_dir / 'prepare.log':
            assert (vuln_host_output_dir / 'best_model' / 'config.json').exists()
            write_text(vuln_host_dataset_dir / 'test_dataset.pkl', 'test\n')
        elif log_path == vuln_host_output_dir / 'test.log':
            assert (vuln_host_output_dir / 'best_model' / 'config.json').exists()
            write_text(vuln_host_output_dir / 'test_pred_with_code.csv', 'label,pred\n1,0\n')
        elif log_path == vuln_host_output_dir / 'raw_model_test.log':
            write_text(
                vuln_host_output_dir / 'raw_model_eval' / 'test_pred_with_code.csv',
                'label,pred\n1,0\n',
            )
        else:
            raise AssertionError(f'unexpected log path: {log_path}')

    monkeypatch.setattr(module, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module, 'run_logged_command', fake_run_logged_command)

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
        ],
    )

    assert result == 0
    assert len(commands) == 6
    assert [log_path for _, log_path in commands] == [
        host_output_dir / 'prepare.log',
        host_output_dir / 'train.log',
        host_output_dir / 'test.log',
        vuln_host_output_dir / 'prepare.log',
        vuln_host_output_dir / 'test.log',
        vuln_host_output_dir / 'raw_model_test.log',
    ]
    assert sum('--train' in command for command, _ in commands) == 1
    assert '--eval_model_name' in commands[-1][0]
    assert host_dataset_dir.joinpath('Real_Vul_data.csv').read_text(encoding='utf-8') == (
        source_csv.read_text(encoding='utf-8')
    )
    assert vuln_host_dataset_dir.joinpath('Real_Vul_data.csv').read_text(encoding='utf-8') == (
        vuln_patch_csv.read_text(encoding='utf-8')
    )
    assert host_output_dir.joinpath('best_model', 'config.json').exists()
    assert host_output_dir.joinpath('training_loss.log').exists()
    assert host_output_dir.joinpath('train_loss_by_epoch.png').exists()
    assert vuln_host_output_dir.joinpath('best_model', 'config.json').exists()
    assert vuln_host_output_dir.joinpath('test_pred_with_code.csv').exists()
    assert vuln_host_output_dir.joinpath('raw_model_eval', 'test_pred_with_code.csv').exists()
    assert not vuln_host_output_dir.joinpath('training_loss.log').exists()
    assert not vuln_host_output_dir.joinpath('train_loss_by_epoch.png').exists()
    assert not vuln_host_output_dir.joinpath('train.log').exists()
    if vuln_host_output_dir.joinpath('best_model').is_symlink():
        assert not os.path.isabs(os.readlink(vuln_host_output_dir / 'best_model'))


def test_load_epoch_training_losses_ignores_non_matching_lines_and_overwrites_duplicates(tmp_path):
    module = load_module_from_path(
        'test_run_linevul_parse_training_loss_log',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    config = module.normalize_config(
        module.LineVulRunConfig(
            run_dir=run_dir,
            pipeline_root=tmp_path / 'pipeline-runs',
            vpbench_root=vpbench_root,
            container_name='linevul',
            tokenizer_name=module.DEFAULT_TOKENIZER_NAME,
            model_name=module.DEFAULT_MODEL_NAME,
            train_batch_size=module.DEFAULT_TRAIN_BATCH_SIZE,
            eval_batch_size=module.DEFAULT_EVAL_BATCH_SIZE,
            num_train_epochs=module.DEFAULT_NUM_TRAIN_EPOCHS,
            extended_realvul=False,
            overwrite=False,
            dry_run=False,
        )
    )
    paths = module.build_linevul_paths(config, run_dir, target_name=module.PRIMARY_TARGET_NAME)
    write_text(
        paths.host_training_loss_log,
        '\n'.join(
            [
                'ignored',
                'TRAIN_EPOCH_LOSS {"epoch": 2.0, "loss": 0.8}',
                'TRAIN_EPOCH_LOSS {"epoch": 1.0, "loss": 0.9}',
                'TRAIN_EPOCH_LOSS {"epoch": 2.0, "loss": 0.4}',
                '',
            ]
        ),
    )

    assert module._load_epoch_training_losses(paths) == [(1.0, 0.9), (2.0, 0.4)]


def test_run_linevul_fails_when_training_loss_log_is_missing(tmp_path, monkeypatch, capsys):
    module = load_module_from_path(
        'test_run_linevul_missing_training_loss_log',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_csv = run_dir / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(source_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    host_dataset_dir = (
        vpbench_root / 'downloads' / 'RealVul' / 'datasets' / 'juliet-playground' / 'run-demo'
    )
    host_output_dir = (
        vpbench_root
        / 'baseline'
        / 'RealVul'
        / 'Experiments'
        / 'LineVul'
        / 'juliet-playground'
        / 'run-demo'
    )

    def fake_run_logged_command(command, log_path):
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if '--prepare_dataset' in command:
            write_text(host_dataset_dir / 'train_dataset.pkl', 'train\n')
            write_text(host_dataset_dir / 'val_dataset.pkl', 'val\n')
            write_text(host_dataset_dir / 'test_dataset.pkl', 'test\n')
        elif '--train' in command:
            write_text(host_output_dir / 'best_model' / 'config.json', '{}\n')
        elif '--test_predict' in command:
            write_text(host_output_dir / 'test_pred_with_code.csv', 'label,pred\n1,1\n')

    monkeypatch.setattr(module, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module, 'run_logged_command', fake_run_logged_command)

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
        ],
    )

    assert result == 1
    captured = capsys.readouterr()
    assert 'training_loss.log' in captured.err


def test_cleanup_output_targets_falls_back_to_container_rm_on_permission_error(
    tmp_path, monkeypatch
):
    module = load_module_from_path(
        'test_run_linevul_overwrite_cleanup',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    _write_stage07_csv(run_dir / '07_dataset_export' / 'Real_Vul_data.csv')
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    config = module.normalize_config(
        module.LineVulRunConfig(
            run_dir=run_dir,
            pipeline_root=tmp_path / 'pipeline-runs',
            vpbench_root=vpbench_root,
            container_name='linevul',
            tokenizer_name=module.DEFAULT_TOKENIZER_NAME,
            model_name=module.DEFAULT_MODEL_NAME,
            train_batch_size=module.DEFAULT_TRAIN_BATCH_SIZE,
            eval_batch_size=module.DEFAULT_EVAL_BATCH_SIZE,
            num_train_epochs=module.DEFAULT_NUM_TRAIN_EPOCHS,
            extended_realvul=False,
            overwrite=True,
            dry_run=False,
        )
    )
    paths = module.build_linevul_paths(config, run_dir, target_name=module.PRIMARY_TARGET_NAME)
    write_text(paths.host_dataset_dir / 'train_dataset.pkl', 'train\n')
    write_text(paths.host_output_dir / 'train.log', 'log\n')

    removals: list[Path] = []
    original_remove = module._remove_host_output_path

    def fake_remove_host_output_path(path):
        removals.append(path)
        if path == paths.host_output_dir and len(removals) == 1:
            raise PermissionError('permission denied')
        original_remove(path)

    container_commands: list[list[str]] = []

    class FakeResult:
        returncode = 0
        stdout = ''
        stderr = ''

    def fake_subprocess_run(command, **kwargs):
        container_commands.append(list(command))
        if command[:4] == ['docker', 'exec', 'linevul', 'rm']:
            if paths.host_output_dir.exists():
                for child in sorted(paths.host_output_dir.rglob('*'), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                paths.host_output_dir.rmdir()
            if paths.host_dataset_dir.exists():
                for child in sorted(paths.host_dataset_dir.rglob('*'), reverse=True):
                    if child.is_file() or child.is_symlink():
                        child.unlink()
                    elif child.is_dir():
                        child.rmdir()
                paths.host_dataset_dir.rmdir()
        return FakeResult()

    monkeypatch.setattr(module, '_remove_host_output_path', fake_remove_host_output_path)
    monkeypatch.setattr(module.subprocess, 'run', fake_subprocess_run)

    module.cleanup_output_targets([paths], container_name='linevul')

    assert not paths.host_output_dir.exists()
    assert not paths.host_dataset_dir.exists()
    assert container_commands == [
        [
            'docker',
            'exec',
            'linevul',
            'rm',
            '-rf',
            str(paths.container_dataset_dir),
            str(paths.container_output_dir),
        ]
    ]


def test_run_linevul_requires_processed_func_column(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_missing_processed_func',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-bad'
    _write_stage07_csv(
        run_dir / '07_dataset_export' / 'Real_Vul_data.csv',
        include_processed_func=False,
    )
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 2
    captured = capsys.readouterr()
    assert 'missing required columns' in captured.err
    assert 'processed_func' in captured.err


def test_run_linevul_requires_test_split_rows(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_missing_test_rows',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-no-test'
    _write_stage07_csv(
        run_dir / '07_dataset_export' / 'Real_Vul_data.csv',
        include_test_rows=False,
    )
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 2
    captured = capsys.readouterr()
    assert 'must contain both train_val and test rows' in captured.err


def test_run_linevul_requires_test_rows_for_vuln_patch_csv(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_missing_vuln_patch_test_rows',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-no-vuln-patch-test'
    _write_stage07_csv(run_dir / '07_dataset_export' / 'Real_Vul_data.csv')
    _write_vuln_patch_csv(
        run_dir / '07_dataset_export' / 'vuln_patch' / 'Real_Vul_data.csv',
        dataset_type='train_val',
    )
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 2
    captured = capsys.readouterr()
    assert 'must contain test rows' in captured.err


def test_run_linevul_requires_overwrite_for_existing_targets(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_linevul_existing_targets',
        REPO_ROOT / 'tools/run_linevul.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-existing'
    _write_stage07_csv(run_dir / '07_dataset_export' / 'Real_Vul_data.csv')
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    existing_output_dir = (
        vpbench_root
        / 'baseline'
        / 'RealVul'
        / 'Experiments'
        / 'LineVul'
        / 'juliet-playground'
        / 'run-existing'
    )
    existing_output_dir.mkdir(parents=True, exist_ok=True)

    result = run_module_main(
        module,
        [
            '--run-dir',
            str(run_dir),
            '--vpbench-root',
            str(vpbench_root),
            '--dry-run',
        ],
    )

    assert result == 2
    captured = capsys.readouterr()
    assert 'use --overwrite to replace it' in captured.err
