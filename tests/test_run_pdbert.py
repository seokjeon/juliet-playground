from __future__ import annotations

import csv
import io
import json
import os
import tarfile
from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_json, write_text


def _make_vpbench_root(root: Path) -> Path:
    baseline_root = root / 'baseline' / 'PDBERT'
    configs_dir = baseline_root / 'downstream' / 'configs' / 'vul_detect'
    experiment_dir = root / 'experiment' / 'scripts' / 'pdbert'

    write_text(baseline_root / 'prepare_dataset.py', '# stub prepare_dataset\n')
    write_text(
        baseline_root / 'downstream' / 'train_eval_from_config.py',
        '# stub train/eval entrypoint\n',
    )
    write_text(
        configs_dir / 'pdbert_realvul.jsonnet',
        "local data_base_path = '/tmp/pdbert-data/';\n{}\n",
    )
    write_text(
        configs_dir / 'pdbert_vpbench.jsonnet',
        "local data_base_path = '/tmp/pdbert-data/';\n{}\n",
    )
    write_text(experiment_dir / 'analyze_prediction.py', '# stub analyze script\n')
    write_text(experiment_dir / 'prepare_raw_baseline.py', '# stub raw baseline script\n')
    return root


def _make_raw_model_archive_dir(root: Path) -> Path:
    write_text(root / 'config.json', '{}\n')
    write_text(root / 'model.tar.gz', 'model\n')
    return root


def _make_pretrained_model_dir(root: Path) -> Path:
    write_text(root / 'config.json', '{}\n')
    write_text(root / 'pytorch_model.bin', 'weights\n')
    write_text(root / 'vocab.json', '{}\n')
    write_text(root / 'merges.txt', '# merges\n')
    return root


def _make_fine_tuned_model_archive(path: Path) -> Path:
    config_payload = {
        'dataset_reader': {'type': 'func_vul_detect_base'},
        'model': {'type': 'vul_func_predictor'},
        'train_data_path': '/old/train.json',
        'validation_data_path': '/old/validate.json',
        'trainer': {
            'callbacks': [
                {
                    'type': 'epoch_print',
                    'serialization_dir': '/old/output/',
                }
            ]
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, 'w:gz') as archive:
        config_bytes = json.dumps(config_payload).encode('utf-8')
        config_info = tarfile.TarInfo('config.json')
        config_info.size = len(config_bytes)
        archive.addfile(config_info, io.BytesIO(config_bytes))

        weights_bytes = b'model\n'
        weights_info = tarfile.TarInfo('weights.th')
        weights_info.size = len(weights_bytes)
        archive.addfile(weights_info, io.BytesIO(weights_bytes))
    return path


def _wrap_model_archive_in_release_tar(inner_archive: Path, release_path: Path) -> Path:
    release_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(release_path, 'w') as archive:
        archive.add(inner_archive, arcname='archive/model.tar.gz')

        config_bytes = b'{}\n'
        config_info = tarfile.TarInfo('archive/config.json')
        config_info.size = len(config_bytes)
        archive.addfile(config_info, io.BytesIO(config_bytes))
    return release_path


def _write_stage07_csv(path: Path, *, include_test_rows: bool = True) -> None:
    fieldnames = [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'source_signature_path',
        'commit_hash',
        'dataset_type',
        'processed_func',
    ]
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
        writer.writerows(rows)


def _write_vuln_patch_csv(path: Path) -> None:
    fieldnames = [
        'file_name',
        'unique_id',
        'target',
        'vulnerable_line_numbers',
        'project',
        'source_signature_path',
        'commit_hash',
        'dataset_type',
        'processed_func',
    ]
    rows = [
        {
            'file_name': '10',
            'unique_id': '10',
            'target': '1',
            'vulnerable_line_numbers': '1',
            'project': 'Juliet',
            'source_signature_path': 'sig-vuln.json',
            'commit_hash': '',
            'dataset_type': 'test',
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
            'dataset_type': 'test',
            'processed_func': 'int good_variant(void) {\n    return 0;\n}\n',
        },
    ]

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def test_run_pdbert_uses_latest_run_in_dry_run_mode(tmp_path, capsys):
    module = load_module_from_path('test_run_pdbert_dry_run', REPO_ROOT / 'tools/run_pdbert.py')

    pipeline_root = tmp_path / 'pipeline-runs'
    older_csv = pipeline_root / 'run-older' / '07_dataset_export' / 'Real_Vul_data.csv'
    newer_csv = pipeline_root / 'run-newer' / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(older_csv)
    _write_stage07_csv(newer_csv)
    _write_vuln_patch_csv(newer_csv.parent / 'vuln_patch' / 'Real_Vul_data.csv')
    os.utime(older_csv.parent.parent, (1, 1))
    os.utime(newer_csv.parent.parent, (2, 2))
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    raw_model_dir = _make_raw_model_archive_dir(tmp_path / 'raw-model')

    result = run_module_main(
        module,
        [
            '--pipeline-root',
            str(pipeline_root),
            '--vpbench-root',
            str(vpbench_root),
            '--raw-model-dir',
            str(raw_model_dir),
            '--dry-run',
        ],
    )

    assert result == 0
    captured = capsys.readouterr()
    assert 'run-newer' in captured.out
    assert '[analyze/setup]' in captured.out
    assert '[primary/prepare]' in captured.out
    assert '[primary/train]' in captured.out
    assert '[primary/test]' in captured.out
    assert '[primary/analyze]' in captured.out
    assert '[vuln_patch/prepare]' in captured.out
    assert '[vuln_patch/test]' in captured.out
    assert '[vuln_patch/analyze]' in captured.out
    assert '[vuln_patch/raw_test]' in captured.out
    assert '[vuln_patch/raw_analyze]' in captured.out


def test_run_pdbert_stages_csv_configs_and_runs_primary_pipeline(tmp_path, monkeypatch):
    module = load_module_from_path('test_run_pdbert_execute', REPO_ROOT / 'tools/run_pdbert.py')

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_csv = run_dir / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(source_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    config = module.normalize_config(
        module.PDBERTRunConfig(
            run_dir=run_dir,
            pipeline_root=tmp_path / 'pipeline-runs',
            vpbench_root=vpbench_root,
            container_name='pdbert',
            raw_model_dir=None,
            extended_realvul=False,
            overwrite=False,
            dry_run=False,
        )
    )
    primary_paths = module.build_pdbert_paths(
        config, run_dir, target_name=module.PRIMARY_TARGET_NAME
    )

    commands: list[tuple[list[str], Path]] = []
    copied_scripts: list[str] = []

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if log_path == primary_paths.host_prepare_log:
            write_text(primary_paths.host_train_json, '{}\n')
            write_text(primary_paths.host_validate_json, '{}\n')
            write_text(primary_paths.host_test_json, '{}\n')
        elif log_path == primary_paths.host_train_log:
            write_text(primary_paths.host_model_config_json, '{}\n')
            write_text(primary_paths.host_model_archive, 'model\n')
            write_json(
                primary_paths.host_output_dir / 'metrics_epoch_0.json',
                {'epoch': 0, 'training_loss': 0.8},
            )
            write_json(
                primary_paths.host_output_dir / 'metrics_epoch_1.json',
                {'epoch': 1, 'training_loss': 0.6},
            )
        elif log_path == primary_paths.host_analyze_log:
            write_text(primary_paths.host_eval_result_csv, 'metric,value\nf1,1.0\n')
            write_text(primary_paths.host_analysis_json, '{}\n')
            write_text(primary_paths.host_feature_npz, 'stub npz\n')

    monkeypatch.setattr(module, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module, 'run_logged_command', fake_run_logged_command)
    monkeypatch.setattr(
        module,
        'copy_analyze_script_to_container',
        lambda paths, container_name: copied_scripts.append(
            f'{paths.display_name}:{container_name}'
        ),
    )

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
    assert [log_path for _, log_path in commands] == [
        primary_paths.host_prepare_log,
        primary_paths.host_train_log,
        primary_paths.host_test_log,
        primary_paths.host_analyze_log,
    ]
    assert '--train-only' in commands[1][0][-1]
    assert '--test-only' in commands[2][0][-1]
    assert copied_scripts == ['run-demo:pdbert']
    assert primary_paths.host_dataset_csv.read_text(encoding='utf-8') == source_csv.read_text(
        encoding='utf-8'
    )
    assert primary_paths.host_runtime_train_config.exists()
    assert primary_paths.host_runtime_test_config.exists()
    assert str(
        primary_paths.container_dataset_dir
    ) + '/' in primary_paths.host_runtime_train_config.read_text(encoding='utf-8')
    assert str(
        primary_paths.container_dataset_dir
    ) + '/' in primary_paths.host_runtime_test_config.read_text(encoding='utf-8')
    assert primary_paths.host_eval_result_csv.exists()
    assert primary_paths.host_analysis_json.exists()
    training_loss_plot = module.training_loss_plot_path(primary_paths)
    assert training_loss_plot.exists()
    assert training_loss_plot.read_bytes().startswith(b'\x89PNG\r\n\x1a\n')


def test_run_pdbert_prepares_python38_compatible_analyze_script(tmp_path):
    module = load_module_from_path(
        'test_run_pdbert_analyze_patch', REPO_ROOT / 'tools/run_pdbert.py'
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_csv = run_dir / '07_dataset_export' / 'Real_Vul_data.csv'
    _write_stage07_csv(source_csv)
    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')

    config = module.normalize_config(
        module.PDBERTRunConfig(
            run_dir=run_dir,
            pipeline_root=tmp_path / 'pipeline-runs',
            vpbench_root=vpbench_root,
            container_name='pdbert',
            raw_model_dir=None,
            extended_realvul=False,
            overwrite=False,
            dry_run=False,
        )
    )
    primary_paths = module.build_pdbert_paths(
        config, run_dir, target_name=module.PRIMARY_TARGET_NAME
    )

    patched_script = module._prepare_analyze_script_for_container(primary_paths)

    assert patched_script.exists()
    assert 'from __future__ import annotations' in patched_script.read_text(encoding='utf-8')


def test_run_pdbert_extended_realvul_dry_run_prints_external_eval_steps(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_pdbert_extended_realvul_dry_run',
        REPO_ROOT / 'tools/run_pdbert.py',
    )

    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    dataset_csv = (
        vpbench_root
        / 'downloads'
        / 'PDBERT'
        / 'data'
        / 'datasets'
        / 'extrinsic'
        / 'vul_detect'
        / 'extended_realvul'
        / 'all_projects_vul_patch_dataset.csv'
    )
    _write_vuln_patch_csv(dataset_csv)
    _make_pretrained_model_dir(
        vpbench_root / 'downloads' / 'PDBERT' / 'data' / 'models' / 'pdbert-base'
    )

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
    assert 'Extended RealVul dataset CSV' in captured.out
    assert module.EXTENDED_REALVUL_MODEL_URL in captured.out
    assert '[downloaded-model/setup]' in captured.out
    assert '[raw-baseline/setup]' in captured.out
    assert '[raw-baseline/build]' in captured.out
    assert '[extended_realvul/prepare]' in captured.out
    assert '[extended_realvul/test]' in captured.out
    assert '[extended_realvul/analyze]' in captured.out
    assert '[extended_realvul/raw_test]' in captured.out
    assert '[extended_realvul/raw_analyze]' in captured.out


def test_run_pdbert_extended_realvul_downloads_dataset_when_missing(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_run_pdbert_extended_realvul_download_dataset',
        REPO_ROOT / 'tools/run_pdbert.py',
    )

    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    _make_pretrained_model_dir(
        vpbench_root / 'downloads' / 'PDBERT' / 'data' / 'models' / 'pdbert-base'
    )
    dataset_csv = (
        vpbench_root
        / 'downloads'
        / 'PDBERT'
        / 'data'
        / 'datasets'
        / 'extrinsic'
        / 'vul_detect'
        / 'extended_realvul'
        / 'all_projects_vul_patch_dataset.csv'
    )

    download_calls: list[tuple[str, Path]] = []
    forwarded_configs: list[module.PDBERTRunConfig] = []

    def fake_download_dataset(url: str, output_path: Path) -> None:
        download_calls.append((url, output_path))
        _write_vuln_patch_csv(output_path)

    monkeypatch.setattr(
        module,
        'download_extended_realvul_dataset',
        fake_download_dataset,
    )
    monkeypatch.setattr(
        module,
        'run_pdbert_from_pipeline',
        lambda config: forwarded_configs.append(config) or 0,
    )

    result = run_module_main(
        module,
        [
            '--extended-realvul',
            '--vpbench-root',
            str(vpbench_root),
        ],
    )

    assert result == 0
    assert download_calls == [(module.EXTENDED_REALVUL_DATASET_URL, dataset_csv)]
    assert dataset_csv.exists()
    assert len(forwarded_configs) == 1
    assert forwarded_configs[0].vpbench_root == vpbench_root.resolve()
    assert forwarded_configs[0].pipeline_root == (
        module.Path(module.RESULT_DIR) / 'pipeline-runs'
    ).resolve()
    assert forwarded_configs[0].raw_model_dir == module.DEFAULT_RAW_MODEL_DIR.resolve()
    assert forwarded_configs[0].extended_realvul is True
    assert forwarded_configs[0].overwrite is False
    assert forwarded_configs[0].dry_run is False


def test_run_pdbert_extended_realvul_executes_after_and_before_eval(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_run_pdbert_extended_realvul_execute',
        REPO_ROOT / 'tools/run_pdbert.py',
    )

    vpbench_root = _make_vpbench_root(tmp_path / 'VP-Bench')
    dataset_csv = (
        vpbench_root
        / 'downloads'
        / 'PDBERT'
        / 'data'
        / 'datasets'
        / 'extrinsic'
        / 'vul_detect'
        / 'extended_realvul'
        / 'all_projects_vul_patch_dataset.csv'
    )
    _write_vuln_patch_csv(dataset_csv)
    pretrained_model_dir = _make_pretrained_model_dir(
        vpbench_root / 'downloads' / 'PDBERT' / 'data' / 'models' / 'pdbert-base'
    )
    inner_fine_tuned_archive = _make_fine_tuned_model_archive(
        tmp_path / 'downloads' / 'inner-pdbert-model.tar.gz'
    )
    fine_tuned_archive = _wrap_model_archive_in_release_tar(
        inner_fine_tuned_archive,
        tmp_path / 'downloads' / 'pdbert-release.tar',
    )

    config = module.normalize_config(
        module.PDBERTRunConfig(
            run_dir=None,
            pipeline_root=tmp_path / 'pipeline-runs',
            vpbench_root=vpbench_root,
            container_name='pdbert',
            raw_model_dir=None,
            extended_realvul=True,
            overwrite=False,
            dry_run=False,
        )
    )
    extended_paths = module.build_pdbert_paths(
        config,
        vpbench_root,
        target_name=module.EXTENDED_REALVUL_TARGET_NAME,
    )
    model_root = extended_paths.host_output_dir
    raw_setup_log = module.raw_model_setup_log_path(extended_paths)
    raw_model_eval_dir = extended_paths.host_raw_model_dir
    combined_tsne_image, combined_tsne_cache = module.combined_feature_artifact_paths(
        extended_paths
    )

    commands: list[tuple[list[str], Path]] = []
    copied_analyze_scripts: list[str] = []
    copied_raw_scripts: list[str] = []

    def fake_download_model(url: str, output_path: Path) -> None:
        assert url == module.EXTENDED_REALVUL_MODEL_URL
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(fine_tuned_archive.read_bytes())

    def fake_run_logged_command(command, log_path):
        commands.append((list(command), log_path))
        write_text(log_path, '$ ' + ' '.join(command) + '\n')
        if log_path == extended_paths.host_prepare_log:
            write_text(extended_paths.host_dataset_dir / 'test.json', '{}\n')
        elif log_path == extended_paths.host_analyze_log:
            write_text(extended_paths.host_eval_result_csv, 'metric,value\nf1,0.9\n')
            write_text(extended_paths.host_analysis_json, '{}\n')
            write_text(extended_paths.host_feature_npz, 'after npz\n')
        elif log_path == raw_setup_log:
            write_text(raw_model_eval_dir / 'config.json', '{}\n')
            write_text(raw_model_eval_dir / 'model.tar.gz', 'before-model\n')
        elif log_path == extended_paths.host_raw_test_log:
            write_text(raw_model_eval_dir / 'eval_result.csv', 'metric,value\nf1,0.7\n')
        elif log_path == extended_paths.host_raw_analyze_log:
            write_text(raw_model_eval_dir / 'prediction_analysis.json', '{}\n')
            write_text(
                raw_model_eval_dir / 'test_last_hidden_state_vectors.npz',
                'combined raw npz\n',
            )
            write_text(combined_tsne_image, 'combined image\n')
            write_text(combined_tsne_cache, '{}\n')

    monkeypatch.setattr(module, 'check_container_running', lambda _container_name: None)
    monkeypatch.setattr(module, 'download_extended_realvul_model', fake_download_model)
    monkeypatch.setattr(module, 'run_logged_command', fake_run_logged_command)
    monkeypatch.setattr(
        module,
        'copy_analyze_script_to_container',
        lambda paths, container_name: copied_analyze_scripts.append(
            f'{paths.display_name}:{container_name}'
        ),
    )
    monkeypatch.setattr(
        module,
        'copy_raw_baseline_script_to_container',
        lambda paths, container_name: copied_raw_scripts.append(
            f'{paths.display_name}:{container_name}'
        ),
    )

    result = run_module_main(
        module,
        [
            '--extended-realvul',
            '--vpbench-root',
            str(vpbench_root),
        ],
    )

    assert result == 0
    assert [log_path for _, log_path in commands] == [
        extended_paths.host_prepare_log,
        extended_paths.host_test_log,
        extended_paths.host_analyze_log,
        raw_setup_log,
        extended_paths.host_raw_test_log,
        extended_paths.host_raw_analyze_log,
    ]
    assert copied_analyze_scripts == [
        'extended_realvul:pdbert',
        'extended_realvul:pdbert',
    ]
    assert copied_raw_scripts == ['extended_realvul:pdbert']
    assert extended_paths.host_dataset_csv.read_text(encoding='utf-8') == dataset_csv.read_text(
        encoding='utf-8'
    )
    assert (
        raw_model_eval_dir / module.RAW_PRETRAINED_SOURCE_DIRNAME / 'config.json'
    ).exists()
    model_archive = extended_paths.host_output_dir / 'model.tar.gz'
    model_config = extended_paths.host_output_dir / 'config.json'

    assert model_archive.exists()
    assert model_config.exists()
    model_config_payload = json.loads(model_config.read_text(encoding='utf-8'))
    assert model_config_payload['train_data_path'] == str(
        extended_paths.container_dataset_dir / 'train.json'
    )
    assert model_config_payload['validation_data_path'] == str(
        extended_paths.container_dataset_dir / 'validate.json'
    )
    assert model_config_payload['trainer']['callbacks'][0]['serialization_dir'] == str(
        extended_paths.container_output_dir
    ) + '/'
    assert extended_paths.host_eval_result_csv.exists()
    assert extended_paths.host_analysis_json.exists()
    assert extended_paths.host_feature_npz.exists()
    assert (raw_model_eval_dir / 'model.tar.gz').exists()
    assert (raw_model_eval_dir / 'config.json').exists()
    assert (raw_model_eval_dir / 'eval_result.csv').exists()
    assert (raw_model_eval_dir / 'prediction_analysis.json').exists()
    assert (raw_model_eval_dir / 'test_last_hidden_state_vectors.npz').exists()
    assert combined_tsne_image.exists()
    assert combined_tsne_cache.exists()
    assert not (model_root / '_after_fine_tuned_model').exists()
    assert not (model_root / '_before_fine_tuned_model').exists()
    assert not (model_root / '_before_fine_tuned_runtime').exists()
    assert not (model_root / 'before_fine_tuned').exists()
    assert pretrained_model_dir.exists()
