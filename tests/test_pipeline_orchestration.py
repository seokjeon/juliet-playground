from __future__ import annotations

from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_build_full_run_paths_recreates_expected_layout(tmp_path):
    module = load_module_from_path(
        'test_pipeline_paths_layout',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_root = tmp_path / 'juliet' / 'C'
    paths = module._build_full_run_paths(run_dir=run_dir, source_root=source_root)

    assert paths['run_dir'] == run_dir.resolve()
    assert (
        paths['manifest_with_comments_xml']
        == run_dir.resolve() / '01_manifest' / 'manifest_with_comments.xml'
    )
    assert (
        paths['trace_strict_jsonl']
        == run_dir.resolve() / '04_trace_flow' / 'trace_flow_match_strict.jsonl'
    )
    assert paths['trace']['traces_jsonl'] == run_dir.resolve() / '05_trace_ds' / 'traces.jsonl'
    assert paths['trace_slices']['slice_dir'] == run_dir.resolve() / '06_trace_slices' / 'slice'
    assert (
        paths['dataset']['summary_json'] == run_dir.resolve() / '07_dataset_export' / 'summary.json'
    )
    assert paths['patched_dataset']['summary_json'] == (
        run_dir.resolve() / '07_dataset_export' / 'train_patched_counterparts_summary.json'
    )


def test_run_step01_manifest_comment_scan_uses_stage_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step01_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    captured: dict[str, object] = {}

    def fake_scan_manifest_comments(**kwargs):
        captured.update(kwargs)
        write_text(kwargs['output_xml'], '<root />\n')
        return {'output_xml': str(kwargs['output_xml']), 'scanned_files': 1}

    monkeypatch.setattr(
        module._stage01_manifest, 'scan_manifest_comments', fake_scan_manifest_comments
    )

    result = module.run_step01_manifest_comment_scan(
        paths=paths,
        manifest=tmp_path / 'manifest.xml',
        source_root=tmp_path / 'juliet' / 'C',
    )

    assert captured['output_xml'] == paths['manifest_with_comments_xml']
    assert result['output_xml'] == str(paths['manifest_with_comments_xml'])


def test_run_step02a_code_field_inventory_uses_stage_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step02a_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    captured: dict[str, object] = {}

    def fake_extract_unique_code_fields(**kwargs):
        captured.update(kwargs)
        write_text(kwargs['pulse_taint_config_output'], '{}\n')
        return {
            'artifacts': {'pulse_taint_config': str(kwargs['pulse_taint_config_output'])},
            'stats': {},
        }

    monkeypatch.setattr(
        module._stage02a_taint, 'extract_unique_code_fields', fake_extract_unique_code_fields
    )

    result = module.run_step02a_code_field_inventory(
        paths=paths, source_root=tmp_path / 'juliet' / 'C'
    )

    assert captured['input_xml'] == paths['manifest_with_comments_xml']
    assert captured['output_dir'] == paths['taint_dir']
    assert result['artifacts']['pulse_taint_config'] == str(paths['generated_taint_config'])


def test_run_step02b_flow_build_returns_compact_stage_result(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step02b_helpers',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    called: dict[str, object] = {}

    def fake_run_stage02b_flow(**kwargs):
        called.update(kwargs)
        write_text(paths['stage02b']['manifest_with_testcase_flows_xml'], '<root />\n')
        write_text(paths['stage02b']['summary_json'], '{}\n')
        return {
            'artifacts': {
                'manifest_with_testcase_flows_xml': str(
                    paths['stage02b']['manifest_with_testcase_flows_xml']
                ),
                'summary_json': str(paths['stage02b']['summary_json']),
            },
            'stats': {'testcases': 1},
        }

    monkeypatch.setattr(module._stage02b_flow, 'run_stage02b_flow', fake_run_stage02b_flow)

    result = module.run_step02b_flow_build(paths=paths)

    assert called['input_xml'] == paths['manifest_with_comments_xml']
    assert called['output_dir'] == paths['flow_dir']
    assert called['prune_single_child_flows'] is True
    assert result['artifacts']['summary_json'] == str(paths['stage02b']['summary_json'])


def test_run_step02b_flow_build_can_keep_single_child_flows_when_requested(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step02b_helpers_keep_single_child',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    called: dict[str, object] = {}

    def fake_run_stage02b_flow(**kwargs):
        called.update(kwargs)
        write_text(paths['stage02b']['manifest_with_testcase_flows_xml'], '<root />\n')
        write_text(paths['stage02b']['summary_json'], '{}\n')
        return {
            'artifacts': {
                'manifest_with_testcase_flows_xml': str(
                    paths['stage02b']['manifest_with_testcase_flows_xml']
                ),
                'summary_json': str(paths['stage02b']['summary_json']),
            },
            'stats': {'testcases': 1},
        }

    monkeypatch.setattr(module._stage02b_flow, 'run_stage02b_flow', fake_run_stage02b_flow)

    module.run_step02b_flow_build(paths=paths, prune_single_child_flows=False)

    assert called['prune_single_child_flows'] is False


def test_run_step07_dataset_export_uses_primary_dataset_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step07_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    captured: dict[str, object] = {}

    def fake_export_primary_dataset(**kwargs):
        captured.update(kwargs)
        paths['dataset']['normalized_slices_dir'].mkdir(parents=True, exist_ok=True)
        for output_path in [
            paths['dataset']['csv_path'],
            paths['dataset']['split_manifest_json'],
            paths['dataset']['summary_json'],
        ]:
            write_text(output_path, 'ok\n')
        return {
            'artifacts': {
                'csv_path': str(paths['dataset']['csv_path']),
                'normalized_slices_dir': str(paths['dataset']['normalized_slices_dir']),
                'split_manifest_json': str(paths['dataset']['split_manifest_json']),
                'summary_json': str(paths['dataset']['summary_json']),
            },
            'stats': {'counts': {'pairs_total': 1}},
        }

    monkeypatch.setattr(module, 'export_primary_dataset', fake_export_primary_dataset)

    result = module.run_step07_dataset_export(
        paths=paths,
        pair_split_seed=1234,
        pair_train_ratio=0.8,
        dedup_mode='row',
    )

    assert captured['pairs_jsonl'] == paths['pair']['pairs_jsonl']
    assert captured['output_dir'] == paths['dataset']['output_dir']
    assert captured['split_seed'] == 1234
    assert captured['train_ratio'] == 0.8
    assert captured['dedup_mode'] == 'row'
    assert result['artifacts']['split_manifest_json'] == str(
        paths['dataset']['split_manifest_json']
    )


def test_run_step07_trace_dataset_export_uses_trace_dataset_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step07_trace_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    captured: dict[str, object] = {}

    def fake_export_trace_dataset_from_pipeline(**kwargs):
        captured.update(kwargs)
        paths['dataset']['normalized_slices_dir'].mkdir(parents=True, exist_ok=True)
        for output_path in [
            paths['dataset']['csv_path'],
            paths['dataset']['split_manifest_json'],
            paths['dataset']['summary_json'],
        ]:
            write_text(output_path, 'ok\n')
        return {
            'artifacts': {
                'csv_path': str(paths['dataset']['csv_path']),
                'normalized_slices_dir': str(paths['dataset']['normalized_slices_dir']),
                'split_manifest_json': str(paths['dataset']['split_manifest_json']),
                'summary_json': str(paths['dataset']['summary_json']),
            },
            'stats': {'counts': {'traces_total': 1}},
        }

    monkeypatch.setattr(
        module, 'export_trace_dataset_from_pipeline', fake_export_trace_dataset_from_pipeline
    )

    result = module.run_step07_trace_dataset_export(
        paths=paths,
        pair_split_seed=1234,
        pair_train_ratio=0.8,
        dedup_mode='row',
    )

    assert captured['traces_jsonl'] == paths['trace']['traces_jsonl']
    assert captured['slice_dir'] == paths['trace_slices']['slice_dir']
    assert captured['output_dir'] == paths['dataset']['output_dir']
    assert captured['split_seed'] == 1234
    assert captured['train_ratio'] == 0.8
    assert captured['dedup_mode'] == 'row'
    assert result['artifacts']['split_manifest_json'] == str(
        paths['dataset']['split_manifest_json']
    )


def test_run_step07c_vuln_patch_export_uses_vuln_patch_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step07c_vuln_patch_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    write_text(
        paths['dataset']['csv_path'],
        'file_name,unique_id,target,vulnerable_line_numbers,project,source_signature_path,commit_hash,dataset_type,processed_func\n',
    )
    captured: dict[str, object] = {}

    def fake_export_vuln_patch_dataset(**kwargs):
        captured.update(kwargs)
        output_dir = kwargs['output_dir']
        output_dir.mkdir(parents=True, exist_ok=True)
        write_text(output_dir / 'Real_Vul_data.csv', 'ok\n')
        write_text(output_dir / 'summary.json', 'ok\n')
        return {
            'artifacts': {
                'csv_path': str(output_dir / 'Real_Vul_data.csv'),
                'summary_json': str(output_dir / 'summary.json'),
            },
            'stats': {'counts': {'eligible_testcases': 1}},
        }

    monkeypatch.setattr(module, 'export_vuln_patch_dataset', fake_export_vuln_patch_dataset)

    result = module.run_step07c_vuln_patch_export(paths=paths)

    assert captured['source_csv_path'] == paths['dataset']['csv_path']
    assert captured['output_dir'] == paths['dataset']['output_dir'] / 'vuln_patch'
    assert result['artifacts']['summary_json'] == str(
        paths['dataset']['output_dir'] / 'vuln_patch' / 'summary.json'
    )


def test_run_step03_infer_and_signature_uses_stage_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step03_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    captured: dict[str, object] = {}

    def fake_run_infer_and_signature(**kwargs):
        captured.update(kwargs)
        signature_non_empty_dir = paths['signatures_root'] / 'sig' / 'non_empty'
        signature_non_empty_dir.mkdir(parents=True, exist_ok=True)
        write_text(paths['infer_summary_json'], '{}\n')
        return {
            'artifacts': {
                'infer_run_dir': str(paths['infer_results_root'] / 'infer-demo'),
                'signature_output_dir': str(paths['signatures_root'] / 'sig'),
                'signature_non_empty_dir': str(signature_non_empty_dir),
            },
            'stats': {'total_cases': 2},
        }

    monkeypatch.setattr(
        module._stage03_infer, 'run_infer_and_signature', fake_run_infer_and_signature
    )

    result = module.run_step03_infer_and_signature(
        paths=paths,
        selected_taint_config=tmp_path / 'config.json',
        files=['demo.c'],
        all_cwes=False,
        cwes=None,
    )

    assert captured['infer_results_root'] == paths['infer_results_root']
    assert captured['signatures_root'] == paths['signatures_root']
    assert captured['summary_json'] == paths['infer_summary_json']
    assert (
        Path(result['artifacts']['signature_non_empty_dir'])
        == paths['signatures_root'] / 'sig' / 'non_empty'
    )


def test_run_step07b_train_patched_counterparts_uses_stage_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step07b_helper',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    paths = module._build_full_run_paths(
        run_dir=tmp_path / 'run', source_root=tmp_path / 'juliet' / 'C'
    )
    captured: dict[str, object] = {}

    def fake_export_patched_dataset(**kwargs):
        captured.update(kwargs)
        paths['patched_pair']['signatures_dir'].mkdir(parents=True, exist_ok=True)
        paths['patched_slices']['slice_dir'].mkdir(parents=True, exist_ok=True)
        paths['patched_dataset']['normalized_slices_dir'].mkdir(parents=True, exist_ok=True)
        for output_path in [
            paths['patched_pair']['pairs_jsonl'],
            paths['patched_dataset']['csv_path'],
            paths['patched_dataset']['split_manifest_json'],
            paths['patched_dataset']['summary_json'],
        ]:
            write_text(output_path, 'ok\n')
        return {
            'artifacts': {
                'summary_json': str(paths['patched_dataset']['summary_json']),
                'split_manifest_json': str(paths['patched_dataset']['split_manifest_json']),
            },
            'stats': {'counts': {'pairs_total': 1}},
        }

    monkeypatch.setattr(module, 'export_patched_dataset', fake_export_patched_dataset)

    result = module.run_step07b_train_patched_counterparts(paths=paths, dedup_mode='none')

    assert captured['run_dir'] == paths['run_dir']
    assert captured['dedup_mode'] == 'none'
    assert result['artifacts']['split_manifest_json'] == str(
        paths['patched_dataset']['split_manifest_json']
    )
