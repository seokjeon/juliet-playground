from __future__ import annotations

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def test_full_subcommand_runs_internal_orchestration(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_pipeline_full', REPO_ROOT / 'tools/run_pipeline.py')

    manifest = tmp_path / 'manifest.xml'
    source_root = tmp_path / 'juliet' / 'C'
    committed_taint_config = tmp_path / 'pulse-taint-config.json'
    pipeline_root = tmp_path / 'pipeline-runs'
    source_root.mkdir(parents=True)
    write_text(manifest, '<manifest />\n')
    write_text(committed_taint_config, '{}\n')

    called: list[str] = []

    def fake_scan_manifest_comments(**kwargs):
        called.append('01_manifest_comment_scan')
        write_text(kwargs['output_xml'], '<root />\n')
        return {'output_xml': str(kwargs['output_xml'])}

    def fake_extract_unique_code_fields(**kwargs):
        called.append('02a_code_field_inventory')
        write_text(kwargs['pulse_taint_config_output'], '{}\n')
        return {
            'artifacts': {'pulse_taint_config': str(kwargs['pulse_taint_config_output'])},
            'stats': {},
        }

    def fake_run_stage02b_flow(**kwargs):
        called.append('02b_testcase_flow_build')
        write_text(kwargs['output_dir'] / 'manifest_with_testcase_flows.xml', '<root />\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {
            'artifacts': {'summary_json': str(kwargs['output_dir'] / 'summary.json')},
            'stats': {},
        }

    def fake_run_infer_and_signature(**kwargs):
        called.append('03_infer_and_signature')
        signature_non_empty_dir = (
            kwargs['signatures_root'] / 'infer-demo' / 'signature-demo' / 'non_empty'
        )
        signature_non_empty_dir.mkdir(parents=True, exist_ok=True)
        write_text(kwargs['summary_json'], '{}\n')
        return {
            'artifacts': {
                'signature_output_dir': str(signature_non_empty_dir.parent),
                'signature_non_empty_dir': str(signature_non_empty_dir),
            },
            'stats': {'total_cases': 1},
        }

    def fake_filter_traces_by_flow(**kwargs):
        called.append('04_trace_flow_filter')
        write_text(kwargs['output_dir'] / 'trace_flow_match_strict.jsonl', '{}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {
            'artifacts': {
                'trace_flow_match_strict_jsonl': str(
                    kwargs['output_dir'] / 'trace_flow_match_strict.jsonl'
                )
            },
            'stats': {},
        }

    def fake_build_paired_trace_dataset(**kwargs):
        called.append('05_pair_trace_dataset')
        write_text(kwargs['output_dir'] / 'pairs.jsonl', '{}\n')
        write_text(kwargs['output_dir'] / 'leftover_counterparts.jsonl', '{}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        (kwargs['output_dir'] / 'paired_signatures').mkdir(parents=True, exist_ok=True)
        return {
            'artifacts': {'pairs_jsonl': str(kwargs['output_dir'] / 'pairs.jsonl')},
            'stats': {},
        }

    def fake_generate_slices(**kwargs):
        called.append('06_generate_slices')
        (kwargs['output_dir'] / 'slice').mkdir(parents=True, exist_ok=True)
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {'artifacts': {'slice_dir': str(kwargs['output_dir'] / 'slice')}, 'stats': {}}

    def fake_export_primary_dataset(**kwargs):
        called.append('07_dataset_export')
        (kwargs['output_dir'] / 'normalized_slices').mkdir(parents=True, exist_ok=True)
        for output_path in [
            kwargs['output_dir'] / 'Real_Vul_data.csv',
            kwargs['output_dir'] / 'split_manifest.json',
            kwargs['output_dir'] / 'summary.json',
        ]:
            write_text(output_path, 'ok\n')
        return {
            'artifacts': {'summary_json': str(kwargs['output_dir'] / 'summary.json')},
            'stats': {},
        }

    def fake_export_patched_dataset(**kwargs):
        called.append('07b_train_patched_counterparts_export')
        run_dir = kwargs['run_dir']
        pair_dir = run_dir / '05_pair_trace_ds'
        slice_dir = run_dir / '06_slices' / 'train_patched_counterparts' / 'slice'
        dataset_dir = run_dir / '07_dataset_export'
        (pair_dir / 'train_patched_counterparts_signatures').mkdir(parents=True, exist_ok=True)
        (slice_dir).mkdir(parents=True, exist_ok=True)
        (dataset_dir / 'train_patched_counterparts_slices').mkdir(parents=True, exist_ok=True)
        for output_path in [
            pair_dir / 'train_patched_counterparts_pairs.jsonl',
            dataset_dir / 'train_patched_counterparts.csv',
            dataset_dir / 'train_patched_counterparts_split_manifest.json',
            dataset_dir / 'train_patched_counterparts_summary.json',
        ]:
            write_text(output_path, 'ok\n')
        return {
            'artifacts': {
                'summary_json': str(dataset_dir / 'train_patched_counterparts_summary.json')
            },
            'stats': {},
        }

    monkeypatch.setattr(
        module._stage01_manifest, 'scan_manifest_comments', fake_scan_manifest_comments
    )
    monkeypatch.setattr(
        module._stage02a_taint, 'extract_unique_code_fields', fake_extract_unique_code_fields
    )
    monkeypatch.setattr(module._stage02b_flow, 'run_stage02b_flow', fake_run_stage02b_flow)
    monkeypatch.setattr(
        module._stage03_infer, 'run_infer_and_signature', fake_run_infer_and_signature
    )
    monkeypatch.setattr(
        module._stage04_trace_flow, 'filter_traces_by_flow', fake_filter_traces_by_flow
    )
    monkeypatch.setattr(
        module._stage05_pair_trace, 'build_paired_trace_dataset', fake_build_paired_trace_dataset
    )
    monkeypatch.setattr(module._stage06_slices, 'generate_slices', fake_generate_slices)
    monkeypatch.setattr(module, 'export_primary_dataset', fake_export_primary_dataset)
    monkeypatch.setattr(module, 'export_patched_dataset', fake_export_patched_dataset)

    result = run_module_main(
        module,
        [
            'full',
            '121',
            '--manifest',
            str(manifest),
            '--source-root',
            str(source_root),
            '--pipeline-root',
            str(pipeline_root),
            '--run-id',
            'run-test',
            '--committed-taint-config',
            str(committed_taint_config),
        ],
    )

    assert result == 0
    assert called == [
        '01_manifest_comment_scan',
        '02a_code_field_inventory',
        '02b_testcase_flow_build',
        '03_infer_and_signature',
        '04_trace_flow_filter',
        '05_pair_trace_dataset',
        '06_generate_slices',
        '07_dataset_export',
        '07b_train_patched_counterparts_export',
    ]

    run_dir = pipeline_root / 'run-test'
    assert not (run_dir / 'run_summary.json').exists()
    assert not (run_dir / 'logs').exists()
    assert (run_dir / '05_pair_trace_ds' / 'leftover_counterparts.jsonl').exists()
    assert (run_dir / '07_dataset_export' / 'split_manifest.json').exists()
    assert (run_dir / '07_dataset_export' / 'summary.json').exists()
    assert (run_dir / '07_dataset_export' / 'train_patched_counterparts_summary.json').exists()
    assert (run_dir / '04_trace_flow' / 'summary.json').exists()
    assert (run_dir / '06_slices' / 'summary.json').exists()


def test_full_subcommand_disable_pair_runs_trace_first_orchestration(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_run_pipeline_full_disable_pair',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    manifest = tmp_path / 'manifest.xml'
    source_root = tmp_path / 'juliet' / 'C'
    committed_taint_config = tmp_path / 'pulse-taint-config.json'
    pipeline_root = tmp_path / 'pipeline-runs'
    source_root.mkdir(parents=True)
    write_text(manifest, '<manifest />\n')
    write_text(committed_taint_config, '{}\n')

    called: list[str] = []

    def fake_scan_manifest_comments(**kwargs):
        called.append('01_manifest_comment_scan')
        write_text(kwargs['output_xml'], '<root />\n')
        return {'output_xml': str(kwargs['output_xml'])}

    def fake_extract_unique_code_fields(**kwargs):
        called.append('02a_code_field_inventory')
        write_text(kwargs['pulse_taint_config_output'], '{}\n')
        return {
            'artifacts': {'pulse_taint_config': str(kwargs['pulse_taint_config_output'])},
            'stats': {},
        }

    def fake_run_stage02b_flow(**kwargs):
        called.append('02b_testcase_flow_build')
        write_text(kwargs['output_dir'] / 'manifest_with_testcase_flows.xml', '<root />\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {
            'artifacts': {'summary_json': str(kwargs['output_dir'] / 'summary.json')},
            'stats': {},
        }

    def fake_run_infer_and_signature(**kwargs):
        called.append('03_infer_and_signature')
        signature_non_empty_dir = (
            kwargs['signatures_root'] / 'infer-demo' / 'signature-demo' / 'non_empty'
        )
        signature_non_empty_dir.mkdir(parents=True, exist_ok=True)
        write_text(kwargs['summary_json'], '{}\n')
        return {
            'artifacts': {
                'signature_output_dir': str(signature_non_empty_dir.parent),
                'signature_non_empty_dir': str(signature_non_empty_dir),
            },
            'stats': {'total_cases': 1},
        }

    def fake_filter_traces_by_flow(**kwargs):
        called.append('04_trace_flow_filter')
        write_text(kwargs['output_dir'] / 'trace_flow_match_strict.jsonl', '{}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {
            'artifacts': {
                'trace_flow_match_strict_jsonl': str(
                    kwargs['output_dir'] / 'trace_flow_match_strict.jsonl'
                )
            },
            'stats': {},
        }

    def fake_build_trace_dataset(**kwargs):
        called.append('05_trace_dataset')
        write_text(kwargs['output_dir'] / 'traces.jsonl', '{}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {
            'artifacts': {'traces_jsonl': str(kwargs['output_dir'] / 'traces.jsonl')},
            'stats': {},
        }

    def fake_generate_trace_slices(**kwargs):
        called.append('06_trace_slices')
        (kwargs['output_dir'] / 'slice').mkdir(parents=True, exist_ok=True)
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {'artifacts': {'slice_dir': str(kwargs['output_dir'] / 'slice')}, 'stats': {}}

    def fake_export_trace_dataset(**kwargs):
        called.append('07_trace_dataset_export')
        (kwargs['output_dir'] / 'normalized_slices').mkdir(parents=True, exist_ok=True)
        for output_path in [
            kwargs['output_dir'] / 'Real_Vul_data.csv',
            kwargs['output_dir'] / 'split_manifest.json',
            kwargs['output_dir'] / 'summary.json',
        ]:
            write_text(output_path, 'ok\n')
        return {
            'artifacts': {'summary_json': str(kwargs['output_dir'] / 'summary.json')},
            'stats': {},
        }

    def fake_export_vuln_patch_dataset(**kwargs):
        called.append('07c_vuln_patch_export')
        output_dir = kwargs['output_dir']
        output_dir.mkdir(parents=True, exist_ok=True)
        for output_path in [
            output_dir / 'Real_Vul_data.csv',
            output_dir / 'summary.json',
        ]:
            write_text(output_path, 'ok\n')
        return {
            'artifacts': {
                'csv_path': str(output_dir / 'Real_Vul_data.csv'),
                'summary_json': str(output_dir / 'summary.json'),
            },
            'stats': {},
        }

    def fail_if_called(**kwargs):  # pragma: no cover - safety assertion
        raise AssertionError(f'Unexpected patched export call: {kwargs}')

    monkeypatch.setattr(
        module._stage01_manifest, 'scan_manifest_comments', fake_scan_manifest_comments
    )
    monkeypatch.setattr(
        module._stage02a_taint, 'extract_unique_code_fields', fake_extract_unique_code_fields
    )
    monkeypatch.setattr(module._stage02b_flow, 'run_stage02b_flow', fake_run_stage02b_flow)
    monkeypatch.setattr(
        module._stage03_infer, 'run_infer_and_signature', fake_run_infer_and_signature
    )
    monkeypatch.setattr(
        module._stage04_trace_flow, 'filter_traces_by_flow', fake_filter_traces_by_flow
    )
    monkeypatch.setattr(
        module._stage05_trace_dataset, 'build_trace_dataset', fake_build_trace_dataset
    )
    monkeypatch.setattr(
        module._stage06_trace_slices, 'generate_trace_slices', fake_generate_trace_slices
    )
    monkeypatch.setattr(module, 'export_trace_dataset_from_pipeline', fake_export_trace_dataset)
    monkeypatch.setattr(module, 'export_vuln_patch_dataset', fake_export_vuln_patch_dataset)
    monkeypatch.setattr(module, 'export_patched_dataset', fail_if_called)

    result = run_module_main(
        module,
        [
            'full',
            '121',
            '--manifest',
            str(manifest),
            '--source-root',
            str(source_root),
            '--pipeline-root',
            str(pipeline_root),
            '--run-id',
            'run-trace',
            '--committed-taint-config',
            str(committed_taint_config),
            '--disable-pair',
        ],
    )

    assert result == 0
    assert called == [
        '01_manifest_comment_scan',
        '02a_code_field_inventory',
        '02b_testcase_flow_build',
        '03_infer_and_signature',
        '04_trace_flow_filter',
        '05_trace_dataset',
        '06_trace_slices',
        '07_trace_dataset_export',
        '07c_vuln_patch_export',
    ]

    run_dir = pipeline_root / 'run-trace'
    assert (run_dir / '05_trace_ds' / 'traces.jsonl').exists()
    assert (run_dir / '06_trace_slices' / 'summary.json').exists()
    assert (run_dir / '07_dataset_export' / 'summary.json').exists()
    assert (run_dir / '07_dataset_export' / 'vuln_patch' / 'summary.json').exists()
    assert not (run_dir / '07_dataset_export' / 'train_patched_counterparts_summary.json').exists()


def test_full_subcommand_returns_failure_on_step_error(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_run_pipeline_full_failure',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    manifest = tmp_path / 'manifest.xml'
    source_root = tmp_path / 'juliet' / 'C'
    committed_taint_config = tmp_path / 'pulse-taint-config.json'
    pipeline_root = tmp_path / 'pipeline-runs'
    source_root.mkdir(parents=True)
    write_text(manifest, '<manifest />\n')
    write_text(committed_taint_config, '{}\n')

    monkeypatch.setattr(module, 'run_step01_manifest_comment_scan', lambda **kwargs: {'step': '01'})
    monkeypatch.setattr(
        module, 'run_step02a_code_field_inventory', lambda **kwargs: {'step': '02a'}
    )
    monkeypatch.setattr(module, 'run_step02b_flow_build', lambda **kwargs: {'step': '02b'})
    monkeypatch.setattr(
        module,
        'run_step03_infer_and_signature',
        lambda **kwargs: {
            'artifacts': {'signature_non_empty_dir': str(tmp_path / 'non-empty')},
            'stats': {},
        },
    )

    def fail_step04(**kwargs):
        raise RuntimeError('trace flow failed')

    monkeypatch.setattr(module, 'run_step04_trace_flow', fail_step04)

    result = run_module_main(
        module,
        [
            'full',
            '121',
            '--manifest',
            str(manifest),
            '--source-root',
            str(source_root),
            '--pipeline-root',
            str(pipeline_root),
            '--run-id',
            'run-fail',
            '--committed-taint-config',
            str(committed_taint_config),
        ],
    )

    assert result == 1
    assert not (pipeline_root / 'run-fail' / 'run_summary.json').exists()


def test_removed_subcommands_are_rejected():
    module = load_module_from_path(
        'test_run_pipeline_removed_subcommands',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    for command in [
        'stage01',
        'stage02a',
        'stage02b',
        'stage03',
        'stage03-signature',
        'stage04',
        'stage05',
        'stage06',
        'stage07',
        'stage07b',
    ]:
        with pytest.raises(SystemExit):
            run_module_main(module, [command])


def test_full_subcommand_defaults_to_pruning_single_child_flows(monkeypatch):
    module = load_module_from_path(
        'test_run_pipeline_default_single_child_prune_flag',
        REPO_ROOT / 'tools/run_pipeline.py',
    )
    captured: dict[str, object] = {}

    def fake_run_full_pipeline(config):
        captured['config'] = config
        return 0

    monkeypatch.setattr(module, 'run_full_pipeline', fake_run_full_pipeline)

    result = run_module_main(module, ['full', '121'])

    assert result == 0
    assert captured['config'].prune_single_child_flows is True


def test_full_subcommand_keep_single_child_flows_disables_pruning(monkeypatch):
    module = load_module_from_path(
        'test_run_pipeline_keep_single_child_flag',
        REPO_ROOT / 'tools/run_pipeline.py',
    )
    captured: dict[str, object] = {}

    def fake_run_full_pipeline(config):
        captured['config'] = config
        return 0

    monkeypatch.setattr(module, 'run_full_pipeline', fake_run_full_pipeline)

    result = run_module_main(module, ['full', '121', '--keep-single-child-flows'])

    assert result == 0
    assert captured['config'].prune_single_child_flows is False
