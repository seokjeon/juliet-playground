from __future__ import annotations

from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_pipeline_paths_from_run_dir_recreates_expected_layout(tmp_path):
    module = load_module_from_path(
        'test_pipeline_paths_layout',
        REPO_ROOT / 'tools/stage/pipeline.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_root = tmp_path / 'juliet' / 'C'
    paths = module.PipelinePaths.from_run_dir(run_dir=run_dir, source_root=source_root)

    assert paths.run_dir == run_dir.resolve()
    assert (
        paths.manifest_with_comments_xml
        == run_dir.resolve() / '01_manifest' / 'manifest_with_comments.xml'
    )
    assert (
        paths.trace_strict_jsonl
        == run_dir.resolve() / '04_trace_flow' / 'trace_flow_match_strict.jsonl'
    )
    assert paths.dataset_summary_json == run_dir.resolve() / '07_dataset_export' / 'summary.json'
    assert paths.train_patched_counterparts_summary_json == (
        run_dir.resolve() / '07_dataset_export' / 'train_patched_counterparts_summary.json'
    )
    assert paths.source_testcases_root == source_root / 'testcases'
    assert paths.train_patched_counterparts_script == (
        Path(module.PROJECT_HOME) / 'tools' / 'export_train_patched_counterparts.py'
    )


def test_run_step02b_flow_build_returns_all_step_results(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step02b_helpers',
        REPO_ROOT / 'tools/stage/pipeline.py',
    )

    paths = module.PipelinePaths.from_run_dir(
        run_dir=tmp_path / 'run',
        source_root=tmp_path / 'juliet' / 'C',
    )
    called: list[str] = []

    def fake_run_command(step_key, cmd, cwd, logs_dir):
        called.append(step_key)
        outputs_by_step = {
            '02b_function_inventory_extract': [
                paths.function_names_unique_csv,
                paths.function_inventory_summary_json,
            ],
            '02b_function_inventory_categorize': [
                paths.function_names_categorized_jsonl,
                paths.grouped_family_role_json,
                paths.category_summary_json,
            ],
            '02b_testcase_flow_partition': [
                paths.manifest_with_testcase_flows_xml,
                paths.testcase_flow_summary_json,
            ],
        }
        for output_path in outputs_by_step[step_key]:
            write_text(output_path, f'{step_key}\n')
        return {'step_key': step_key, 'command': cmd, 'cwd': str(cwd), 'stdout_log': str(logs_dir)}

    monkeypatch.setattr(module, 'run_command', fake_run_command)

    result = module.run_step02b_flow_build(paths=paths)

    assert list(result) == [
        '02b_function_inventory_extract',
        '02b_function_inventory_categorize',
        '02b_testcase_flow_partition',
    ]
    assert called == [
        '02b_function_inventory_extract',
        '02b_function_inventory_categorize',
        '02b_testcase_flow_partition',
    ]


def test_run_step07_dataset_export_uses_primary_dataset_api(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_pipeline_step07_helper',
        REPO_ROOT / 'tools/stage/pipeline.py',
    )

    paths = module.PipelinePaths.from_run_dir(
        run_dir=tmp_path / 'run',
        source_root=tmp_path / 'juliet' / 'C',
    )
    captured: dict[str, object] = {}

    class FakeResult:
        def to_payload(self):
            return {
                'summary_json': str(paths.dataset_summary_json),
                'output_dir': str(paths.dataset_stage_dir),
                'normalized_slices_dir': str(paths.normalized_slices_dir),
                'real_vul_data_csv': str(paths.real_vul_data_csv),
                'dedup_dropped_csv': str(paths.real_vul_data_dedup_dropped_csv),
                'normalized_token_counts_csv': str(paths.normalized_token_counts_csv),
                'slice_token_distribution_png': str(paths.slice_token_distribution_png),
                'split_manifest_json': str(paths.dataset_split_manifest_json),
            }

    def fake_export_primary_dataset(params):
        captured['params'] = params
        paths.normalized_slices_dir.mkdir(parents=True, exist_ok=True)
        for output_path in [
            paths.real_vul_data_csv,
            paths.real_vul_data_dedup_dropped_csv,
            paths.normalized_token_counts_csv,
            paths.slice_token_distribution_png,
            paths.dataset_split_manifest_json,
            paths.dataset_summary_json,
        ]:
            write_text(output_path, 'ok\n')
        return FakeResult()

    monkeypatch.setattr(module, 'export_primary_dataset', fake_export_primary_dataset)
    monkeypatch.setattr(module, 'run_internal_step', lambda step_key, logs_dir, fn: fn())

    result = module.run_step07_dataset_export(
        paths=paths,
        pair_split_seed=1234,
        pair_train_ratio=0.8,
        dedup_mode='row',
    )

    params = captured['params']
    assert params.pairs_jsonl == paths.pairs_jsonl
    assert params.output_dir == paths.dataset_stage_dir
    assert params.split_seed == 1234
    assert params.train_ratio == 0.8
    assert params.dedup_mode == 'row'
    assert result['summary_json'] == str(paths.dataset_summary_json)
