from __future__ import annotations

from tests.golden.helpers import assert_flow_xml_contents_match, prepare_workspace
from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_build_stage02b_output_paths_matches_pipeline_layout(tmp_path):
    stage02b_module = load_module_from_path(
        'test_stage02b_output_paths_module',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )
    pipeline_module = load_module_from_path(
        'test_stage02b_output_paths_pipeline_module',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    run_dir = tmp_path / 'pipeline-runs' / 'run-demo'
    source_root = tmp_path / 'juliet' / 'C'
    pipeline_paths = pipeline_module._build_full_run_paths(run_dir=run_dir, source_root=source_root)
    stage02b_paths = stage02b_module.build_stage02b_output_paths(pipeline_paths['flow_dir'])

    assert pipeline_paths['stage02b'] == stage02b_paths
    assert set(stage02b_paths) == {'output_dir', 'manifest_with_testcase_flows_xml', 'summary_json'}


def test_run_stage02b_flow_uses_shared_output_paths(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_stage02b_run_stage_flow_module',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    output_dir = tmp_path / '02b_flow'
    expected_paths = module.build_stage02b_output_paths(output_dir)
    captured: dict[str, object] = {}

    def fake_add_flow_tags_to_testcase(**kwargs):
        captured['partition'] = kwargs
        write_text(kwargs['output_xml'], '<root />\n')
        return {'testcases': 1}

    monkeypatch.setattr(module, 'add_flow_tags_to_testcase', fake_add_flow_tags_to_testcase)

    result = module.run_stage02b_flow(
        input_xml=tmp_path / 'manifest.xml',
        output_dir=output_dir,
    )

    assert captured['partition']['output_xml'] == expected_paths['manifest_with_testcase_flows_xml']
    assert captured['partition']['prune_single_child_flows'] is True
    assert captured['partition']['summary_json'] is None
    assert result['artifacts']['manifest_with_testcase_flows_xml'] == str(
        expected_paths['manifest_with_testcase_flows_xml']
    )
    assert result['artifacts']['summary_json'] == str(expected_paths['summary_json'])
    assert result['stats'] == {'testcases': 1}


def test_run_stage02b_flow_can_keep_single_child_flows_when_requested(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_stage02b_run_stage_flow_module_keep_single_child',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    captured: dict[str, object] = {}

    def fake_add_flow_tags_to_testcase(**kwargs):
        captured['partition'] = kwargs
        write_text(kwargs['output_xml'], '<root />\n')
        return {'testcases': 1}

    monkeypatch.setattr(module, 'add_flow_tags_to_testcase', fake_add_flow_tags_to_testcase)

    module.run_stage02b_flow(
        input_xml=tmp_path / 'manifest.xml',
        output_dir=tmp_path / '02b_flow',
        prune_single_child_flows=False,
    )

    assert captured['partition']['prune_single_child_flows'] is False


def test_run_stage02b_flow_matches_existing_flow_golden(tmp_path):
    module = load_module_from_path(
        'test_stage02b_run_stage_flow_real',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )
    baseline_root, work_root = prepare_workspace(tmp_path)
    output_dir = work_root / 'expected/02b_flow'

    result = module.run_stage02b_flow(
        input_xml=baseline_root / 'expected/01_manifest/manifest_with_comments.xml',
        output_dir=output_dir,
    )

    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    assert_flow_xml_contents_match(
        expected_path=baseline_root / 'expected/02c_flow/manifest_with_testcase_flows.xml',
        actual_path=output_dir / 'manifest_with_testcase_flows.xml',
        root_aliases=root_aliases,
    )
    assert result['stats']['testcases'] > 0
