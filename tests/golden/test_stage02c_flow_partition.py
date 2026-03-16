from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_flow_xml_contents_match,
    load_module_from_path,
    normalized_file_text,
    prepare_workspace,
    run_module_main,
)


def test_stage02c_flow_partition_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage02c_flow_partition',
        REPO_ROOT
        / 'experiments/epic001c_testcase_flow_partition/scripts/add_flow_tags_to_testcase.py',
    )

    output_dir = work_root / 'expected/02c_flow'
    output_xml = output_dir / 'manifest_with_testcase_flows.xml'
    summary_json = output_dir / 'summary.json'
    assert (
        run_module_main(
            module,
            [
                '--input-xml',
                str(baseline_root / 'expected/01_manifest/manifest_with_comments.xml'),
                '--function-categories-jsonl',
                str(baseline_root / 'expected/02b_inventory/function_names_categorized.jsonl'),
                '--output-xml',
                str(output_xml),
                '--summary-json',
                str(summary_json),
            ],
        )
        == 0
    )

    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    assert_flow_xml_contents_match(
        expected_path=baseline_root / 'expected/02c_flow/manifest_with_testcase_flows.xml',
        actual_path=output_xml,
        root_aliases=root_aliases,
    )
    assert normalized_file_text(
        baseline_root / 'expected/02c_flow/summary.json',
        root_aliases,
    ) == normalized_file_text(summary_json, root_aliases)
