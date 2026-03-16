from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_unordered_jsonl_matches,
    load_module_from_path,
    normalized_file_text,
    prepare_workspace,
    run_module_main,
)


def test_stage04_trace_flow_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage04_trace_flow',
        REPO_ROOT / 'experiments/epic001d_trace_flow_filter/scripts/filter_traces_by_flow.py',
    )

    output_dir = work_root / 'expected/04_trace_flow'
    assert (
        run_module_main(
            module,
            [
                '--flow-xml',
                str(baseline_root / 'expected/02c_flow/manifest_with_testcase_flows.xml'),
                '--signatures-dir',
                str(baseline_root / 'expected/03_signatures_non_empty'),
                '--output-dir',
                str(output_dir),
            ],
        )
        == 0
    )

    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    for name in [
        'trace_flow_match_all.jsonl',
        'trace_flow_match_strict.jsonl',
        'trace_flow_match_partial_or_strict.jsonl',
    ]:
        assert_unordered_jsonl_matches(
            expected_path=baseline_root / 'expected/04_trace_flow' / name,
            actual_path=output_dir / name,
            root_aliases=root_aliases,
        )

    assert normalized_file_text(
        baseline_root / 'expected/04_trace_flow/summary.json',
        root_aliases,
    ) == normalized_file_text(output_dir / 'summary.json', root_aliases)
