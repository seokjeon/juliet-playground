from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    normalized_file_text,
    normalized_json_value,
    prepare_workspace,
    run_module_main,
)


def test_stage02b_function_inventory_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    output_dir = work_root / 'expected/02b_inventory'
    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]

    extract_module = load_module_from_path(
        'test_golden_stage02b_extract_inventory',
        REPO_ROOT / 'experiments/epic001b_function_inventory/scripts/extract_function_inventory.py',
    )
    assert (
        run_module_main(
            extract_module,
            [
                '--input-xml',
                str(baseline_root / 'expected/01_manifest/manifest_with_comments.xml'),
                '--output-csv',
                str(output_dir / 'function_names_unique.csv'),
                '--output-summary',
                str(output_dir / 'function_inventory_summary.json'),
            ],
        )
        == 0
    )

    assert normalized_file_text(
        baseline_root / 'expected/02b_inventory/function_names_unique.csv',
        root_aliases,
    ) == normalized_file_text(
        output_dir / 'function_names_unique.csv',
        root_aliases,
    )

    expected_extract_summary = normalized_json_value(
        baseline_root / 'expected/02b_inventory/function_inventory_summary.json',
        root_aliases,
    )
    actual_extract_summary = normalized_json_value(
        output_dir / 'function_inventory_summary.json',
        root_aliases,
    )
    for key in [
        'total_comment_tags_seen',
        'total_function_values',
        'missing_or_empty_function',
        'unique_function_names',
    ]:
        assert actual_extract_summary[key] == expected_extract_summary[key]

    categorize_module = load_module_from_path(
        'test_golden_stage02b_categorize_inventory',
        REPO_ROOT / 'experiments/epic001b_function_inventory/scripts/categorize_function_names.py',
    )
    assert (
        run_module_main(
            categorize_module,
            [
                '--input-csv',
                str(output_dir / 'function_names_unique.csv'),
                '--manifest-xml',
                str(baseline_root / 'expected/01_manifest/manifest_with_comments.xml'),
                '--source-root',
                str(REPO_ROOT / 'juliet-test-suite-v1.3/C/testcases'),
                '--output-jsonl',
                str(output_dir / 'function_names_categorized.jsonl'),
                '--output-nested-json',
                str(output_dir / 'grouped_family_role.json'),
                '--output-summary',
                str(output_dir / 'category_summary.json'),
            ],
        )
        == 0
    )

    assert normalized_file_text(
        baseline_root / 'expected/02b_inventory/function_names_categorized.jsonl',
        root_aliases,
    ) == normalized_file_text(
        output_dir / 'function_names_categorized.jsonl',
        root_aliases,
    )

    expected_category_summary = normalized_json_value(
        baseline_root / 'expected/02b_inventory/category_summary.json',
        root_aliases,
    )
    actual_category_summary = normalized_json_value(
        output_dir / 'category_summary.json',
        root_aliases,
    )
    for key in [
        'total_unique_function_names',
        'total_weighted_count',
        'flow_family_distribution',
        'operation_role_distribution',
        'role_variant_distribution',
        'flow_family_operation_role_distribution',
    ]:
        assert actual_category_summary[key] == expected_category_summary[key]
