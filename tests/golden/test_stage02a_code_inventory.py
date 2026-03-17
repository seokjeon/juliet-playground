from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    load_module_from_path,
    normalized_file_text,
    prepare_workspace,
)


def test_stage02a_code_inventory_matches_golden(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage02a_code_inventory',
        REPO_ROOT / 'tools/stage/stage02a_taint.py',
    )

    output_dir = work_root / 'expected/02a_taint'
    module.extract_unique_code_fields(
        input_xml=baseline_root / 'expected/01_manifest/manifest_with_comments.xml',
        source_root=REPO_ROOT / 'juliet-test-suite-v1.3/C',
        output_dir=output_dir,
        pulse_taint_config_output=output_dir / 'pulse-taint-config.json',
    )

    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    for relative_path in [
        'pulse-taint-config.json',
        'function_name_macro_resolution.csv',
        'summary.json',
    ]:
        assert normalized_file_text(
            baseline_root / 'expected/02a_taint' / relative_path,
            root_aliases,
        ) == normalized_file_text(
            output_dir / relative_path,
            root_aliases,
        )
