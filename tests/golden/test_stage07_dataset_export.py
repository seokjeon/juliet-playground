from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_text_multiset_matches,
    deterministic_tokenizer_context,
    load_module_from_path,
    normalized_file_text,
    prepare_workspace,
)


def test_stage07_dataset_export_matches_golden(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    pipeline_module = load_module_from_path(
        'test_golden_stage07_dataset_export',
        REPO_ROOT / 'tools/run-epic001-pipeline.py',
    )

    monkeypatch.chdir(baseline_root)
    output_dir = work_root / 'expected/07_dataset_export'
    with deterministic_tokenizer_context():
        pipeline_module.export_dataset_from_pipeline(
            pairs_jsonl=baseline_root / 'expected/05_pair_trace_ds/pairs.jsonl',
            paired_signatures_dir=baseline_root / 'expected/05_pair_trace_ds/paired_signatures',
            slice_dir=baseline_root / 'expected/06_slices/slice',
            output_dir=output_dir,
            split_seed=1234,
            train_ratio=0.8,
            dedup_mode='row',
        )

    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    for name in [
        'Real_Vul_data.csv',
        'Real_Vul_data_dedup_dropped.csv',
        'normalized_token_counts.csv',
        'split_manifest.json',
        'summary.json',
    ]:
        assert normalized_file_text(
            baseline_root / 'expected/07_dataset_export' / name,
            root_aliases,
        ) == normalized_file_text(output_dir / name, root_aliases)

    assert_directory_text_multiset_matches(
        expected_dir=baseline_root / 'expected/07_dataset_export/normalized_slices',
        actual_dir=output_dir / 'normalized_slices',
        root_aliases=root_aliases,
        suffixes={'.c', '.cpp'},
    )

    assert (output_dir / 'slice_token_distribution.png').exists()
