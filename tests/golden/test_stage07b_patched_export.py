from __future__ import annotations

from tests.golden.helpers import (
    REPO_ROOT,
    assert_directory_matches,
    assert_directory_text_multiset_matches,
    deterministic_tokenizer_context,
    load_module_from_path,
    normalized_file_text,
    prepare_workspace,
    run_module_main,
)


def test_stage07b_patched_export_matches_golden(tmp_path, monkeypatch):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_golden_stage07b_patched_export',
        REPO_ROOT / 'tools/export_train_patched_counterparts.py',
    )

    monkeypatch.chdir(baseline_root)

    pair_dir = baseline_root / 'expected/05_pair_trace_ds'
    output_pair_dir = work_root / 'expected/05_pair_trace_ds'
    dataset_export_dir = work_root / 'expected/07b_dataset_export'
    slice_output_dir = work_root / 'expected/06_slices/train_patched_counterparts'
    signature_output_dir = output_pair_dir / 'train_patched_counterparts_signatures'
    output_pairs_jsonl = output_pair_dir / 'train_patched_counterparts_pairs.jsonl'
    selection_summary_json = output_pair_dir / 'train_patched_counterparts_selection_summary.json'

    dataset_export_dir.mkdir(parents=True, exist_ok=True)
    (dataset_export_dir / 'split_manifest.json').write_text(
        (baseline_root / 'expected/07b_dataset_export/split_manifest.json').read_text(
            encoding='utf-8'
        ),
        encoding='utf-8',
    )

    with deterministic_tokenizer_context():
        assert (
            run_module_main(
                module,
                [
                    '--pair-dir',
                    str(pair_dir),
                    '--dataset-export-dir',
                    str(dataset_export_dir),
                    '--signature-output-dir',
                    str(signature_output_dir),
                    '--slice-output-dir',
                    str(slice_output_dir),
                    '--output-pairs-jsonl',
                    str(output_pairs_jsonl),
                    '--selection-summary-json',
                    str(selection_summary_json),
                    '--dedup-mode',
                    'row',
                    '--overwrite',
                ],
                cwd=baseline_root,
            )
            == 0
        )

    root_aliases = [(baseline_root, ''), (work_root, ''), (REPO_ROOT, '')]
    assert normalized_file_text(
        baseline_root / 'expected/05_pair_trace_ds/train_patched_counterparts_pairs.jsonl',
        root_aliases,
    ) == normalized_file_text(output_pairs_jsonl, root_aliases)
    assert normalized_file_text(
        baseline_root
        / 'expected/05_pair_trace_ds/train_patched_counterparts_selection_summary.json',
        root_aliases,
    ) == normalized_file_text(selection_summary_json, root_aliases)

    assert_directory_matches(
        expected_dir=baseline_root
        / 'expected/05_pair_trace_ds/train_patched_counterparts_signatures',
        actual_dir=signature_output_dir,
        root_aliases=root_aliases,
    )
    assert_directory_matches(
        expected_dir=baseline_root / 'expected/06_slices/train_patched_counterparts',
        actual_dir=slice_output_dir,
        root_aliases=root_aliases,
    )

    for name in [
        'train_patched_counterparts.csv',
        'train_patched_counterparts_dedup_dropped.csv',
        'train_patched_counterparts_token_counts.csv',
        'train_patched_counterparts_split_manifest.json',
        'train_patched_counterparts_summary.json',
    ]:
        assert normalized_file_text(
            baseline_root / 'expected/07b_dataset_export' / name,
            root_aliases,
        ) == normalized_file_text(dataset_export_dir / name, root_aliases)

    assert_directory_text_multiset_matches(
        expected_dir=baseline_root
        / 'expected/07b_dataset_export/train_patched_counterparts_slices',
        actual_dir=dataset_export_dir / 'train_patched_counterparts_slices',
        root_aliases=root_aliases,
        suffixes={'.c', '.cpp'},
    )
    assert (dataset_export_dir / 'train_patched_counterparts_token_distribution.png').exists()
