from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path, write_jsonl


def test_pipeline_run_uses_shared_step07_core(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07_shared_pipeline',
        REPO_ROOT / 'tools/stage/pipeline.py',
    )

    pairs_jsonl = tmp_path / 'pairs.jsonl'
    write_jsonl(
        pairs_jsonl,
        [
            {'pair_id': 'pair-a', 'testcase_key': 'CASE_A'},
            {'pair_id': 'pair-b', 'testcase_key': 'CASE_B'},
        ],
    )
    paired_signatures_dir = tmp_path / 'paired'
    slice_dir = tmp_path / 'slice'
    paired_signatures_dir.mkdir()
    slice_dir.mkdir()

    captured: dict[str, object] = {}

    def fake_core(**kwargs):
        captured.update(kwargs)
        return {
            'csv_path': kwargs['csv_path'],
            'dedup_dropped_csv': kwargs['dedup_dropped_csv'],
            'normalized_slices_dir': kwargs['normalized_slices_dir'],
            'token_counts_csv': kwargs['token_counts_csv'],
            'token_distribution_png': kwargs['token_distribution_png'],
            'split_manifest_json': kwargs['split_manifest_json'],
            'summary_json': kwargs['summary_json'],
            'counts': {},
        }

    monkeypatch.setattr(module._step07_shared, 'run_step07_export_core', fake_core)

    result = module.export_dataset_from_pipeline(
        pairs_jsonl=pairs_jsonl,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        output_dir=tmp_path / 'out',
        split_seed=1234,
        train_ratio=0.8,
        dedup_mode='row',
    )

    assert result['real_vul_data_csv'].endswith('Real_Vul_data.csv')
    split_assignments = captured['split_assignments_fn'](['pair-a', 'pair-b'])
    assert split_assignments.keys() == {'pair-a', 'pair-b'}
    assert set(split_assignments.values()) == {'train_val', 'test'}
    assert captured['summary_metadata']['seed'] == 1234
    assert captured['split_manifest_metadata']['split_unit'] == 'pair_id'


def test_patched_counterparts_uses_shared_step07_core(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07_shared_patched',
        REPO_ROOT / 'tools/stage/patched_export.py',
    )

    paired_signatures_dir = tmp_path / 'paired'
    slice_dir = tmp_path / 'slice'
    paired_signatures_dir.mkdir()
    slice_dir.mkdir()
    pairs = [
        {'pair_id': 'pair-a', 'testcase_key': 'CASE_A'},
        {'pair_id': 'pair-b', 'testcase_key': 'CASE_B'},
    ]

    captured: dict[str, object] = {}

    def fake_core(**kwargs):
        captured.update(kwargs)
        return {
            'csv_path': kwargs['csv_path'],
            'dedup_dropped_csv': kwargs['dedup_dropped_csv'],
            'normalized_slices_dir': kwargs['normalized_slices_dir'],
            'token_counts_csv': kwargs['token_counts_csv'],
            'token_distribution_png': kwargs['token_distribution_png'],
            'split_manifest_json': kwargs['split_manifest_json'],
            'summary_json': kwargs['summary_json'],
            'counts': {'pairs_total': 2},
        }

    monkeypatch.setattr(module._step07_shared, 'run_step07_export_core', fake_core)

    result = module.export_dataset(
        pairs=pairs,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        dataset_export_dir=tmp_path / 'out',
        overwrite=False,
        dedup_mode='none',
    )

    assert result['csv_path'].name == 'train_patched_counterparts.csv'
    assert captured['split_assignments_fn'](['pair-a', 'pair-b']) == {
        'pair-a': 'train_val',
        'pair-b': 'train_val',
    }
    assert captured['summary_metadata']['dataset_basename'] == 'train_patched_counterparts'
    assert captured['split_manifest_metadata']['split_mode'] == 'inherited_train_val_only'
