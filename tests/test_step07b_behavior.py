from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_json, write_jsonl


def test_build_train_patched_counterparts_tracks_selection_and_skip_reasons(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_selection',
        REPO_ROOT / 'tools/stage/patched_export.py',
    )

    pair_dir = tmp_path / 'run' / '05_pair_trace_ds'
    dataset_export_dir = tmp_path / 'run' / '07_dataset_export'
    signature_output_dir = tmp_path / 'selected-signatures'
    output_pairs_jsonl = pair_dir / 'train_patched_counterparts_pairs.jsonl'
    selection_summary_json = pair_dir / 'train_patched_counterparts_selection_summary.json'

    b2b_1 = pair_dir / 'paired_signatures' / 'CASE1' / 'b2b.json'
    b2b_2 = pair_dir / 'paired_signatures' / 'CASE2' / 'b2b.json'
    b2b_3 = pair_dir / 'paired_signatures' / 'CASE3' / 'b2b.json'
    counterpart_1 = pair_dir / 'leftovers' / 'case1_g2b.json'
    counterpart_3 = pair_dir / 'leftovers' / 'case3_unknown.json'

    for path in [b2b_1, b2b_2, b2b_3, counterpart_1, counterpart_3]:
        write_json(path, {'bug_trace': [], 'key': path.stem, 'hash': f'hash-{path.stem}'})

    write_jsonl(
        pair_dir / 'pairs.jsonl',
        [
            {
                'pair_id': 'primary-1',
                'testcase_key': 'CASE1',
                'b2b_trace_file': str(b2b_1),
                'b2b_flow_type': 'b2b',
                'b2b_bug_trace_length': 4,
                'b2b_signature': {'procedure': 'bad'},
                'output_files': {'b2b': str(b2b_1)},
            },
            {
                'pair_id': 'primary-2',
                'testcase_key': 'CASE2',
                'b2b_trace_file': str(b2b_2),
                'b2b_flow_type': 'b2b',
                'b2b_bug_trace_length': 3,
                'b2b_signature': {'procedure': 'bad'},
                'output_files': {'b2b': str(b2b_2)},
            },
            {
                'pair_id': 'primary-3',
                'testcase_key': 'CASE3',
                'b2b_trace_file': str(b2b_3),
                'b2b_flow_type': 'b2b',
                'b2b_bug_trace_length': 2,
                'b2b_signature': {'procedure': 'bad'},
                'output_files': {'b2b': str(b2b_3)},
            },
        ],
    )
    write_jsonl(
        pair_dir / 'leftover_counterparts.jsonl',
        [
            {
                'testcase_key': 'CASE1',
                'trace_file': str(counterpart_1),
                'best_flow_type': 'g2b',
                'bug_trace_length': 8,
                'procedure': 'goodG2B',
            },
            {
                'testcase_key': 'CASE3',
                'trace_file': str(counterpart_3),
                'best_flow_type': '',
                'bug_trace_length': 5,
                'procedure': 'mystery',
            },
        ],
    )
    write_json(
        dataset_export_dir / 'split_manifest.json',
        {
            'pair_ids': {
                'train_val': ['primary-1', 'primary-2', 'primary-3'],
                'test': [],
            }
        },
    )

    result = module.build_train_patched_counterparts(
        pair_dir=pair_dir,
        dataset_export_dir=dataset_export_dir,
        signature_output_dir=signature_output_dir,
        output_pairs_jsonl=output_pairs_jsonl,
        selection_summary_json=selection_summary_json,
        overwrite=False,
    )

    assert len(result['pairs']) == 1
    selected = result['pairs'][0]
    assert selected['testcase_key'] == 'CASE1'
    assert selected['source_primary_pair_id'] == 'primary-1'
    assert selected['selection_reason'] == 'top_leftover_train_val'
    assert selected['counterpart_flow_type'] == 'g2b'
    assert Path(selected['output_files']['b2b']).exists()
    assert Path(selected['output_files']['g2b']).exists()

    summary = json.loads(selection_summary_json.read_text(encoding='utf-8'))
    assert summary['counts'] == {
        'primary_train_val_pairs_total': 3,
        'selected_pairs': 1,
        'selected_counterpart_flow_g2b': 1,
        'primary_train_val_pairs_without_leftover': 1,
        'skipped_missing_counterpart_flow_type': 1,
    }


def test_build_train_patched_counterparts_requires_train_val_pairs(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_requires_train',
        REPO_ROOT / 'tools/stage/patched_export.py',
    )

    pair_dir = tmp_path / 'run' / '05_pair_trace_ds'
    dataset_export_dir = tmp_path / 'run' / '07_dataset_export'
    write_jsonl(pair_dir / 'pairs.jsonl', [])
    write_jsonl(pair_dir / 'leftover_counterparts.jsonl', [])
    write_json(
        dataset_export_dir / 'split_manifest.json', {'pair_ids': {'train_val': [], 'test': []}}
    )

    with pytest.raises(ValueError, match='No train_val pair_ids found'):
        module.build_train_patched_counterparts(
            pair_dir=pair_dir,
            dataset_export_dir=dataset_export_dir,
            signature_output_dir=tmp_path / 'sig-out',
            output_pairs_jsonl=tmp_path / 'pairs-out.jsonl',
            selection_summary_json=tmp_path / 'selection.json',
            overwrite=False,
        )


def test_main_passes_dedup_mode_to_export_dataset(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07b_behavior_main',
        REPO_ROOT / 'tools/stage/patched_export.py',
    )

    run_dir = tmp_path / 'run'
    pair_dir = run_dir / '05_pair_trace_ds'
    dataset_export_dir = run_dir / '07_dataset_export'
    pair_dir.mkdir(parents=True)
    dataset_export_dir.mkdir(parents=True)

    captured: dict[str, object] = {}

    def fake_build_train_patched_counterparts(**kwargs):
        captured['build_args'] = kwargs
        return {
            'pairs': [{'pair_id': 'p1', 'testcase_key': 'CASE1'}],
            'output_pairs_jsonl': Path(kwargs['output_pairs_jsonl']),
            'selection_summary_json': Path(kwargs['selection_summary_json']),
            'signature_output_dir': Path(kwargs['signature_output_dir']),
            'selection_counts': {},
        }

    def fake_process_signature_db(**kwargs):
        captured['slice_args'] = kwargs
        return {'signature_db_dirs_total': 0, 'total_slices': 0, 'errors': 0, 'counts': {}}

    def fake_export_dataset(**kwargs):
        captured['export_args'] = kwargs
        out = kwargs['dataset_export_dir']
        return {
            'csv_path': out / 'train_patched_counterparts.csv',
            'dedup_dropped_csv': out / 'train_patched_counterparts_dedup_dropped.csv',
            'normalized_slices_dir': out / 'train_patched_counterparts_slices',
            'token_counts_csv': out / 'train_patched_counterparts_token_counts.csv',
            'token_distribution_png': out / 'train_patched_counterparts_token_distribution.png',
            'split_manifest_json': out / 'train_patched_counterparts_split_manifest.json',
            'summary_json': out / 'train_patched_counterparts_summary.json',
        }

    monkeypatch.setattr(
        module, 'build_train_patched_counterparts', fake_build_train_patched_counterparts
    )
    monkeypatch.setattr(module, 'process_signature_db', fake_process_signature_db)
    monkeypatch.setattr(module, 'export_dataset', fake_export_dataset)

    assert (
        run_module_main(
            module,
            [
                '--run-dir',
                str(run_dir),
                '--dedup-mode',
                'none',
                '--signature-output-dir',
                str(tmp_path / 'sig-out'),
                '--slice-output-dir',
                str(tmp_path / 'slice-out'),
            ],
        )
        == 0
    )

    assert captured['export_args']['dedup_mode'] == 'none'
    assert captured['build_args']['pair_dir'] == pair_dir
    assert captured['build_args']['dataset_export_dir'] == dataset_export_dir
    assert captured['slice_args']['signature_db_dir'] == tmp_path / 'sig-out'
