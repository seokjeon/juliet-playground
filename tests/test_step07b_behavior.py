from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, write_json, write_jsonl


def test_build_train_patched_counterparts_tracks_selection_and_skip_reasons(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_selection',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
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
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
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


def test_build_train_patched_counterparts_pair_id_is_stable_across_run_roots(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_pair_id_stability',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    def build_selection(root: Path) -> str:
        pair_dir = root / 'run' / '05_pair_trace_ds'
        dataset_export_dir = root / 'run' / '07_dataset_export'
        signature_output_dir = pair_dir / 'train_patched_counterparts_signatures'
        output_pairs_jsonl = pair_dir / 'train_patched_counterparts_pairs.jsonl'
        selection_summary_json = pair_dir / 'train_patched_counterparts_selection_summary.json'

        b2b_path = pair_dir / 'paired_signatures' / 'CASE1' / 'b2b.json'
        counterpart_path = pair_dir / 'leftovers' / 'case1_g2b.json'
        for path, payload in (
            (b2b_path, {'bug_trace': [], 'key': 'CASE1|bad|TAINT_ERROR', 'hash': 'hash-b2b'}),
            (
                counterpart_path,
                {'bug_trace': [], 'key': 'CASE1|goodG2B|TAINT_ERROR', 'hash': 'hash-g2b'},
            ),
        ):
            write_json(path, payload)

        write_jsonl(
            pair_dir / 'pairs.jsonl',
            [
                {
                    'pair_id': 'primary-1',
                    'testcase_key': 'CASE1',
                    'b2b_trace_file': str(b2b_path),
                    'b2b_flow_type': 'b2b',
                    'b2b_bug_trace_length': 4,
                    'b2b_signature': {'procedure': 'bad'},
                    'output_files': {'b2b': str(b2b_path)},
                }
            ],
        )
        write_jsonl(
            pair_dir / 'leftover_counterparts.jsonl',
            [
                {
                    'testcase_key': 'CASE1',
                    'trace_file': str(counterpart_path),
                    'best_flow_type': 'g2b',
                    'bug_trace_length': 8,
                    'procedure': 'goodG2B',
                }
            ],
        )
        write_json(
            dataset_export_dir / 'split_manifest.json',
            {'pair_ids': {'train_val': ['primary-1'], 'test': []}},
        )

        result = module.build_train_patched_counterparts(
            pair_dir=pair_dir,
            dataset_export_dir=dataset_export_dir,
            signature_output_dir=signature_output_dir,
            output_pairs_jsonl=output_pairs_jsonl,
            selection_summary_json=selection_summary_json,
            overwrite=False,
        )
        return result['pairs'][0]['pair_id']

    assert build_selection(tmp_path / 'root_a') == build_selection(tmp_path / 'root_b')


def test_leftover_sort_key_ignores_run_prefix():
    module = load_module_from_path(
        'test_step07b_behavior_leftover_sort_key_stability',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    left = {
        'trace_file': '/tmp/run-a/leftovers/CASE1/7.json',
        'best_flow_type': 'g2b',
        'bug_trace_length': 8,
        'procedure': 'goodG2B',
    }
    right = {
        'trace_file': '/tmp/run-b/leftovers/CASE1/7.json',
        'best_flow_type': 'g2b',
        'bug_trace_length': 8,
        'procedure': 'goodG2B',
    }

    assert module.leftover_sort_key(left) == module.leftover_sort_key(right)


def test_export_patched_dataset_runs_selection_slice_and_export(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07b_behavior_export_api',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
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

    def fake_generate_slices(**kwargs):
        captured['slice_args'] = kwargs
        out = kwargs['output_dir']
        (out / 'slice').mkdir(parents=True, exist_ok=True)
        (out / 'summary.json').write_text('{}\n', encoding='utf-8')
        return {
            'dataset_basename': module.DATASET_BASENAME,
            'signature_db_dir': str(kwargs['signature_db_dir']),
            'output_dir': str(out),
            'slice_dir': str(out / 'slice'),
            'run_dir': str(kwargs['run_dir']),
            'signature_db_dirs_total': 0,
            'total_slices': 0,
            'errors': 0,
            'counts': {},
        }

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
    monkeypatch.setattr(module, 'generate_slices', fake_generate_slices)
    monkeypatch.setattr(module, 'export_dataset', fake_export_dataset)

    result = module.export_patched_dataset(
        module.PatchedDatasetExportParams(
            run_dir=run_dir,
            pair_dir=pair_dir,
            dataset_export_dir=dataset_export_dir,
            signature_output_dir=tmp_path / 'sig-out',
            slice_output_dir=tmp_path / 'slice-out',
            output_pairs_jsonl=pair_dir / 'train_patched_counterparts_pairs.jsonl',
            selection_summary_json=pair_dir / 'train_patched_counterparts_selection_summary.json',
            dedup_mode='none',
            overwrite=False,
            old_prefix=None,
            new_prefix=None,
        )
    )

    assert captured['export_args']['dedup_mode'] == 'none'
    assert captured['build_args']['pair_dir'] == pair_dir
    assert captured['build_args']['dataset_export_dir'] == dataset_export_dir
    assert captured['slice_args']['signature_db_dir'] == tmp_path / 'sig-out'
    assert captured['slice_args']['output_dir'] == tmp_path / 'slice-out'
    assert captured['slice_args']['summary_metadata'] == {
        'dataset_basename': module.DATASET_BASENAME
    }
    assert result.summary_json == dataset_export_dir / 'train_patched_counterparts_summary.json'
    assert result.slice_summary_json == tmp_path / 'slice-out' / 'summary.json'


def test_resolve_paths_and_validate_args_use_explicit_inputs(tmp_path):
    module = load_module_from_path(
        'test_step07b_behavior_paths',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    run_dir = tmp_path / 'run'
    pair_dir = run_dir / '05_pair_trace_ds'
    dataset_export_dir = run_dir / '07_dataset_export'
    pair_dir.mkdir(parents=True)
    dataset_export_dir.mkdir(parents=True)

    paths = module.resolve_paths(run_dir=run_dir)

    assert paths['run_dir'] == run_dir
    assert paths['pair_dir'] == pair_dir
    assert paths['dataset_export_dir'] == dataset_export_dir
    assert paths['signature_output_dir'] == pair_dir / 'train_patched_counterparts_signatures'
    assert paths['slice_output_dir'] == run_dir / '06_slices' / 'train_patched_counterparts'

    module.validate_args(
        pair_dir=paths['pair_dir'],
        dataset_export_dir=paths['dataset_export_dir'],
        old_prefix='old',
        new_prefix='new',
    )

    with pytest.raises(ValueError, match='--old-prefix and --new-prefix'):
        module.validate_args(
            pair_dir=paths['pair_dir'],
            dataset_export_dir=paths['dataset_export_dir'],
            old_prefix='old',
            new_prefix=None,
        )
