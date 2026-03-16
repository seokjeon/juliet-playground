from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from tests.helpers import (
    REPO_ROOT,
    deterministic_tokenizer_context,
    load_module_from_path,
    write_json,
    write_jsonl,
    write_text,
)


def _make_pair(
    root: Path,
    testcase_key: str,
    pair_id: str,
    counterpart_flow_type: str,
    b2b_code: str,
    counterpart_code: str,
) -> dict[str, object]:
    pair_dir = root / 'paired_signatures' / testcase_key
    b2b_path = pair_dir / 'b2b.json'
    counterpart_path = pair_dir / f'{counterpart_flow_type}.json'
    write_json(b2b_path, {'file': str(root / 'sources' / f'{testcase_key}.c'), 'bug_trace': []})
    write_json(
        counterpart_path,
        {'file': str(root / 'sources' / f'{testcase_key}.c'), 'bug_trace': []},
    )

    slice_dir = root / 'slice'
    write_text(slice_dir / f'slice_{testcase_key}_b2b.c', b2b_code)
    write_text(slice_dir / f'slice_{testcase_key}_{counterpart_flow_type}.c', counterpart_code)

    return {
        'pair_id': pair_id,
        'testcase_key': testcase_key,
        'counterpart_flow_type': counterpart_flow_type,
        'b2b_signature': {'primary_file': f'{testcase_key}.c'},
        'counterpart_signature': {'primary_file': f'{testcase_key}.c'},
        'output_files': {
            'b2b': str(b2b_path),
            counterpart_flow_type: str(counterpart_path),
        },
    }


def test_export_dataset_from_pipeline_validates_inputs_and_options(tmp_path):
    module = load_module_from_path(
        'test_step07_behavior_validation',
        REPO_ROOT / 'tools/stage/pipeline.py',
    )

    paired_signatures_dir = tmp_path / 'paired'
    slice_dir = tmp_path / 'slice'
    output_dir = tmp_path / 'out'

    with pytest.raises(FileNotFoundError, match='Pairs JSONL not found'):
        module.export_dataset_from_pipeline(
            pairs_jsonl=tmp_path / 'missing.jsonl',
            paired_signatures_dir=paired_signatures_dir,
            slice_dir=slice_dir,
            output_dir=output_dir,
            split_seed=1234,
            train_ratio=0.8,
            dedup_mode='row',
        )

    pairs_jsonl = tmp_path / 'pairs.jsonl'
    write_text(pairs_jsonl, '')
    paired_signatures_dir.mkdir()
    slice_dir.mkdir()

    with pytest.raises(ValueError, match='train_ratio'):
        module.export_dataset_from_pipeline(
            pairs_jsonl=pairs_jsonl,
            paired_signatures_dir=paired_signatures_dir,
            slice_dir=slice_dir,
            output_dir=output_dir,
            split_seed=1234,
            train_ratio=1.5,
            dedup_mode='row',
        )

    with pytest.raises(ValueError, match='Unsupported dedup_mode'):
        module.export_dataset_from_pipeline(
            pairs_jsonl=pairs_jsonl,
            paired_signatures_dir=paired_signatures_dir,
            slice_dir=slice_dir,
            output_dir=output_dir,
            split_seed=1234,
            train_ratio=0.8,
            dedup_mode='weird',
        )


def test_export_dataset_from_pipeline_writes_split_and_dedup_outputs(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07_behavior_happy_path',
        REPO_ROOT / 'tools/stage/pipeline.py',
    )

    source_path = tmp_path / 'sources' / 'shared.c'
    write_text(source_path, 'int helper(void) { return 0; }\n')

    root = tmp_path / 'inputs'
    pair_a = _make_pair(
        root,
        'CASE_A',
        'pair-a',
        'g2b',
        'int bad_a = 1;\n',
        'int good_a = 0;\n',
    )
    pair_b = _make_pair(
        root,
        'CASE_B',
        'pair-b',
        'g2b1',
        'int bad_b = 2;\n',
        'int good_b = 3;\n',
    )
    pair_c = _make_pair(
        root,
        'CASE_C',
        'pair-c',
        'g2b2',
        'int bad_a = 1;\n',
        'int good_a = 0;\n',
    )
    pair_d = _make_pair(
        root,
        'CASE_D',
        'pair-d',
        'g2b',
        'int bad_d = 4;\n',
        'int good_d = 5;\n',
    )
    # Trigger missing_slice_file for pair_d counterpart.
    (root / 'slice' / 'slice_CASE_D_g2b.c').unlink()

    pairs_jsonl = tmp_path / 'pairs.jsonl'
    write_jsonl(pairs_jsonl, [pair_a, pair_b, pair_c, pair_d])

    monkeypatch.setattr(
        module, 'build_source_file_candidates', lambda *_args, **_kwargs: [source_path]
    )
    monkeypatch.setattr(
        module,
        'collect_defined_function_names',
        lambda *_args, **_kwargs: (set(), None),
    )

    output_dir = tmp_path / 'out'
    with deterministic_tokenizer_context():
        result = module.export_dataset_from_pipeline(
            pairs_jsonl=pairs_jsonl,
            paired_signatures_dir=root / 'paired_signatures',
            slice_dir=root / 'slice',
            output_dir=output_dir,
            split_seed=1234,
            train_ratio=0.8,
            dedup_mode='row',
        )

    assert Path(result['summary_json']).exists()

    summary = json.loads((output_dir / 'summary.json').read_text(encoding='utf-8'))
    assert summary['counts']['pairs_total'] == 4
    assert summary['counts']['pairs_survived'] == 2
    assert summary['counts']['pairs_filtered_out'] == 2
    assert summary['counts']['train_val_pairs'] == 1
    assert summary['counts']['test_pairs'] == 1
    assert summary['filtered_pair_reasons'] == {
        'missing_slice_file': 1,
        'dedup_duplicate_normalized_slice': 1,
    }

    split_manifest = json.loads((output_dir / 'split_manifest.json').read_text(encoding='utf-8'))
    assert split_manifest['counts']['pairs_total'] == 2
    assert split_manifest['counts']['train_val'] == 1
    assert split_manifest['counts']['test'] == 1
    assert len(split_manifest['pair_ids']['train_val']) == 1
    assert len(split_manifest['pair_ids']['test']) == 1

    with (output_dir / 'Real_Vul_data_dedup_dropped.csv').open(newline='', encoding='utf-8') as f:
        rows = list(csv.reader(f))
    assert len(rows) == 3  # header + 2 dropped rows from duplicate pair

    normalized_files = sorted((output_dir / 'normalized_slices').iterdir())
    assert len(normalized_files) == 4


def test_export_dataset_from_pipeline_filters_over_limit_pairs(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_step07_behavior_over_limit',
        REPO_ROOT / 'tools/stage/pipeline.py',
    )

    root = tmp_path / 'inputs'
    pair = _make_pair(
        root,
        'CASE_LONG',
        'pair-long',
        'g2b',
        'OVER_LIMIT bad\n',
        'OVER_LIMIT good\n',
    )
    pairs_jsonl = tmp_path / 'pairs.jsonl'
    write_jsonl(pairs_jsonl, [pair])

    source_path = tmp_path / 'sources' / 'shared.c'
    write_text(source_path, 'int helper(void) { return 0; }\n')
    monkeypatch.setattr(
        module, 'build_source_file_candidates', lambda *_args, **_kwargs: [source_path]
    )
    monkeypatch.setattr(
        module,
        'collect_defined_function_names',
        lambda *_args, **_kwargs: (set(), None),
    )

    import tokenize_slices

    class OverLimitTokenizer:
        def tokenize(self, code: str) -> list[str]:
            if 'OVER_LIMIT' in code:
                return ['tok'] * 600
            return code.split()

    monkeypatch.setattr(tokenize_slices, 'load_tokenizer', lambda _model_name: OverLimitTokenizer())
    monkeypatch.setattr(
        tokenize_slices,
        'plot_distribution',
        lambda _rows, output_plot: Path(output_plot).write_bytes(b'STUB_PNG\n'),
    )

    output_dir = tmp_path / 'out'
    module.export_dataset_from_pipeline(
        pairs_jsonl=pairs_jsonl,
        paired_signatures_dir=root / 'paired_signatures',
        slice_dir=root / 'slice',
        output_dir=output_dir,
        split_seed=1234,
        train_ratio=0.8,
        dedup_mode='row',
    )

    summary = json.loads((output_dir / 'summary.json').read_text(encoding='utf-8'))
    assert summary['filtered_pair_reasons'] == {'over_limit': 1}
    assert summary['counts']['pairs_survived'] == 0
    assert summary['counts']['rows_written'] == 0

    with (output_dir / 'Real_Vul_data.csv').open(newline='', encoding='utf-8') as f:
        rows = list(csv.reader(f))
    assert len(rows) == 1
