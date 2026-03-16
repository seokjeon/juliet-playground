from __future__ import annotations

import json

from tests.helpers import REPO_ROOT, load_module_from_path


def test_process_signature_db_uses_longest_subtrace_and_dedupes_locations(tmp_path):
    module = load_module_from_path(
        'test_stage06_slices_module',
        REPO_ROOT / 'tools/stage/stage06_slices.py',
    )

    source_file = tmp_path / 'sample.c'
    source_file.write_text('line 1\nline 2\nline 3\n', encoding='utf-8')

    testcase_dir = tmp_path / 'signatures' / 'CASE001'
    testcase_dir.mkdir(parents=True)
    (testcase_dir / 'b2b.json').write_text(
        json.dumps(
            {
                'file': str(source_file),
                'bug_trace': [
                    [{'filename': str(source_file), 'line_number': 1}],
                    [
                        {'filename': str(source_file), 'line_number': 2},
                        {'filename': str(source_file), 'line_number': 2},
                        {'filename': str(source_file), 'line_number': 3},
                    ],
                ],
            }
        ),
        encoding='utf-8',
    )

    slice_dir = tmp_path / 'out' / 'slice'
    summary = module.process_signature_db(
        signature_db_dir=tmp_path / 'signatures',
        slice_dir=slice_dir,
        old_prefix=None,
        new_prefix=None,
    )

    assert summary['total_slices'] == 1
    assert summary['counts']['generated'] == 1

    generated_files = list(slice_dir.iterdir())
    assert len(generated_files) == 1
    assert generated_files[0].name == 'slice_CASE001_b2b.c'
    assert generated_files[0].read_text(encoding='utf-8') == 'line 2\nline 3\n'


def test_generate_slices_merges_summary_metadata_without_overriding_core_keys(tmp_path):
    module = load_module_from_path(
        'test_stage06_slices_metadata',
        REPO_ROOT / 'tools/stage/stage06_slices.py',
    )

    source_file = tmp_path / 'sample.c'
    source_file.write_text('line 1\n', encoding='utf-8')

    testcase_dir = tmp_path / 'signatures' / 'CASE001'
    testcase_dir.mkdir(parents=True)
    (testcase_dir / 'b2b.json').write_text(
        json.dumps(
            {
                'file': str(source_file),
                'bug_trace': [{'filename': str(source_file), 'line_number': 1}],
            }
        ),
        encoding='utf-8',
    )

    output_dir = tmp_path / 'out'
    summary = module.generate_slices(
        signature_db_dir=tmp_path / 'signatures',
        output_dir=output_dir,
        run_dir=tmp_path / 'run',
        summary_metadata={
            'dataset_basename': 'train_patched_counterparts',
            'slice_dir': 'should-not-override',
            'total_slices': 999,
        },
    )

    assert summary['dataset_basename'] == 'train_patched_counterparts'
    assert summary['slice_dir'] == str(output_dir / 'slice')
    assert summary['total_slices'] == 1
