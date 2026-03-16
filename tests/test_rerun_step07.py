from __future__ import annotations

import json

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_json


def test_main_runs_both_steps_by_default_and_writes_metadata(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_rerun_step07_main_default',
        REPO_ROOT / 'tools/stage/rerun_step07.py',
    )

    run_dir = tmp_path / 'run'
    run_dir.mkdir()
    calls: dict[str, dict[str, object]] = {}

    monkeypatch.setattr(module, 'now_ts_compact', lambda: '20260313_120000')
    monkeypatch.setattr(module, 'now_iso_utc', lambda: '2026-03-13T00:00:00+00:00')

    def fake_step07(**kwargs):
        calls['step07'] = kwargs
        kwargs['output_dir'].mkdir(parents=True, exist_ok=True)
        return {'summary_json': str(kwargs['output_dir'] / 'summary.json')}

    def fake_step07b(**kwargs):
        calls['step07b'] = kwargs
        return {
            'summary_json': str(
                kwargs['dataset_export_dir'] / 'train_patched_counterparts_summary.json'
            )
        }

    monkeypatch.setattr(module, 'rerun_step07', fake_step07)
    monkeypatch.setattr(module, 'rerun_step07b', fake_step07b)

    assert run_module_main(module, ['--run-dir', str(run_dir)]) == 0

    expected_output_dir = run_dir / '07_dataset_export_20260313_120000'
    metadata = json.loads(
        (expected_output_dir / 'rerun_step07_metadata.json').read_text(encoding='utf-8')
    )
    assert metadata['ran_step07'] is True
    assert metadata['ran_step07b'] is True
    assert calls['step07']['output_dir'] == expected_output_dir
    assert calls['step07b']['dataset_export_dir'] == expected_output_dir
    assert calls['step07b']['run_suffix'] == '20260313_120000'


def test_main_only_07_skips_step07b(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_rerun_step07_only07',
        REPO_ROOT / 'tools/stage/rerun_step07.py',
    )

    run_dir = tmp_path / 'run'
    run_dir.mkdir()
    called = {'step07': False, 'step07b': False}

    monkeypatch.setattr(module, 'now_ts_compact', lambda: '20260313_130000')
    monkeypatch.setattr(module, 'now_iso_utc', lambda: '2026-03-13T01:00:00+00:00')

    def fake_step07(**kwargs):
        called['step07'] = True
        kwargs['output_dir'].mkdir(parents=True, exist_ok=True)
        return {'summary_json': str(kwargs['output_dir'] / 'summary.json')}

    def fake_step07b(**_kwargs):
        called['step07b'] = True
        raise AssertionError('step07b should not run for --only-07')

    monkeypatch.setattr(module, 'rerun_step07', fake_step07)
    monkeypatch.setattr(module, 'rerun_step07b', fake_step07b)

    assert run_module_main(module, ['--run-dir', str(run_dir), '--only-07']) == 0
    assert called == {'step07': True, 'step07b': False}


def test_main_only_07b_uses_existing_output_dir(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_rerun_step07_only07b',
        REPO_ROOT / 'tools/stage/rerun_step07.py',
    )

    run_dir = tmp_path / 'run'
    output_dir = run_dir / '07_dataset_export'
    output_dir.mkdir(parents=True)
    write_json(output_dir / 'summary.json', {'ok': True})
    write_json(output_dir / 'split_manifest.json', {'pair_ids': {'train_val': [], 'test': []}})

    called: dict[str, object] = {}
    monkeypatch.setattr(module, 'now_ts_compact', lambda: '20260313_140000')
    monkeypatch.setattr(module, 'now_iso_utc', lambda: '2026-03-13T02:00:00+00:00')

    def fake_step07(**_kwargs):
        raise AssertionError('step07 should not run for --only-07b')

    def fake_step07b(**kwargs):
        called.update(kwargs)
        return {
            'summary_json': str(
                kwargs['dataset_export_dir'] / 'train_patched_counterparts_summary.json'
            )
        }

    monkeypatch.setattr(module, 'rerun_step07', fake_step07)
    monkeypatch.setattr(module, 'rerun_step07b', fake_step07b)

    assert run_module_main(module, ['--run-dir', str(run_dir), '--only-07b']) == 0
    assert called['dataset_export_dir'] == output_dir
    assert called['run_suffix'] == '20260313_140000'


def test_rerun_step07b_passes_prefix_args_and_overwrite_to_subprocess(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_rerun_step07_subprocess',
        REPO_ROOT / 'tools/stage/rerun_step07.py',
    )

    captured: dict[str, object] = {}

    class Proc:
        returncode = 0

    def fake_run(cmd, cwd):
        captured['cmd'] = cmd
        captured['cwd'] = cwd
        return Proc()

    monkeypatch.setattr(module.subprocess, 'run', fake_run)

    run_dir = tmp_path / 'run'
    dataset_export_dir = tmp_path / '07_dataset_export_custom'
    result = module.rerun_step07b(
        run_dir=run_dir,
        dataset_export_dir=dataset_export_dir,
        run_suffix='suffix123',
        dedup_mode='none',
        overwrite=True,
        old_prefix='/old/root',
        new_prefix='/new/root',
    )

    cmd = captured['cmd']
    assert '--overwrite' in cmd
    assert ['--old-prefix', '/old/root', '--new-prefix', '/new/root'] == cmd[-4:]
    assert str(
        run_dir / '05_pair_trace_ds' / 'train_patched_counterparts_pairs_suffix123.jsonl'
    ) == str(result['output_pairs_jsonl'])
    assert (
        str(run_dir / '06_slices' / 'train_patched_counterparts_suffix123')
        == result['slice_output_dir']
    )


def test_rerun_step07_raises_if_export_returns_non_dict(tmp_path, monkeypatch):
    module = load_module_from_path(
        'test_rerun_step07_non_dict',
        REPO_ROOT / 'tools/stage/rerun_step07.py',
    )

    run_dir = tmp_path / 'run'
    run_dir.mkdir()
    pairs_jsonl = run_dir / '05_pair_trace_ds' / 'pairs.jsonl'
    paired_signatures_dir = run_dir / '05_pair_trace_ds' / 'paired_signatures'
    slice_dir = run_dir / '06_slices' / 'slice'
    pairs_jsonl.parent.mkdir(parents=True, exist_ok=True)
    paired_signatures_dir.mkdir(parents=True, exist_ok=True)
    slice_dir.mkdir(parents=True, exist_ok=True)
    pairs_jsonl.write_text('', encoding='utf-8')

    monkeypatch.setattr(
        module,
        'choose_run_config',
        lambda _run_dir: {
            'pairs_jsonl': pairs_jsonl,
            'paired_signatures_dir': paired_signatures_dir,
            'slice_dir': slice_dir,
            'split_seed': 999,
            'train_ratio': 0.75,
        },
    )

    class FakePipelineModule:
        def export_dataset_from_pipeline(self, **kwargs):
            return 'not-a-dict'

    monkeypatch.setattr(module, 'load_module', lambda *_args, **_kwargs: FakePipelineModule())

    with pytest.raises(ValueError, match='non-dict'):
        module.rerun_step07(
            run_dir=run_dir,
            output_dir=tmp_path / 'rerun-out',
            dedup_mode='row',
            overwrite=False,
        )
