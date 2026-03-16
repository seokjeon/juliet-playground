from __future__ import annotations

import os

import pytest
from shared.pipeline_runs import find_latest_pipeline_run_dir, find_latest_prefixed_dir

from tests.helpers import REPO_ROOT, load_module_from_path


def test_find_latest_prefixed_dir_selects_newest_match(tmp_path):
    older = tmp_path / 'run-old'
    newer = tmp_path / 'run-new'
    other = tmp_path / 'misc'
    older.mkdir()
    newer.mkdir()
    other.mkdir()
    os.utime(older, (1, 1))
    os.utime(newer, (2, 2))

    assert find_latest_prefixed_dir(tmp_path, 'run-') == newer


def test_find_latest_pipeline_run_dir_preserves_missing_root_error(tmp_path):
    with pytest.raises(FileNotFoundError, match='Pipeline root not found'):
        find_latest_pipeline_run_dir(tmp_path / 'missing')


def test_find_latest_infer_run_dir_uses_shared_prefix_helper(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_stage03_signature_pipeline_runs',
        REPO_ROOT / 'tools/stage/stage03_signature.py',
    )

    expected = tmp_path / 'infer-demo'
    captured: dict[str, object] = {}

    def fake_find_latest_prefixed_dir(root_dir, prefix):
        captured['root_dir'] = root_dir
        captured['prefix'] = prefix
        return expected

    monkeypatch.setattr(module, 'find_latest_prefixed_dir', fake_find_latest_prefixed_dir)

    assert module.find_latest_infer_run_dir(tmp_path) == expected
    assert captured == {'root_dir': tmp_path, 'prefix': 'infer-'}


def test_find_latest_infer_run_dir_converts_missing_dir_to_bad_parameter(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_stage03_signature_bad_parameter',
        REPO_ROOT / 'tools/stage/stage03_signature.py',
    )

    def fake_find_latest_prefixed_dir(_root_dir, _prefix):
        raise FileNotFoundError('No infer-* directory found under: demo')

    monkeypatch.setattr(module, 'find_latest_prefixed_dir', fake_find_latest_prefixed_dir)

    with pytest.raises(module.typer.BadParameter, match='No infer-\\* directory found under: demo'):
        module.find_latest_infer_run_dir(tmp_path)
