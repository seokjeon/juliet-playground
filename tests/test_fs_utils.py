from __future__ import annotations

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_prepare_target_raises_without_overwrite_for_existing_file(tmp_path):
    module = load_module_from_path('test_fs_utils_raise', REPO_ROOT / 'tools/shared/fs.py')

    target = tmp_path / 'existing.txt'
    write_text(target, 'hello')

    with pytest.raises(FileExistsError):
        module.prepare_target(target, overwrite=False)


def test_prepare_target_replaces_file_and_directory_when_overwrite_enabled(tmp_path):
    module = load_module_from_path('test_fs_utils_replace', REPO_ROOT / 'tools/shared/fs.py')

    file_target = tmp_path / 'existing.txt'
    dir_target = tmp_path / 'existing-dir'
    write_text(file_target, 'hello')
    write_text(dir_target / 'child.txt', 'world')

    module.prepare_target(file_target, overwrite=True)
    module.prepare_target(dir_target, overwrite=True)

    assert not file_target.exists()
    assert not dir_target.exists()


def test_remove_target_handles_file_and_directory(tmp_path):
    module = load_module_from_path('test_fs_utils_remove', REPO_ROOT / 'tools/shared/fs.py')

    file_target = tmp_path / 'file.txt'
    dir_target = tmp_path / 'dir'
    write_text(file_target, 'hello')
    write_text(dir_target / 'child.txt', 'world')

    module.remove_target(file_target)
    module.remove_target(dir_target)

    assert not file_target.exists()
    assert not dir_target.exists()
