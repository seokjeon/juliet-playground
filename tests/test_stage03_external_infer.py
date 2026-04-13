from __future__ import annotations

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path


def test_stage03_external_infer_builds_shell_wrapped_command(tmp_path):
    module = load_module_from_path(
        'test_stage03_external_infer',
        REPO_ROOT / 'tools/stage/stage03_external_infer.py',
    )
    pre_commands, infer_args = module.split_build_command('make clean && make -j22')

    command = module.build_infer_command(
        infer_args=infer_args,
        pulse_taint_config=tmp_path / 'pulse-taint-config.json',
        results_dir=tmp_path / 'infer-out',
        infer_jobs=1,
    )

    assert pre_commands == ['make clean']
    assert infer_args == ['make', '-j22']
    assert command[:10] == [
        module.INFER_BIN,
        'run',
        '-j',
        '1',
        '--keep-going',
        '--results-dir',
        str(tmp_path / 'infer-out'),
        '--force-delete-results-dir',
        '--pulse-taint-config',
        str(tmp_path / 'pulse-taint-config.json'),
    ]
    assert command[10:] == [
        '--',
        'make',
        '-j22',
    ]
    assert module._single_job_fallback_command('make clean && make -j22') == (
        'make clean && make -j1'
    )


def test_stage03_external_infer_builds_with_custom_infer_jobs(tmp_path):
    module = load_module_from_path(
        'test_stage03_external_infer_custom_jobs',
        REPO_ROOT / 'tools/stage/stage03_external_infer.py',
    )

    command = module.build_infer_command(
        infer_args=['make', '-j22'],
        pulse_taint_config=tmp_path / 'pulse-taint-config.json',
        results_dir=tmp_path / 'infer-out',
        infer_jobs=8,
    )

    assert command[:5] == [
        module.INFER_BIN,
        'run',
        '-j',
        '8',
        '--keep-going',
    ]


def test_stage03_external_infer_rejects_non_positive_infer_jobs(tmp_path):
    module = load_module_from_path(
        'test_stage03_external_infer_invalid_jobs',
        REPO_ROOT / 'tools/stage/stage03_external_infer.py',
    )

    with pytest.raises(ValueError, match='infer_jobs must be >= 1'):
        module.build_infer_command(
            infer_args=['make'],
            pulse_taint_config=tmp_path / 'pulse-taint-config.json',
            results_dir=tmp_path / 'infer-out',
            infer_jobs=0,
        )
