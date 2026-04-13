from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def _make_case_layout(
    tmp_path: Path,
    *,
    create_run_dir: bool = True,
    include_inputs_pulse_taint_config: bool = False,
) -> Path:
    case_dir = tmp_path / 'cases' / 'demo-project__CVE-2099-0001'
    vulnerable_dir = case_dir / 'vulnerable'
    repo_dir = vulnerable_dir / 'repo'
    repo_dir.mkdir(parents=True, exist_ok=True)
    write_text(
        repo_dir / '.git' / 'config',
        '[remote "origin"]\n\turl = https://github.com/example/demo-project.git\n',
    )

    inputs_dir = vulnerable_dir / 'runs' / 'inputs'
    write_text(
        inputs_dir / 'build_targets.csv',
        'testcase_key,workdir,build_command\ndemo,../../repo,"make clean && make -j1"\n',
    )
    write_text(
        inputs_dir / 'manual_line_truth.csv',
        'testcase_key,file_path,line_number,label,note\n'
        'demo,src/demo.c,1187,vuln,confirmed vulnerable line\n',
    )
    if include_inputs_pulse_taint_config:
        write_text(inputs_dir / 'pulse-taint-config.json', '{"base": true}\n')

    if create_run_dir:
        run_dir = vulnerable_dir / 'runs' / 'run-001'
        run_dir.mkdir(parents=True, exist_ok=True)
        (run_dir / 'build_targets.csv').symlink_to('../inputs/build_targets.csv')
        write_text(run_dir / 'manual_line_truth.csv', 'stale manual truth\n')
        write_text(run_dir / 'pulse-taint-config.json', '{}\n')
    return case_dir


def test_run_case_overwrites_existing_run_inputs_from_canonical_inputs(
    monkeypatch, tmp_path, capsys
):
    module = load_module_from_path('test_run_case', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(tmp_path, include_inputs_pulse_taint_config=True)
    expected_outputs_dir = case_dir / 'vulnerable' / 'runs' / 'run-001' / 'outputs'

    calls: list[dict[str, object]] = []

    def fake_run_external_trace_pipeline(args):
        calls.append(
            {
                'source_root': args.source_root,
                'build_targets': args.build_targets,
                'manual_line_truth': args.manual_line_truth,
                'pulse_taint_config': args.pulse_taint_config,
                'output_root': args.output_root,
                'run_id': args.run_id,
                'project_name': args.project_name,
                'infer_jobs': args.infer_jobs,
                'overwrite': args.overwrite,
            }
        )
        (args.output_root / args.run_id).mkdir(parents=True, exist_ok=True)
        return 0

    monkeypatch.setattr(
        module._run_external_trace_pipeline,
        'run_external_trace_pipeline',
        fake_run_external_trace_pipeline,
    )

    result = run_module_main(
        module,
        [
            '--case',
            str(case_dir),
            '--track',
            'vulnerable',
            '--run',
            'run-001',
        ],
    )

    assert result == 0
    assert calls == [
        {
            'source_root': case_dir / 'vulnerable' / 'repo',
            'build_targets': case_dir / 'vulnerable' / 'runs' / 'run-001' / 'build_targets.csv',
            'manual_line_truth': case_dir
            / 'vulnerable'
            / 'runs'
            / 'run-001'
            / 'manual_line_truth.csv',
            'pulse_taint_config': case_dir
            / 'vulnerable'
            / 'runs'
            / 'run-001'
            / 'pulse-taint-config.json',
            'output_root': case_dir / 'vulnerable' / 'runs' / 'run-001',
            'run_id': 'outputs',
            'project_name': 'demo-project',
            'infer_jobs': 1,
            'overwrite': False,
        }
    ]

    run_dir = case_dir / 'vulnerable' / 'runs' / 'run-001'
    assert (run_dir / 'build_targets.csv').read_text(encoding='utf-8') == (
        case_dir / 'vulnerable' / 'runs' / 'inputs' / 'build_targets.csv'
    ).read_text(encoding='utf-8')
    assert not (run_dir / 'build_targets.csv').is_symlink()
    assert (run_dir / 'manual_line_truth.csv').read_text(encoding='utf-8') == (
        case_dir / 'vulnerable' / 'runs' / 'inputs' / 'manual_line_truth.csv'
    ).read_text(encoding='utf-8')
    assert not (run_dir / 'manual_line_truth.csv').is_symlink()
    assert (run_dir / 'pulse-taint-config.json').read_text(encoding='utf-8') == '{"base": true}\n'

    assert expected_outputs_dir.exists()
    assert expected_outputs_dir.is_dir()
    assert not expected_outputs_dir.is_symlink()

    captured = capsys.readouterr()
    assert 'Case run completed: demo-project__CVE-2099-0001/vulnerable/run-001' in captured.out


def test_run_case_bootstraps_missing_run_dir_from_inputs(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_case_bootstrap', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(
        tmp_path,
        create_run_dir=False,
        include_inputs_pulse_taint_config=True,
    )

    calls: list[dict[str, object]] = []

    def fake_run_external_trace_pipeline(args):
        calls.append(
            {
                'build_targets': args.build_targets,
                'manual_line_truth': args.manual_line_truth,
                'pulse_taint_config': args.pulse_taint_config,
                'output_root': args.output_root,
                'run_id': args.run_id,
                'infer_jobs': args.infer_jobs,
            }
        )
        (args.output_root / args.run_id).mkdir(parents=True, exist_ok=True)
        return 0

    monkeypatch.setattr(
        module._run_external_trace_pipeline,
        'run_external_trace_pipeline',
        fake_run_external_trace_pipeline,
    )

    result = run_module_main(
        module,
        [
            '--case',
            str(case_dir),
            '--track',
            'vulnerable',
            '--run',
            'run-001',
        ],
    )

    assert result == 0
    run_dir = case_dir / 'vulnerable' / 'runs' / 'run-001'
    build_targets = run_dir / 'build_targets.csv'
    manual_line_truth = run_dir / 'manual_line_truth.csv'
    pulse_taint_config = run_dir / 'pulse-taint-config.json'

    assert build_targets.exists()
    assert not build_targets.is_symlink()
    assert build_targets.read_text(encoding='utf-8') == (
        case_dir / 'vulnerable' / 'runs' / 'inputs' / 'build_targets.csv'
    ).read_text(encoding='utf-8')

    assert manual_line_truth.exists()
    assert not manual_line_truth.is_symlink()
    assert manual_line_truth.read_text(encoding='utf-8') == (
        case_dir / 'vulnerable' / 'runs' / 'inputs' / 'manual_line_truth.csv'
    ).read_text(encoding='utf-8')

    assert pulse_taint_config.exists()
    assert not pulse_taint_config.is_symlink()
    assert pulse_taint_config.read_text(encoding='utf-8') == '{"base": true}\n'

    assert calls == [
        {
            'build_targets': build_targets,
            'manual_line_truth': manual_line_truth,
            'pulse_taint_config': pulse_taint_config,
            'output_root': run_dir,
            'run_id': 'outputs',
            'infer_jobs': 1,
        }
    ]
    assert (run_dir / 'outputs').exists()
    assert not (run_dir / 'outputs').is_symlink()


def test_run_case_removed_input_override_flags_are_rejected(tmp_path):
    module = load_module_from_path('test_run_case_removed_flags', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(
        tmp_path,
        create_run_dir=False,
        include_inputs_pulse_taint_config=True,
    )

    for option in [
        '--build-targets',
        '--manual-line-truth',
        '--pulse-taint-config',
    ]:
        with pytest.raises(SystemExit):
            run_module_main(
                module,
                [
                    '--case',
                    str(case_dir),
                    '--track',
                    'vulnerable',
                    '--run',
                    'run-001',
                    option,
                    'dummy',
                ],
            )


def test_run_case_keeps_partial_outputs_directory_on_failure(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_case_failure_outputs', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(
        tmp_path,
        create_run_dir=False,
        include_inputs_pulse_taint_config=True,
    )

    def fake_run_external_trace_pipeline(args):
        outputs_dir = args.output_root / args.run_id
        outputs_dir.mkdir(parents=True, exist_ok=True)
        write_text(outputs_dir / 'partial.txt', 'partial\n')
        raise RuntimeError('boom')

    monkeypatch.setattr(
        module._run_external_trace_pipeline,
        'run_external_trace_pipeline',
        fake_run_external_trace_pipeline,
    )

    result = run_module_main(
        module,
        [
            '--case',
            str(case_dir),
            '--track',
            'vulnerable',
            '--run',
            'run-001',
        ],
    )

    outputs_dir = case_dir / 'vulnerable' / 'runs' / 'run-001' / 'outputs'
    assert result == 1
    assert outputs_dir.exists()
    assert outputs_dir.is_dir()
    assert not outputs_dir.is_symlink()
    assert (outputs_dir / 'partial.txt').read_text(encoding='utf-8') == 'partial\n'


def test_run_case_passes_custom_infer_jobs(monkeypatch, tmp_path):
    module = load_module_from_path('test_run_case_custom_jobs', REPO_ROOT / 'tools/run_case.py')
    case_dir = _make_case_layout(
        tmp_path,
        create_run_dir=False,
        include_inputs_pulse_taint_config=True,
    )

    calls: list[dict[str, object]] = []

    def fake_run_external_trace_pipeline(args):
        calls.append({'infer_jobs': args.infer_jobs})
        (args.output_root / args.run_id).mkdir(parents=True, exist_ok=True)
        return 0

    monkeypatch.setattr(
        module._run_external_trace_pipeline,
        'run_external_trace_pipeline',
        fake_run_external_trace_pipeline,
    )

    result = run_module_main(
        module,
        [
            '--case',
            str(case_dir),
            '--track',
            'vulnerable',
            '--run',
            'run-001',
            '--infer-jobs',
            '8',
        ],
    )

    assert result == 0
    assert calls == [{'infer_jobs': 8}]


def test_run_case_fails_when_canonical_inputs_are_incomplete(tmp_path):
    module = load_module_from_path(
        'test_run_case_missing_inputs',
        REPO_ROOT / 'tools/run_case.py',
    )
    case_dir = _make_case_layout(tmp_path, create_run_dir=False)

    result = run_module_main(
        module,
        [
            '--case',
            str(case_dir),
            '--track',
            'vulnerable',
            '--run',
            'run-001',
        ],
    )

    assert result == 2
