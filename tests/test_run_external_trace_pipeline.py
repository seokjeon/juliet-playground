from __future__ import annotations

from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text


def _make_inputs(tmp_path: Path) -> dict[str, Path]:
    source_root = tmp_path / 'demo-project' / 'raw_code'
    source_root.mkdir(parents=True, exist_ok=True)

    build_targets = tmp_path / 'build_targets.csv'
    build_targets.write_text(
        f'testcase_key,workdir,build_command\ncase1,{source_root},"make -j1"\n',
        encoding='utf-8',
    )

    manual_line_truth = tmp_path / 'manual_line_truth.csv'
    manual_line_truth.write_text(
        'testcase_key,file_path,line_number,label,note\n'
        f'case1,{source_root / "src" / "foo.c"},1187,vuln,confirmed vulnerable line\n',
        encoding='utf-8',
    )

    pulse_taint_config = tmp_path / 'pulse-taint-config.json'
    write_text(pulse_taint_config, '{}\n')

    return {
        'source_root': source_root,
        'build_targets': build_targets,
        'manual_line_truth': manual_line_truth,
        'pulse_taint_config': pulse_taint_config,
        'output_root': tmp_path / 'external-runs',
    }


def _install_stage_fakes(
    module,
    monkeypatch,
    expected_run_dir: Path,
    *,
    expected_infer_jobs: int = 1,
) -> list[str]:
    calls: list[str] = []

    def fake_run_external_infer_and_signature(**kwargs):
        calls.append('stage03')
        assert kwargs['infer_results_root'] == expected_run_dir / '03_infer-results'
        assert kwargs['signatures_root'] == expected_run_dir / '03_signatures'
        assert kwargs['summary_json'] == expected_run_dir / '03_infer_summary.json'
        assert kwargs['infer_jobs'] == expected_infer_jobs

        signature_non_empty_dir = (
            kwargs['signatures_root'] / 'infer-demo' / 'signature-demo' / 'non_empty'
        )
        signature_non_empty_dir.mkdir(parents=True, exist_ok=True)
        write_text(kwargs['summary_json'], '{}\n')
        return {
            'artifacts': {
                'signature_non_empty_dir': str(signature_non_empty_dir),
            },
            'stats': {'targets_total': 1},
        }

    def fake_filter_traces_by_manual_lines(**kwargs):
        calls.append('stage05')
        assert kwargs['signatures_dir'] == (
            expected_run_dir / '03_signatures' / 'infer-demo' / 'signature-demo' / 'non_empty'
        )
        assert kwargs['output_dir'] == expected_run_dir / '05b_manual_line_filter'

        traces_jsonl = kwargs['output_dir'] / 'traces.jsonl'
        write_text(traces_jsonl, '{"trace_id":"trace-1","trace_file":"trace.json"}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {
            'artifacts': {'traces_jsonl': str(traces_jsonl)},
            'stats': {'traces_kept': 1},
        }

    def fake_generate_trace_slices(**kwargs):
        calls.append('stage06')
        assert (
            kwargs['traces_jsonl'] == expected_run_dir / '05b_manual_line_filter' / 'traces.jsonl'
        )
        assert kwargs['output_dir'] == expected_run_dir / '06_trace_slices'

        slice_dir = kwargs['output_dir'] / 'slice'
        slice_dir.mkdir(parents=True, exist_ok=True)
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {
            'artifacts': {'slice_dir': str(slice_dir)},
            'stats': {'generated': 1},
        }

    def fake_export_external_test_dataset(**kwargs):
        calls.append('stage07')
        assert (
            kwargs['traces_jsonl'] == expected_run_dir / '05b_manual_line_filter' / 'traces.jsonl'
        )
        assert kwargs['slice_dir'] == expected_run_dir / '06_trace_slices' / 'slice'
        assert kwargs['output_dir'] == expected_run_dir / '07_dataset_export'
        assert kwargs['project_name'] == 'demo-project'

        normalized_slices_dir = kwargs['output_dir'] / 'normalized_slices'
        normalized_slices_dir.mkdir(parents=True, exist_ok=True)
        csv_path = kwargs['output_dir'] / 'Real_Vul_data.csv'
        manifest_path = kwargs['output_dir'] / 'trace_row_manifest.jsonl'
        write_text(csv_path, 'id,flaw_line,case_id\n1,1,demo\n')
        write_text(manifest_path, '{"row_id":1,"trace_id":"trace-1"}\n')
        write_text(kwargs['output_dir'] / 'summary.json', '{}\n')
        return {
            'artifacts': {
                'csv_path': str(csv_path),
                'trace_row_manifest_jsonl': str(manifest_path),
            },
            'stats': {'counts': {'rows_written': 1}},
        }

    monkeypatch.setattr(
        module._stage03_external_infer,
        'run_external_infer_and_signature',
        fake_run_external_infer_and_signature,
    )
    monkeypatch.setattr(
        module._stage05b_manual_line_filter,
        'filter_traces_by_manual_lines',
        fake_filter_traces_by_manual_lines,
    )
    monkeypatch.setattr(
        module._stage06_trace_slices,
        'generate_trace_slices',
        fake_generate_trace_slices,
    )
    monkeypatch.setattr(
        module._stage07_external_test_dataset_export,
        'export_external_test_dataset',
        fake_export_external_test_dataset,
    )
    return calls


def test_run_external_trace_pipeline_fresh_run(monkeypatch, tmp_path, capsys):
    module = load_module_from_path(
        'test_run_external_trace_pipeline_fresh',
        REPO_ROOT / 'tools/run_external_trace_pipeline.py',
    )
    inputs = _make_inputs(tmp_path)
    run_dir = inputs['output_root'] / 'run-fresh'
    calls = _install_stage_fakes(module, monkeypatch, run_dir)

    result = run_module_main(
        module,
        [
            '--source-root',
            str(inputs['source_root']),
            '--build-targets',
            str(inputs['build_targets']),
            '--manual-line-truth',
            str(inputs['manual_line_truth']),
            '--pulse-taint-config',
            str(inputs['pulse_taint_config']),
            '--output-root',
            str(inputs['output_root']),
            '--run-id',
            'run-fresh',
        ],
    )

    assert result == 0
    assert calls == ['stage03', 'stage05', 'stage06', 'stage07']
    assert (run_dir / '07_dataset_export' / 'Real_Vul_data.csv').exists()
    assert (run_dir / '07_dataset_export' / 'trace_row_manifest.jsonl').exists()

    captured = capsys.readouterr()
    assert f'External trace pipeline completed: {run_dir}' in captured.out
    assert str(run_dir / '07_dataset_export' / 'Real_Vul_data.csv') in captured.out


def test_run_external_trace_pipeline_requires_overwrite_for_existing_run_dir(
    monkeypatch, tmp_path, capsys
):
    module = load_module_from_path(
        'test_run_external_trace_pipeline_existing',
        REPO_ROOT / 'tools/run_external_trace_pipeline.py',
    )
    inputs = _make_inputs(tmp_path)
    run_dir = inputs['output_root'] / 'run-existing'
    write_text(run_dir / 'stale.txt', 'stale\n')

    def fail_if_called(**kwargs):  # pragma: no cover - safety assertion
        raise AssertionError(f'Unexpected stage call: {kwargs}')

    monkeypatch.setattr(
        module._stage03_external_infer,
        'run_external_infer_and_signature',
        fail_if_called,
    )

    result = run_module_main(
        module,
        [
            '--source-root',
            str(inputs['source_root']),
            '--build-targets',
            str(inputs['build_targets']),
            '--manual-line-truth',
            str(inputs['manual_line_truth']),
            '--pulse-taint-config',
            str(inputs['pulse_taint_config']),
            '--output-root',
            str(inputs['output_root']),
            '--run-id',
            'run-existing',
        ],
    )

    assert result == 2
    assert (run_dir / 'stale.txt').exists()

    captured = capsys.readouterr()
    assert 'Output directory already exists and is not empty' in captured.err
    assert 'Re-run with --overwrite to replace its contents' in captured.err


def test_run_external_trace_pipeline_overwrite_replaces_existing_run_dir(
    monkeypatch, tmp_path, capsys
):
    module = load_module_from_path(
        'test_run_external_trace_pipeline_overwrite',
        REPO_ROOT / 'tools/run_external_trace_pipeline.py',
    )
    inputs = _make_inputs(tmp_path)
    run_dir = inputs['output_root'] / 'run-overwrite'
    write_text(run_dir / 'stale.txt', 'stale\n')
    write_text(run_dir / '07_dataset_export' / 'normalized_slices' / 'old.c', 'old\n')
    calls = _install_stage_fakes(module, monkeypatch, run_dir)

    result = run_module_main(
        module,
        [
            '--source-root',
            str(inputs['source_root']),
            '--build-targets',
            str(inputs['build_targets']),
            '--manual-line-truth',
            str(inputs['manual_line_truth']),
            '--pulse-taint-config',
            str(inputs['pulse_taint_config']),
            '--output-root',
            str(inputs['output_root']),
            '--run-id',
            'run-overwrite',
            '--overwrite',
        ],
    )

    assert result == 0
    assert calls == ['stage03', 'stage05', 'stage06', 'stage07']
    assert not (run_dir / 'stale.txt').exists()
    assert not (run_dir / '07_dataset_export' / 'normalized_slices' / 'old.c').exists()
    assert (run_dir / '07_dataset_export' / 'Real_Vul_data.csv').exists()

    captured = capsys.readouterr()
    assert f'External trace pipeline completed: {run_dir}' in captured.out


def test_run_external_trace_pipeline_passes_custom_infer_jobs(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_run_external_trace_pipeline_custom_jobs',
        REPO_ROOT / 'tools/run_external_trace_pipeline.py',
    )
    inputs = _make_inputs(tmp_path)
    run_dir = inputs['output_root'] / 'run-custom-jobs'
    calls = _install_stage_fakes(
        module,
        monkeypatch,
        run_dir,
        expected_infer_jobs=8,
    )

    result = run_module_main(
        module,
        [
            '--source-root',
            str(inputs['source_root']),
            '--build-targets',
            str(inputs['build_targets']),
            '--manual-line-truth',
            str(inputs['manual_line_truth']),
            '--pulse-taint-config',
            str(inputs['pulse_taint_config']),
            '--output-root',
            str(inputs['output_root']),
            '--run-id',
            'run-custom-jobs',
            '--infer-jobs',
            '8',
        ],
    )

    assert result == 0
    assert calls == ['stage03', 'stage05', 'stage06', 'stage07']


def test_run_external_trace_pipeline_rejects_non_positive_infer_jobs(tmp_path, capsys):
    module = load_module_from_path(
        'test_run_external_trace_pipeline_invalid_jobs',
        REPO_ROOT / 'tools/run_external_trace_pipeline.py',
    )
    inputs = _make_inputs(tmp_path)

    result = run_module_main(
        module,
        [
            '--source-root',
            str(inputs['source_root']),
            '--build-targets',
            str(inputs['build_targets']),
            '--manual-line-truth',
            str(inputs['manual_line_truth']),
            '--pulse-taint-config',
            str(inputs['pulse_taint_config']),
            '--output-root',
            str(inputs['output_root']),
            '--run-id',
            'run-invalid-jobs',
            '--infer-jobs',
            '0',
        ],
    )

    assert result == 2
    captured = capsys.readouterr()
    assert '--infer-jobs must be >= 1' in captured.err


def test_run_external_trace_pipeline_overwrite_replaces_symlinked_run_dir(
    monkeypatch, tmp_path, capsys
):
    module = load_module_from_path(
        'test_run_external_trace_pipeline_symlink_overwrite',
        REPO_ROOT / 'tools/run_external_trace_pipeline.py',
    )
    inputs = _make_inputs(tmp_path)
    output_root = tmp_path / 'case-run'
    output_root.mkdir(parents=True, exist_ok=True)
    legacy_artifact_dir = tmp_path / 'legacy-artifact-run'
    write_text(legacy_artifact_dir / 'legacy.txt', 'legacy\n')
    run_dir = output_root / 'outputs'
    run_dir.symlink_to(legacy_artifact_dir, target_is_directory=True)
    calls = _install_stage_fakes(module, monkeypatch, run_dir)

    result = run_module_main(
        module,
        [
            '--source-root',
            str(inputs['source_root']),
            '--build-targets',
            str(inputs['build_targets']),
            '--manual-line-truth',
            str(inputs['manual_line_truth']),
            '--pulse-taint-config',
            str(inputs['pulse_taint_config']),
            '--output-root',
            str(output_root),
            '--run-id',
            'outputs',
            '--overwrite',
        ],
    )

    assert result == 0
    assert calls == ['stage03', 'stage05', 'stage06', 'stage07']
    assert run_dir.exists()
    assert run_dir.is_dir()
    assert not run_dir.is_symlink()
    assert (run_dir / '07_dataset_export' / 'Real_Vul_data.csv').exists()
    assert (legacy_artifact_dir / 'legacy.txt').read_text(encoding='utf-8') == 'legacy\n'

    captured = capsys.readouterr()
    assert f'External trace pipeline completed: {run_dir}' in captured.out
