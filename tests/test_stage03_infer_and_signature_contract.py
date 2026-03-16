from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path


def test_stage03_infer_and_signature_contract(monkeypatch, tmp_path):
    module = load_module_from_path(
        'test_stage03_infer_contract',
        REPO_ROOT / 'tools/stage/stage03_infer.py',
    )

    pulse_taint_config = tmp_path / 'pulse-taint-config.json'
    pulse_taint_config.write_text('{}\n', encoding='utf-8')

    infer_results_root = tmp_path / 'infer-results'
    signatures_root = tmp_path / 'signatures'
    summary_json = tmp_path / '03_infer_summary.json'

    def fake_run_infer_for_files(files: list[str], result_dir: str, pulse_config: str):
        assert files == ['demo.c']
        assert pulse_config == str(pulse_taint_config.resolve())
        return {
            'issue': 1,
            'no_issue': 1,
            'error': 0,
            'no_issue_files': ['demo-no-issue.c'],
            'time': 1.25,
        }

    def fake_generate_signatures(*, input_dir: Path, output_root: Path, infer_run_name: str):
        output_dir = output_root / infer_run_name / 'signature-contract'
        testcase_dir = output_dir / 'non_empty' / 'CASE_DEMO'
        testcase_dir.mkdir(parents=True, exist_ok=True)
        (testcase_dir / '1.json').write_text(
            json.dumps(
                {
                    'file': 'demo.c',
                    'line': 10,
                    'procedure': 'bad',
                    'bug_trace': [{'filename': 'demo.c', 'line_number': 10}],
                },
                ensure_ascii=False,
                indent=2,
            )
            + '\n',
            encoding='utf-8',
        )
        return output_dir

    monkeypatch.setattr(module, 'run_infer_for_files', fake_run_infer_for_files)
    monkeypatch.setattr(module, 'generate_signatures', fake_generate_signatures)

    result = module.main(
        cwes=None,
        global_result=False,
        all_cwes=False,
        files=['demo.c'],
        pulse_taint_config=pulse_taint_config,
        infer_results_root=infer_results_root,
        signatures_root=signatures_root,
        summary_json=summary_json,
    )

    assert result is None
    assert summary_json.exists()

    summary = json.loads(summary_json.read_text(encoding='utf-8'))
    required_keys = {
        'infer_run_dir',
        'signature_output_dir',
        'signature_non_empty_dir',
        'analysis_result_csv',
        'analysis_no_issue_files',
        'result_by_target',
        'totals',
    }
    assert required_keys.issubset(summary.keys())

    signature_non_empty_dir = Path(summary['signature_non_empty_dir'])
    assert signature_non_empty_dir.exists()
    assert any(signature_non_empty_dir.rglob('*.json'))

    assert Path(summary['analysis_result_csv']).exists()
    assert Path(summary['analysis_no_issue_files']).exists()

    totals = summary['totals']
    assert set(totals) == {'issue', 'no_issue', 'error', 'total_cases', 'elapsed_seconds'}
    assert totals['issue'] == 1
    assert totals['no_issue'] == 1
    assert totals['error'] == 0
    assert totals['total_cases'] == 2

    result_by_target = summary['result_by_target']
    assert set(result_by_target) == {'FILES'}
    assert result_by_target['FILES'] == {
        'issue': 1,
        'no_issue': 1,
        'error': 0,
        'time': 1.25,
        'total_cases': 2,
    }
