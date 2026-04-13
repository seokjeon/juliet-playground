from __future__ import annotations

import csv

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_load_manual_line_truth_csv_normalizes_compact_rows(tmp_path):
    module = load_module_from_path(
        'test_shared_external_inputs',
        REPO_ROOT / 'tools/shared/external_inputs.py',
    )

    source_root = tmp_path / 'project'
    write_text(source_root / 'src' / 'manager.c', 'int main(void) { return 0; }\n')
    csv_path = tmp_path / 'manual_line_truth.csv'
    with csv_path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['testcase_key', 'file_path', 'line_number', 'label', 'note'])
        writer.writerow(
            [
                'demo-case',
                str(source_root / 'src' / 'manager.c'),
                '1187,609,486',
                '1',
                'confirmed vulnerable line',
            ]
        )

    records = module.load_manual_line_truth_csv(csv_path, source_root=source_root)

    assert [(record.file_path, record.line_number, record.label) for record in records] == [
        ('src/manager.c', 1187, 'vuln'),
        ('src/manager.c', 609, 'vuln'),
        ('src/manager.c', 486, 'vuln'),
    ]


def test_load_build_targets_csv_requires_unique_testcase_keys(tmp_path):
    module = load_module_from_path(
        'test_shared_external_inputs_build_targets',
        REPO_ROOT / 'tools/shared/external_inputs.py',
    )

    csv_path = tmp_path / 'build_targets.csv'
    with csv_path.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['testcase_key', 'workdir', 'build_command'])
        writer.writerow(['demo', str(tmp_path), 'make clean && make -j1'])
        writer.writerow(['demo', str(tmp_path), 'make -j1'])

    try:
        module.load_build_targets_csv(csv_path)
    except ValueError as exc:
        assert 'Duplicate testcase_key' in str(exc)
    else:
        raise AssertionError('Expected duplicate testcase_key validation to fail')


def test_load_build_targets_csv_resolves_relative_workdir_from_real_csv_path(tmp_path):
    module = load_module_from_path(
        'test_shared_external_inputs_relative_workdir',
        REPO_ROOT / 'tools/shared/external_inputs.py',
    )

    case_dir = tmp_path / 'cases' / 'CVE-2099-0001' / 'vulnerable'
    repo_dir = case_dir / 'repo'
    repo_dir.mkdir(parents=True, exist_ok=True)

    inputs_dir = case_dir / 'runs' / 'inputs'
    inputs_dir.mkdir(parents=True, exist_ok=True)
    base_csv = inputs_dir / 'build_targets.csv'
    with base_csv.open('w', encoding='utf-8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['testcase_key', 'workdir', 'build_command'])
        writer.writerow(['demo', '../../repo', 'make -j1'])

    run_dir = case_dir / 'runs' / 'run-001'
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / 'build_targets.csv').symlink_to('../inputs/build_targets.csv')

    targets = module.load_build_targets_csv(run_dir / 'build_targets.csv')

    assert len(targets) == 1
    assert targets[0].workdir == repo_dir.resolve()
