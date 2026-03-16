from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


def test_parse_case_group_accepts_valid_juliet_filename():
    module = load_module_from_path(
        'test_stage03_infer_parse_case_group',
        REPO_ROOT / 'tools/stage/stage03_infer.py',
    )

    parsed = module.parse_case_group('/tmp/CWE78_OS_Command_Injection__char_console_execlp_52a.c')

    assert parsed is not None
    group_key, cwe_dir, filename_head, flow_variant_id, extension = parsed
    assert group_key == (
        '/tmp',
        '78',
        'OS_Command_Injection',
        'char_console_execlp',
        '52',
        'c',
    )
    assert cwe_dir == 'CWE78'
    assert filename_head == 'CWE78_OS_Command_Injection__char_console_execlp'
    assert flow_variant_id == '52'
    assert extension == 'c'


def test_parse_case_group_rejects_non_juliet_filename():
    module = load_module_from_path(
        'test_stage03_infer_parse_case_group_invalid',
        REPO_ROOT / 'tools/stage/stage03_infer.py',
    )

    assert module.parse_case_group('/tmp/not_a_juliet_case.c') is None
