from __future__ import annotations

import re
from pathlib import Path

TESTCASE_KEY_RE = re.compile(r'^(CWE\d+)_([A-Za-z0-9_]+)_(\d+)([a-zA-Z]?)$')


def derive_testcase_key_from_file_name(file_name: str) -> str | None:
    stem = Path(file_name).stem
    m = TESTCASE_KEY_RE.match(stem)
    if not m:
        return None
    cwe, body, num, _letter = m.groups()
    return f'{cwe}_{num}-{cwe}_{body}'
