from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable


def load_json(path: Path) -> dict[str, Any]:
    with path.open('r', encoding='utf-8') as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError(f'Expected JSON object: {path}')
    return payload


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError(f'Expected JSON object at line {lineno} in {path}')
            records.append(obj)
    return records


def write_json(
    path: Path,
    payload: Any,
    *,
    indent: int = 2,
    ensure_ascii: bool = False,
    trailing_newline: bool = True,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, ensure_ascii=ensure_ascii, indent=indent)
    if trailing_newline:
        text += '\n'
    path.write_text(text, encoding='utf-8')


def write_summary_json(
    path: Path,
    payload: dict[str, Any],
    *,
    echo: bool = True,
    ensure_ascii: bool = False,
) -> None:
    write_json(path, payload, ensure_ascii=ensure_ascii)
    if echo:
        print(json.dumps(payload, ensure_ascii=ensure_ascii))


def write_jsonl(
    path: Path,
    rows: Iterable[dict[str, Any]],
    *,
    ensure_ascii: bool = False,
    trailing_newline: bool = True,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    iterator = iter(rows)
    try:
        first_row = next(iterator)
    except StopIteration:
        path.write_text('', encoding='utf-8')
        return

    with path.open('w', encoding='utf-8') as f:
        f.write(json.dumps(first_row, ensure_ascii=ensure_ascii))
        for row in iterator:
            f.write('\n')
            f.write(json.dumps(row, ensure_ascii=ensure_ascii))
        if trailing_newline:
            f.write('\n')
