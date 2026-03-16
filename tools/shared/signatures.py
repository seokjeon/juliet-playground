from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_signature_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f'Signature JSON not found: {path}')
    with path.open('r', encoding='utf-8') as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError(f'Signature JSON must be an object: {path}')
    return payload


def stable_trace_ref(path: Path | str) -> str:
    raw = str(path or '').strip()
    if not raw:
        return ''

    candidate = Path(raw)
    parent_name = candidate.parent.name.strip()
    file_name = candidate.name.strip()
    if parent_name and file_name:
        return f'{parent_name}/{file_name}'
    if file_name:
        return file_name
    return raw


def stable_signature_ref(payload: dict[str, Any], trace_file: Path | str) -> str:
    signature_hash = str(payload.get('hash') or '').strip()
    if signature_hash:
        return f'hash:{signature_hash}'

    signature_key = str(payload.get('key') or '').strip()
    if signature_key:
        return f'key:{signature_key}'

    trace_ref = stable_trace_ref(trace_file)
    if trace_ref:
        return f'trace:{trace_ref}'
    return 'trace:'
