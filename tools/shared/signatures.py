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
