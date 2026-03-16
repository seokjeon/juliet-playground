from __future__ import annotations

from pathlib import Path


def find_latest_pipeline_run_dir(pipeline_root: Path) -> Path:
    if not pipeline_root.exists():
        raise FileNotFoundError(f'Pipeline root not found: {pipeline_root}')
    candidates = [p for p in pipeline_root.iterdir() if p.is_dir() and p.name.startswith('run-')]
    latest = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if latest is None:
        raise FileNotFoundError(f'No run-* directories found under: {pipeline_root}')
    return latest
