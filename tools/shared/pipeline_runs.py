from __future__ import annotations

from pathlib import Path


def find_latest_prefixed_dir(root_dir: Path, prefix: str) -> Path:
    candidates = [p for p in root_dir.iterdir() if p.is_dir() and p.name.startswith(prefix)]
    latest = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if latest is None:
        raise FileNotFoundError(f'No {prefix}* directories found under: {root_dir}')
    return latest


def find_latest_pipeline_run_dir(pipeline_root: Path) -> Path:
    if not pipeline_root.exists():
        raise FileNotFoundError(f'Pipeline root not found: {pipeline_root}')
    return find_latest_prefixed_dir(pipeline_root, 'run-')
