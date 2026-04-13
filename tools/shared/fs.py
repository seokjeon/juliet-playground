from __future__ import annotations

import shutil
from pathlib import Path


def remove_target(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def prepare_target(path: Path, overwrite: bool) -> None:
    if path.exists() or path.is_symlink():
        if not overwrite:
            raise FileExistsError(
                f'Target already exists: {path}. Re-run with --overwrite to replace it.'
            )
        remove_target(path)


def prepare_output_dir(output_dir: Path, overwrite: bool) -> None:
    if output_dir.is_symlink():
        if not overwrite:
            raise FileExistsError(
                f'Output directory already exists and is not empty: {output_dir}. '
                f'Re-run with --overwrite to replace its contents.'
            )
        output_dir.unlink()
    elif output_dir.exists():
        if not overwrite:
            existing = list(output_dir.iterdir())
            if existing:
                raise FileExistsError(
                    f'Output directory already exists and is not empty: {output_dir}. '
                    f'Re-run with --overwrite to replace its contents.'
                )
        else:
            shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
