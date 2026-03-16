#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

import typer
from shared.paths import PROJECT_HOME, PULSE_TAINT_CONFIG, RESULT_DIR
from stage import pipeline as _pipeline_run

compute_pair_split = _pipeline_run.compute_pair_split
dedupe_pairs_by_normalized_rows = _pipeline_run.dedupe_pairs_by_normalized_rows
export_dataset_from_pipeline = _pipeline_run.export_dataset_from_pipeline


def main(
    cwes: Optional[List[int]] = typer.Argument(None),
    all_cwes: bool = typer.Option(
        False, '--all', help='Run the pipeline for all CWEs in the testcase directory'
    ),
    files: List[str] = typer.Option(
        [],
        '--files',
        help='Run infer for specific files (repeatable); if set, cwes and --all are ignored',
    ),
    manifest: Path = typer.Option(
        Path(PROJECT_HOME)
        / 'experiments'
        / 'epic001_manifest_comment_scan'
        / 'inputs'
        / 'manifest.xml',
        '--manifest',
        help='Input manifest.xml path',
    ),
    source_root: Path = typer.Option(
        Path(PROJECT_HOME) / 'juliet-test-suite-v1.3' / 'C',
        '--source-root',
        help='Juliet C source root',
    ),
    pipeline_root: Path = typer.Option(
        Path(RESULT_DIR) / 'pipeline-runs',
        '--pipeline-root',
        help='Root directory for pipeline runs',
    ),
    run_id: Optional[str] = typer.Option(
        None, '--run-id', help='Run id under pipeline root (default: run-<YYYY.MM.DD-HH:MM:SS>)'
    ),
    committed_taint_config: Path = typer.Option(
        Path(PULSE_TAINT_CONFIG),
        '--committed-taint-config',
        help='Committed taint config path for fallback/reference',
    ),
    pair_split_seed: int = typer.Option(
        1234, '--pair-split-seed', help='Random seed for pair-level train/test split'
    ),
    pair_train_ratio: float = typer.Option(
        0.8, '--pair-train-ratio', help='Train ratio for pair-level train/test split'
    ),
    dedup_mode: str = typer.Option(
        'row', '--dedup-mode', help='Normalized-slice dedup mode before split/export: none or row'
    ),
):
    return _pipeline_run.main(
        cwes=cwes,
        all_cwes=all_cwes,
        files=files,
        manifest=manifest,
        source_root=source_root,
        pipeline_root=pipeline_root,
        run_id=run_id,
        committed_taint_config=committed_taint_config,
        pair_split_seed=pair_split_seed,
        pair_train_ratio=pair_train_ratio,
        dedup_mode=dedup_mode,
    )


if __name__ == '__main__':
    typer.run(main)
