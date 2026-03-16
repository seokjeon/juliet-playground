#!/usr/bin/env python3
from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.artifact_layout import build_dataset_export_paths
from shared.dataset_export_core import run_step07_export_core, run_step07_export_wrapper
from shared.dataset_sources import build_source_file_candidates, collect_defined_function_names
from shared.jsonio import load_jsonl as _load_jsonl


@dataclass(frozen=True)
class PrimaryDatasetExportParams:
    pairs_jsonl: Path
    paired_signatures_dir: Path
    slice_dir: Path
    output_dir: Path
    split_seed: int
    train_ratio: float
    dedup_mode: str


@dataclass(frozen=True)
class PrimaryDatasetExportResult:
    summary_json: Path
    output_dir: Path
    normalized_slices_dir: Path
    real_vul_data_csv: Path
    dedup_dropped_csv: Path
    normalized_token_counts_csv: Path
    slice_token_distribution_png: Path
    split_manifest_json: Path

    def to_payload(self) -> dict[str, object]:
        return {
            'summary_json': str(self.summary_json),
            'output_dir': str(self.output_dir),
            'normalized_slices_dir': str(self.normalized_slices_dir),
            'real_vul_data_csv': str(self.real_vul_data_csv),
            'dedup_dropped_csv': str(self.dedup_dropped_csv),
            'normalized_token_counts_csv': str(self.normalized_token_counts_csv),
            'slice_token_distribution_png': str(self.slice_token_distribution_png),
            'split_manifest_json': str(self.split_manifest_json),
        }


def load_pairs_jsonl(path: Path) -> list[dict[str, Any]]:
    records = _load_jsonl(path)
    for lineno, obj in enumerate(records, start=1):
        pair_id = obj.get('pair_id')
        testcase_key = obj.get('testcase_key')
        if not pair_id or not testcase_key:
            raise ValueError(f'Missing pair_id/testcase_key at line {lineno} in {path}')
    return records


def compute_pair_split(pair_ids: list[str], train_ratio: float, seed: int) -> dict[str, str]:
    keys = sorted(set(pair_ids))
    shuffled = list(keys)
    random.Random(seed).shuffle(shuffled)

    test_ratio = 1.0 - train_ratio
    test_count = int(round(len(shuffled) * test_ratio))
    if len(shuffled) > 1:
        test_count = max(1, min(len(shuffled) - 1, test_count))
    else:
        test_count = 0

    test_keys = set(shuffled[:test_count])
    split_map: dict[str, str] = {}
    for key in shuffled:
        split_map[key] = 'test' if key in test_keys else 'train_val'
    return split_map


def export_primary_dataset(params: PrimaryDatasetExportParams) -> PrimaryDatasetExportResult:
    if not params.pairs_jsonl.exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {params.pairs_jsonl}')
    if not (0.0 < params.train_ratio < 1.0):
        raise ValueError(f'train_ratio must be between 0 and 1: {params.train_ratio}')

    pairs = load_pairs_jsonl(params.pairs_jsonl)
    export_paths = build_dataset_export_paths(params.output_dir)

    export_result = run_step07_export_wrapper(
        pairs=pairs,
        paired_signatures_dir=params.paired_signatures_dir,
        slice_dir=params.slice_dir,
        output_dir=params.output_dir,
        dedup_mode=params.dedup_mode,
        dataset_basename=None,
        split_assignments_fn=lambda pair_ids: compute_pair_split(
            pair_ids, train_ratio=params.train_ratio, seed=params.split_seed
        ),
        summary_metadata={
            'pairs_jsonl': str(params.pairs_jsonl),
            'paired_signatures_dir': str(params.paired_signatures_dir),
            'slice_dir': str(params.slice_dir),
            'output_dir': str(params.output_dir),
            'real_vul_data_csv': str(export_paths['csv_path']),
            'normalized_token_counts_csv': str(export_paths['token_counts_csv']),
            'slice_token_distribution_png': str(export_paths['token_distribution_png']),
            'seed': params.split_seed,
            'train_ratio': params.train_ratio,
            'test_ratio': round(1.0 - params.train_ratio, 6),
        },
        split_manifest_metadata={
            'output_dir': str(params.output_dir),
            'pairs_jsonl': str(params.pairs_jsonl),
            'paired_signatures_dir': str(params.paired_signatures_dir),
            'slice_dir': str(params.slice_dir),
            'split_unit': 'pair_id',
            'train_ratio': params.train_ratio,
            'test_ratio': round(1.0 - params.train_ratio, 6),
            'seed': params.split_seed,
        },
        collect_defined_function_names_fn=collect_defined_function_names,
        build_source_file_candidates_fn=build_source_file_candidates,
        run_step07_export_core_fn=run_step07_export_core,
    )

    return PrimaryDatasetExportResult(
        summary_json=Path(export_result['summary_json']),
        output_dir=params.output_dir,
        normalized_slices_dir=Path(export_result['normalized_slices_dir']),
        real_vul_data_csv=Path(export_result['csv_path']),
        dedup_dropped_csv=Path(export_result['dedup_dropped_csv']),
        normalized_token_counts_csv=Path(export_result['token_counts_csv']),
        slice_token_distribution_png=Path(export_result['token_distribution_png']),
        split_manifest_json=Path(export_result['split_manifest_json']),
    )


def export_dataset_from_pipeline(
    *,
    pairs_jsonl: Path,
    paired_signatures_dir: Path,
    slice_dir: Path,
    output_dir: Path,
    split_seed: int,
    train_ratio: float,
    dedup_mode: str,
) -> dict[str, object]:
    return export_primary_dataset(
        PrimaryDatasetExportParams(
            pairs_jsonl=pairs_jsonl,
            paired_signatures_dir=paired_signatures_dir,
            slice_dir=slice_dir,
            output_dir=output_dir,
            split_seed=split_seed,
            train_ratio=train_ratio,
            dedup_mode=dedup_mode,
        )
    ).to_payload()
