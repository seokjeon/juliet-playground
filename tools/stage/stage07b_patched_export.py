from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared import fs as _fs_utils
from shared.artifact_layout import (
    TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    DatasetExportPaths,
    PatchedPairingPaths,
    SliceStagePaths,
    build_dataset_export_paths,
    build_pair_trace_paths,
    build_patched_pairing_paths,
    build_slice_stage_paths,
)
from shared.dataset_export_core import run_configured_step07_export, run_step07_export_core
from shared.dataset_sources import build_source_file_candidates, collect_defined_function_names
from shared.jsonio import load_jsonl, write_json, write_jsonl
from shared.pairing import (
    build_pairing_meta,
    build_signature_meta,
    build_trace_priority_key,
    make_pair_id,
)
from shared.signatures import load_signature_payload

from stage.stage06_slices import generate_slices

DATASET_BASENAME = TRAIN_PATCHED_COUNTERPARTS_BASENAME
prepare_target = _fs_utils.prepare_target


@dataclass(frozen=True)
class PatchedDatasetExportParams:
    run_dir: Path
    dedup_mode: str


@dataclass(frozen=True)
class Stage07BPaths:
    run_dir: Path
    pair_dir: Path
    dataset_export_dir: Path
    pairing: PatchedPairingPaths
    slices: SliceStagePaths
    dataset: DatasetExportPaths
    primary_split_manifest_json: Path


@dataclass(frozen=True)
class PatchedPairingSelectionResult:
    pairs: list[dict[str, Any]]
    pairing: PatchedPairingPaths
    selection_counts: dict[str, int]


@dataclass(frozen=True)
class PatchedDatasetExportResult:
    dataset_basename: str
    run_dir: Path
    pair_dir: Path
    pairing: PatchedPairingPaths
    slices: SliceStagePaths
    dataset: DatasetExportPaths
    dedup_mode: str

    def to_payload(self) -> dict[str, object]:
        return {
            'dataset_basename': self.dataset_basename,
            'run_dir': str(self.run_dir),
            'pair_dir': str(self.pair_dir),
            'dedup_mode': self.dedup_mode,
            'pairing': self.pairing.to_payload(),
            'slices': self.slices.to_payload(),
            'dataset': self.dataset.to_payload(),
        }


def build_stage07b_paths(run_dir: Path) -> Stage07BPaths:
    resolved_run_dir = run_dir.resolve()
    pair_dir = resolved_run_dir / '05_pair_trace_ds'
    dataset_export_dir = resolved_run_dir / '07_dataset_export'
    pairing = build_patched_pairing_paths(pair_dir, DATASET_BASENAME)
    slices = build_slice_stage_paths(resolved_run_dir / '06_slices' / DATASET_BASENAME)
    dataset = build_dataset_export_paths(dataset_export_dir, DATASET_BASENAME)
    primary_dataset = build_dataset_export_paths(dataset_export_dir)
    return Stage07BPaths(
        run_dir=resolved_run_dir,
        pair_dir=pair_dir,
        dataset_export_dir=dataset_export_dir,
        pairing=pairing,
        slices=slices,
        dataset=dataset,
        primary_split_manifest_json=primary_dataset.split_manifest_json,
    )


def leftover_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
    return build_trace_priority_key(
        bug_trace_length=int(record.get('bug_trace_length', 0) or 0),
        trace_file=str(record.get('trace_file') or ''),
        best_flow_type=str(record.get('best_flow_type') or ''),
        procedure=record.get('procedure'),
    )


def build_train_patched_counterparts(*, run_dir: Path) -> PatchedPairingSelectionResult:
    paths = build_stage07b_paths(run_dir)
    pair_trace_paths = build_pair_trace_paths(paths.pair_dir)

    if not pair_trace_paths.pairs_jsonl.exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {pair_trace_paths.pairs_jsonl}')
    if not pair_trace_paths.leftover_counterparts_jsonl.exists():
        raise FileNotFoundError(
            f'Leftover counterparts JSONL not found: {pair_trace_paths.leftover_counterparts_jsonl}'
        )
    if not paths.primary_split_manifest_json.exists():
        raise FileNotFoundError(
            f'Primary split manifest not found: {paths.primary_split_manifest_json}'
        )

    prepare_target(paths.pairing.signatures_dir, overwrite=False)
    prepare_target(paths.pairing.pairs_jsonl, overwrite=False)
    prepare_target(paths.pairing.selection_summary_json, overwrite=False)
    paths.pairing.signatures_dir.mkdir(parents=True, exist_ok=True)
    paths.pairing.pairs_jsonl.parent.mkdir(parents=True, exist_ok=True)
    paths.pairing.selection_summary_json.parent.mkdir(parents=True, exist_ok=True)

    split_manifest = json.loads(paths.primary_split_manifest_json.read_text(encoding='utf-8'))
    train_val_pair_ids = set(split_manifest.get('pair_ids', {}).get('train_val') or [])
    if not train_val_pair_ids:
        raise ValueError(f'No train_val pair_ids found in {paths.primary_split_manifest_json}')

    primary_pairs = load_jsonl(pair_trace_paths.pairs_jsonl)
    primary_pairs_by_testcase = {
        str(pair.get('testcase_key') or ''): pair
        for pair in primary_pairs
        if str(pair.get('pair_id') or '') in train_val_pair_ids
    }

    leftovers = load_jsonl(pair_trace_paths.leftover_counterparts_jsonl)
    leftovers_by_testcase: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in leftovers:
        testcase_key = str(record.get('testcase_key') or '')
        if testcase_key:
            leftovers_by_testcase[testcase_key].append(record)

    selected_pairs: list[dict[str, Any]] = []
    selection_counts = Counter()

    for testcase_key, primary_pair in sorted(primary_pairs_by_testcase.items()):
        selection_counts['primary_train_val_pairs_total'] += 1
        candidate_leftovers = sorted(
            leftovers_by_testcase.get(testcase_key, []), key=leftover_sort_key
        )
        if not candidate_leftovers:
            selection_counts['primary_train_val_pairs_without_leftover'] += 1
            continue

        selected_leftover = candidate_leftovers[0]
        b2b_signature_path = Path(str((primary_pair.get('output_files') or {}).get('b2b') or ''))
        counterpart_trace_path = Path(str(selected_leftover.get('trace_file') or ''))
        if not b2b_signature_path.exists():
            selection_counts['skipped_missing_b2b_signature'] += 1
            continue
        if not counterpart_trace_path.exists():
            selection_counts['skipped_missing_counterpart_signature'] += 1
            continue

        b2b_payload = load_signature_payload(b2b_signature_path)
        counterpart_payload = load_signature_payload(counterpart_trace_path)
        counterpart_flow_type = str(selected_leftover.get('best_flow_type') or '').strip()
        if not counterpart_flow_type:
            selection_counts['skipped_missing_counterpart_flow_type'] += 1
            continue

        pair_id = make_pair_id(
            testcase_key=testcase_key,
            b2b_payload=b2b_payload,
            b2b_trace_file=str(primary_pair.get('b2b_trace_file') or ''),
            b2b_flow_type=str(primary_pair.get('b2b_flow_type') or ''),
            counterpart_payload=counterpart_payload,
            counterpart_trace_file=str(selected_leftover.get('trace_file') or ''),
            counterpart_flow_type=counterpart_flow_type,
            dataset_namespace=DATASET_BASENAME,
        )

        testcase_dir = paths.pairing.signatures_dir / testcase_key
        testcase_dir.mkdir(parents=True, exist_ok=True)
        b2b_output_path = testcase_dir / 'b2b.json'
        counterpart_output_path = testcase_dir / f'{counterpart_flow_type}.json'

        b2b_export = dict(b2b_payload)
        b2b_export['pairing_meta'] = build_pairing_meta(
            pair_id=pair_id,
            testcase_key=testcase_key,
            role='b2b',
            selection_reason='train_val_primary_pair',
            source_primary_pair_id=str(primary_pair.get('pair_id') or '') or None,
            trace_file=str(primary_pair.get('b2b_trace_file') or ''),
            best_flow_type=str(primary_pair.get('b2b_flow_type') or ''),
            bug_trace_length=int(primary_pair.get('b2b_bug_trace_length', 0) or 0),
        )
        counterpart_export = dict(counterpart_payload)
        counterpart_export['pairing_meta'] = build_pairing_meta(
            pair_id=pair_id,
            testcase_key=testcase_key,
            role='counterpart',
            selection_reason='top_leftover_train_val',
            source_primary_pair_id=str(primary_pair.get('pair_id') or '') or None,
            trace_file=str(selected_leftover.get('trace_file') or ''),
            best_flow_type=counterpart_flow_type,
            bug_trace_length=int(selected_leftover.get('bug_trace_length', 0) or 0),
            leftover_rank=1,
            leftover_candidates_total=len(candidate_leftovers),
        )

        write_json(b2b_output_path, b2b_export)
        write_json(counterpart_output_path, counterpart_export)

        selected_pairs.append(
            {
                'pair_id': pair_id,
                'testcase_key': testcase_key,
                'selection_reason': 'top_leftover_train_val',
                'source_primary_pair_id': primary_pair.get('pair_id'),
                'source_primary_dataset_type': 'train_val',
                'b2b_flow_type': str(primary_pair.get('b2b_flow_type') or ''),
                'b2b_trace_file': str(primary_pair.get('b2b_trace_file') or ''),
                'b2b_bug_trace_length': int(primary_pair.get('b2b_bug_trace_length', 0) or 0),
                'b2b_signature': primary_pair.get('b2b_signature'),
                'counterpart_flow_type': counterpart_flow_type,
                'counterpart_trace_file': str(selected_leftover.get('trace_file') or ''),
                'counterpart_bug_trace_length': int(
                    selected_leftover.get('bug_trace_length', 0) or 0
                ),
                'counterpart_signature': build_signature_meta(
                    payload=counterpart_payload,
                    trace_file=str(selected_leftover.get('trace_file') or ''),
                    best_flow_type=counterpart_flow_type,
                    bug_trace_length=int(selected_leftover.get('bug_trace_length', 0) or 0),
                    procedure=selected_leftover.get('procedure'),
                    primary_file=selected_leftover.get('primary_file'),
                    primary_line=selected_leftover.get('primary_line'),
                ),
                'output_files': {
                    'b2b': str(b2b_output_path),
                    counterpart_flow_type: str(counterpart_output_path),
                },
            }
        )
        selection_counts['selected_pairs'] += 1
        selection_counts[f'selected_counterpart_flow_{counterpart_flow_type}'] += 1
        if len(candidate_leftovers) > 1:
            selection_counts['selected_pairs_with_extra_leftovers'] += 1

    write_jsonl(paths.pairing.pairs_jsonl, selected_pairs)

    summary_payload = {
        'dataset_basename': DATASET_BASENAME,
        'counts': dict(selection_counts),
        'train_val_pair_ids_total': len(train_val_pair_ids),
        'selected_testcases': len(selected_pairs),
    }
    write_json(paths.pairing.selection_summary_json, summary_payload)
    print(json.dumps(summary_payload, ensure_ascii=False))
    return PatchedPairingSelectionResult(
        pairs=selected_pairs,
        pairing=paths.pairing,
        selection_counts=dict(selection_counts),
    )


def export_dataset(
    *,
    pairs: list[dict[str, Any]],
    paired_signatures_dir: Path,
    slice_dir: Path,
    dataset_paths: DatasetExportPaths,
    dedup_mode: str,
) -> DatasetExportPaths:
    run_configured_step07_export(
        pairs=pairs,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        export_paths=dataset_paths,
        dedup_mode=dedup_mode,
        split_assignments_fn=lambda pair_ids: {pair_id: 'train_val' for pair_id in pair_ids},
        summary_metadata={'dataset_basename': DATASET_BASENAME},
        split_manifest_metadata={},
        collect_defined_function_names_fn=collect_defined_function_names,
        build_source_file_candidates_fn=build_source_file_candidates,
        run_step07_export_core_fn=run_step07_export_core,
    )
    return dataset_paths


def export_patched_dataset(params: PatchedDatasetExportParams) -> PatchedDatasetExportResult:
    paths = build_stage07b_paths(params.run_dir)
    selected = build_train_patched_counterparts(run_dir=params.run_dir)

    generate_slices(
        signature_db_dir=selected.pairing.signatures_dir,
        output_dir=paths.slices.output_dir,
        overwrite=False,
        run_dir=paths.run_dir,
        summary_metadata={'dataset_basename': DATASET_BASENAME},
    )

    dataset_paths = export_dataset(
        pairs=selected.pairs,
        paired_signatures_dir=selected.pairing.signatures_dir,
        slice_dir=paths.slices.slice_dir,
        dataset_paths=paths.dataset,
        dedup_mode=params.dedup_mode,
    )

    return PatchedDatasetExportResult(
        dataset_basename=DATASET_BASENAME,
        run_dir=paths.run_dir,
        pair_dir=paths.pair_dir,
        pairing=selected.pairing,
        slices=paths.slices,
        dataset=dataset_paths,
        dedup_mode=params.dedup_mode,
    )
