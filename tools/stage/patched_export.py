#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from shared import fs as _fs_utils
from shared import step07 as _step07_shared
from shared.jsonio import load_jsonl
from shared.paths import PROJECT_HOME, RESULT_DIR
from shared.pipeline_runs import find_latest_pipeline_run_dir
from shared.signatures import load_signature_payload

from stage.slices import process_signature_db

CPP_LIKE_SUFFIXES = {'.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hh', '.hxx'}
ROLE_SORT_ORDER = {'b2b': 0, 'counterpart': 1}
DATASET_BASENAME = 'train_patched_counterparts'
PROJECT_HOME_PATH = Path(PROJECT_HOME).resolve()

normalize_artifact_path = _step07_shared.normalize_artifact_path
unique_in_order = _step07_shared.unique_in_order
build_dedup_audit_row = _step07_shared.build_dedup_audit_row
extract_std_bug_trace = _step07_shared.extract_std_bug_trace
load_tree_sitter_parsers = _step07_shared.load_tree_sitter_parsers
candidate_languages_for_source = _step07_shared.candidate_languages_for_source
node_text = _step07_shared.node_text
extract_function_name_from_declarator = _step07_shared.extract_function_name_from_declarator
extract_defined_function_names = _step07_shared.extract_defined_function_names
dedupe_paths = _step07_shared.dedupe_paths
build_source_file_candidates = _step07_shared.build_source_file_candidates
lex_c_like = _step07_shared.lex_c_like
previous_meaningful_token = _step07_shared.previous_meaningful_token
next_meaningful_token = _step07_shared.next_meaningful_token
normalize_slice_function_names = _step07_shared.normalize_slice_function_names
find_slice_path = _step07_shared.find_slice_path
compact_code_for_hash = _step07_shared.compact_code_for_hash
normalized_code_md5 = _step07_shared.normalized_code_md5
dedupe_pairs_by_normalized_rows = _step07_shared.dedupe_pairs_by_normalized_rows
prepare_target = _fs_utils.prepare_target
remove_target = _fs_utils.remove_target


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            'Export a train-only evaluation dataset that pairs the original train_val b2b sample '
            'with the top leftover patched counterpart for the same testcase.'
        )
    )
    parser.add_argument(
        '--run-dir',
        type=Path,
        default=None,
        help='Pipeline run directory. If omitted, use the latest run under --pipeline-root.',
    )
    parser.add_argument(
        '--pair-dir',
        type=Path,
        default=None,
        help='Override 05_pair_trace_ds directory. If provided, infer run-dir when possible.',
    )
    parser.add_argument(
        '--dataset-export-dir',
        type=Path,
        default=None,
        help='Directory containing 07_dataset_export outputs; defaults to <run-dir>/07_dataset_export.',
    )
    parser.add_argument(
        '--signature-output-dir',
        type=Path,
        default=None,
        help='Output directory for materialized train_patched_counterparts signature JSONs.',
    )
    parser.add_argument(
        '--slice-output-dir',
        type=Path,
        default=None,
        help='Output stage directory for generated slices; defaults to <run-dir>/06_slices/train_patched_counterparts.',
    )
    parser.add_argument(
        '--output-pairs-jsonl',
        type=Path,
        default=None,
        help='Output JSONL path for selected train_patched_counterparts pairs.',
    )
    parser.add_argument(
        '--selection-summary-json',
        type=Path,
        default=None,
        help='Output summary JSON path for train_patched_counterparts pair selection.',
    )
    parser.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
        help='Root directory containing run-* pipeline outputs.',
    )
    parser.add_argument(
        '--old-prefix',
        type=str,
        default=None,
        help='Optional old path prefix to rewrite inside bug_trace filenames.',
    )
    parser.add_argument(
        '--new-prefix',
        type=str,
        default=None,
        help='Optional new path prefix used with --old-prefix.',
    )
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='Overwrite train_patched_counterparts outputs if they already exist.',
    )
    parser.add_argument(
        '--dedup-mode',
        choices=['none', 'row'],
        default='row',
        help='Normalized-slice dedup mode before export.',
    )
    return parser.parse_args()


def infer_run_dir_from_pair_dir(pair_dir: Path) -> Path | None:
    if pair_dir.name != '05_pair_trace_ds':
        return None
    return pair_dir.parent


def resolve_paths(args: argparse.Namespace) -> dict[str, Path | None]:
    run_dir: Path | None
    if args.run_dir is not None:
        run_dir = args.run_dir.resolve()
        pair_dir = (
            args.pair_dir.resolve() if args.pair_dir is not None else run_dir / '05_pair_trace_ds'
        )
    elif args.pair_dir is not None:
        pair_dir = args.pair_dir.resolve()
        run_dir = infer_run_dir_from_pair_dir(pair_dir)
    else:
        run_dir = find_latest_pipeline_run_dir(args.pipeline_root.resolve())
        pair_dir = run_dir / '05_pair_trace_ds'

    if args.dataset_export_dir is None:
        if run_dir is None:
            raise ValueError('--dataset-export-dir is required when run-dir cannot be inferred.')
        dataset_export_dir = run_dir / '07_dataset_export'
    else:
        dataset_export_dir = args.dataset_export_dir.resolve()

    if args.signature_output_dir is None:
        signature_output_dir = pair_dir / f'{DATASET_BASENAME}_signatures'
    else:
        signature_output_dir = args.signature_output_dir.resolve()

    if args.slice_output_dir is None:
        if run_dir is None:
            raise ValueError('--slice-output-dir is required when run-dir cannot be inferred.')
        slice_output_dir = run_dir / '06_slices' / DATASET_BASENAME
    else:
        slice_output_dir = args.slice_output_dir.resolve()

    paths: dict[str, Path | None] = {
        'run_dir': run_dir,
        'pair_dir': pair_dir,
        'dataset_export_dir': dataset_export_dir,
        'signature_output_dir': signature_output_dir,
        'slice_output_dir': slice_output_dir,
    }
    return paths


def validate_args(args: argparse.Namespace, paths: dict[str, Path | None]) -> None:
    pair_dir = paths['pair_dir']
    dataset_export_dir = paths['dataset_export_dir']
    if pair_dir is None or dataset_export_dir is None:
        raise ValueError('Resolved pair_dir and dataset_export_dir are required.')
    if not pair_dir.exists():
        raise FileNotFoundError(f'Pair dir not found: {pair_dir}')
    if not pair_dir.is_dir():
        raise NotADirectoryError(f'Pair dir is not a directory: {pair_dir}')
    if not dataset_export_dir.exists():
        raise FileNotFoundError(f'Dataset export dir not found: {dataset_export_dir}')
    if not dataset_export_dir.is_dir():
        raise NotADirectoryError(f'Dataset export dir is not a directory: {dataset_export_dir}')
    if bool(args.old_prefix) != bool(args.new_prefix):
        raise ValueError('--old-prefix and --new-prefix must be provided together.')


def leftover_sort_key(record: dict[str, Any]) -> tuple[Any, ...]:
    return (
        -int(record.get('bug_trace_length', 0) or 0),
        str(record.get('trace_file') or ''),
        str(record.get('best_flow_type') or ''),
        str(record.get('procedure') or ''),
    )


def make_pair_id(
    testcase_key: str,
    b2b_trace_file: str,
    b2b_flow_type: str,
    b2b_procedure: str | None,
    counterpart_trace_file: str,
    counterpart_flow_type: str,
    counterpart_procedure: str | None,
) -> str:
    seed = '||'.join(
        [
            testcase_key,
            b2b_trace_file,
            b2b_flow_type,
            b2b_procedure or '',
            counterpart_trace_file,
            counterpart_flow_type,
            counterpart_procedure or '',
            DATASET_BASENAME,
        ]
    )
    return hashlib.sha1(seed.encode('utf-8')).hexdigest()[:16]


def signature_meta(payload: dict[str, Any], record: dict[str, Any]) -> dict[str, Any]:
    return {
        'trace_file': str(record.get('trace_file') or ''),
        'best_flow_type': str(record.get('best_flow_type') or ''),
        'bug_trace_length': int(record.get('bug_trace_length', 0) or 0),
        'procedure': record.get('procedure'),
        'primary_file': record.get('primary_file'),
        'primary_line': record.get('primary_line'),
        'signature_key': payload.get('key'),
        'signature_hash': payload.get('hash'),
    }


def build_train_patched_counterparts(
    *,
    pair_dir: Path,
    dataset_export_dir: Path,
    signature_output_dir: Path,
    output_pairs_jsonl: Path,
    selection_summary_json: Path,
    overwrite: bool,
) -> dict[str, Any]:
    pairs_jsonl = pair_dir / 'pairs.jsonl'
    leftovers_jsonl = pair_dir / 'leftover_counterparts.jsonl'
    source_split_manifest_json = dataset_export_dir / 'split_manifest.json'
    summary_json = selection_summary_json

    if not pairs_jsonl.exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {pairs_jsonl}')
    if not leftovers_jsonl.exists():
        raise FileNotFoundError(f'Leftover counterparts JSONL not found: {leftovers_jsonl}')
    if not source_split_manifest_json.exists():
        raise FileNotFoundError(f'Primary split manifest not found: {source_split_manifest_json}')

    prepare_target(signature_output_dir, overwrite=overwrite)
    prepare_target(output_pairs_jsonl, overwrite=overwrite)
    prepare_target(summary_json, overwrite=overwrite)
    signature_output_dir.mkdir(parents=True, exist_ok=True)
    output_pairs_jsonl.parent.mkdir(parents=True, exist_ok=True)
    summary_json.parent.mkdir(parents=True, exist_ok=True)

    split_manifest = json.loads(source_split_manifest_json.read_text(encoding='utf-8'))
    train_val_pair_ids = set(split_manifest.get('pair_ids', {}).get('train_val') or [])
    if not train_val_pair_ids:
        raise ValueError(f'No train_val pair_ids found in {source_split_manifest_json}')

    primary_pairs = load_jsonl(pairs_jsonl)
    primary_pairs_by_testcase = {
        str(pair.get('testcase_key') or ''): pair
        for pair in primary_pairs
        if str(pair.get('pair_id') or '') in train_val_pair_ids
    }

    leftovers = load_jsonl(leftovers_jsonl)
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

        testcase_dir = signature_output_dir / testcase_key
        testcase_dir.mkdir(parents=True, exist_ok=True)
        b2b_output_path = testcase_dir / 'b2b.json'
        counterpart_output_path = testcase_dir / f'{counterpart_flow_type}.json'

        pair_id = make_pair_id(
            testcase_key=testcase_key,
            b2b_trace_file=str(primary_pair.get('b2b_trace_file') or ''),
            b2b_flow_type=str(primary_pair.get('b2b_flow_type') or ''),
            b2b_procedure=(primary_pair.get('b2b_signature') or {}).get('procedure'),
            counterpart_trace_file=str(selected_leftover.get('trace_file') or ''),
            counterpart_flow_type=counterpart_flow_type,
            counterpart_procedure=selected_leftover.get('procedure'),
        )

        b2b_export = dict(b2b_payload)
        b2b_export['pairing_meta'] = {
            'pair_id': pair_id,
            'testcase_key': testcase_key,
            'role': 'b2b',
            'selection_reason': 'train_val_primary_pair',
            'source_primary_pair_id': primary_pair.get('pair_id'),
            'trace_file': str(primary_pair.get('b2b_trace_file') or ''),
            'best_flow_type': str(primary_pair.get('b2b_flow_type') or ''),
            'bug_trace_length': int(primary_pair.get('b2b_bug_trace_length', 0) or 0),
        }
        counterpart_export = dict(counterpart_payload)
        counterpart_export['pairing_meta'] = {
            'pair_id': pair_id,
            'testcase_key': testcase_key,
            'role': 'counterpart',
            'selection_reason': 'top_leftover_train_val',
            'source_primary_pair_id': primary_pair.get('pair_id'),
            'trace_file': str(selected_leftover.get('trace_file') or ''),
            'best_flow_type': counterpart_flow_type,
            'bug_trace_length': int(selected_leftover.get('bug_trace_length', 0) or 0),
            'leftover_rank': 1,
            'leftover_candidates_total': len(candidate_leftovers),
        }

        b2b_output_path.write_text(
            json.dumps(b2b_export, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
        )
        counterpart_output_path.write_text(
            json.dumps(counterpart_export, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8',
        )

        selected_pairs.append(
            {
                'pair_id': pair_id,
                'testcase_key': testcase_key,
                'selection_reason': 'top_leftover_train_val',
                'source_primary_pair_id': primary_pair.get('pair_id'),
                'source_primary_dataset_type': 'train_val',
                'b2b_flow_type': primary_pair.get('b2b_flow_type'),
                'b2b_trace_file': primary_pair.get('b2b_trace_file'),
                'b2b_bug_trace_length': primary_pair.get('b2b_bug_trace_length'),
                'b2b_signature': primary_pair.get('b2b_signature'),
                'counterpart_flow_type': counterpart_flow_type,
                'counterpart_trace_file': str(selected_leftover.get('trace_file') or ''),
                'counterpart_bug_trace_length': int(
                    selected_leftover.get('bug_trace_length', 0) or 0
                ),
                'counterpart_signature': signature_meta(counterpart_payload, selected_leftover),
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

    with output_pairs_jsonl.open('w', encoding='utf-8') as f:
        for record in selected_pairs:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')

    summary_payload = {
        'dataset_basename': DATASET_BASENAME,
        'pair_dir': str(pair_dir),
        'source_pairs_jsonl': str(pairs_jsonl),
        'source_leftover_counterparts_jsonl': str(leftovers_jsonl),
        'source_split_manifest_json': str(source_split_manifest_json),
        'signature_output_dir': str(signature_output_dir),
        'output_pairs_jsonl': str(output_pairs_jsonl),
        'counts': dict(selection_counts),
        'train_val_pair_ids_total': len(train_val_pair_ids),
        'selected_testcases': len(selected_pairs),
    }
    summary_json.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    print(json.dumps(summary_payload, ensure_ascii=False))
    return {
        'pairs': selected_pairs,
        'output_pairs_jsonl': output_pairs_jsonl,
        'selection_summary_json': summary_json,
        'signature_output_dir': signature_output_dir,
        'selection_counts': dict(selection_counts),
    }


def collect_defined_function_names(
    source_path: Path, parsers: dict[str, object]
) -> tuple[set[str], str | None]:
    try:
        source_bytes = source_path.read_bytes()
    except Exception as exc:
        return set(), f'read_error:{exc}'

    last_error: str | None = None
    for language_name in candidate_languages_for_source(source_path):
        parser = parsers.get(language_name)
        if parser is None:
            continue
        try:
            tree = parser.parse(source_bytes)
            return extract_defined_function_names(tree.root_node, source_bytes), None
        except Exception as exc:
            last_error = f'{language_name}:{exc}'

    if not parsers:
        return set(), 'parser_unavailable'
    return set(), last_error or 'parse_failed'


def export_dataset(
    *,
    pairs: list[dict[str, Any]],
    paired_signatures_dir: Path,
    slice_dir: Path,
    dataset_export_dir: Path,
    overwrite: bool,
    dedup_mode: str,
) -> dict[str, Any]:
    if not paired_signatures_dir.exists():
        raise FileNotFoundError(f'Paired signatures dir not found: {paired_signatures_dir}')
    if not slice_dir.exists():
        raise FileNotFoundError(f'Slice dir not found: {slice_dir}')
    if dedup_mode not in {'none', 'row'}:
        raise ValueError(f'Unsupported dedup_mode: {dedup_mode}')

    csv_path = dataset_export_dir / f'{DATASET_BASENAME}.csv'
    dedup_dropped_csv = dataset_export_dir / f'{DATASET_BASENAME}_dedup_dropped.csv'
    normalized_slices_dir = dataset_export_dir / f'{DATASET_BASENAME}_slices'
    token_counts_csv = dataset_export_dir / f'{DATASET_BASENAME}_token_counts.csv'
    token_distribution_png = dataset_export_dir / f'{DATASET_BASENAME}_token_distribution.png'
    split_manifest_json = dataset_export_dir / f'{DATASET_BASENAME}_split_manifest.json'
    summary_json = dataset_export_dir / f'{DATASET_BASENAME}_summary.json'

    for target in [
        csv_path,
        dedup_dropped_csv,
        normalized_slices_dir,
        token_counts_csv,
        token_distribution_png,
        split_manifest_json,
        summary_json,
    ]:
        prepare_target(target, overwrite=overwrite)

    return _step07_shared.run_step07_export_core(
        pairs=pairs,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        csv_path=csv_path,
        dedup_dropped_csv=dedup_dropped_csv,
        normalized_slices_dir=normalized_slices_dir,
        token_counts_csv=token_counts_csv,
        token_distribution_png=token_distribution_png,
        split_manifest_json=split_manifest_json,
        summary_json=summary_json,
        dedup_mode=dedup_mode,
        split_assignments_fn=lambda pair_ids: {pair_id: 'train_val' for pair_id in pair_ids},
        summary_metadata={
            'dataset_basename': DATASET_BASENAME,
            'paired_signatures_dir': str(paired_signatures_dir),
            'slice_dir': str(slice_dir),
            'output_dir': str(dataset_export_dir),
            'csv_path': str(csv_path),
        },
        split_manifest_metadata={
            'dataset_basename': DATASET_BASENAME,
            'output_dir': str(dataset_export_dir),
            'paired_signatures_dir': str(paired_signatures_dir),
            'slice_dir': str(slice_dir),
            'split_unit': 'pair_id',
            'split_mode': 'inherited_train_val_only',
        },
        collect_defined_function_names_fn=collect_defined_function_names,
        build_source_file_candidates_fn=build_source_file_candidates,
    )


def main() -> int:
    args = parse_args()
    paths = resolve_paths(args)
    validate_args(args, paths)

    run_dir = paths['run_dir']
    pair_dir = paths['pair_dir']
    dataset_export_dir = paths['dataset_export_dir']
    signature_output_dir = paths['signature_output_dir']
    slice_output_dir = paths['slice_output_dir']
    if (
        run_dir is None
        or pair_dir is None
        or dataset_export_dir is None
        or signature_output_dir is None
        or slice_output_dir is None
    ):
        raise ValueError('Failed to resolve required paths.')

    output_pairs_jsonl = (
        args.output_pairs_jsonl.resolve()
        if args.output_pairs_jsonl is not None
        else pair_dir / f'{DATASET_BASENAME}_pairs.jsonl'
    )
    selection_summary_json = (
        args.selection_summary_json.resolve()
        if args.selection_summary_json is not None
        else pair_dir / f'{DATASET_BASENAME}_selection_summary.json'
    )

    selected = build_train_patched_counterparts(
        pair_dir=pair_dir,
        dataset_export_dir=dataset_export_dir,
        signature_output_dir=signature_output_dir,
        output_pairs_jsonl=output_pairs_jsonl,
        selection_summary_json=selection_summary_json,
        overwrite=args.overwrite,
    )

    prepare_target(slice_output_dir, overwrite=args.overwrite)
    slice_output_dir.mkdir(parents=True, exist_ok=True)
    slice_dir = slice_output_dir / 'slice'
    slice_summary = process_signature_db(
        signature_db_dir=signature_output_dir,
        slice_dir=slice_dir,
        old_prefix=args.old_prefix,
        new_prefix=args.new_prefix,
    )
    slice_summary_payload = {
        'dataset_basename': DATASET_BASENAME,
        'signature_db_dir': str(signature_output_dir),
        'output_dir': str(slice_output_dir),
        'slice_dir': str(slice_dir),
        'run_dir': str(run_dir),
        'old_prefix': args.old_prefix,
        'new_prefix': args.new_prefix,
        **slice_summary,
    }
    slice_summary_json = slice_output_dir / 'summary.json'
    prepare_target(slice_summary_json, overwrite=args.overwrite)
    slice_summary_json.write_text(
        json.dumps(slice_summary_payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    print(json.dumps(slice_summary_payload, ensure_ascii=False))

    export_result = export_dataset(
        pairs=selected['pairs'],
        paired_signatures_dir=signature_output_dir,
        slice_dir=slice_dir,
        dataset_export_dir=dataset_export_dir,
        overwrite=args.overwrite,
        dedup_mode=args.dedup_mode,
    )

    result = {
        'dataset_basename': DATASET_BASENAME,
        'run_dir': str(run_dir),
        'pair_dir': str(pair_dir),
        'dataset_export_dir': str(dataset_export_dir),
        'signature_output_dir': str(signature_output_dir),
        'slice_output_dir': str(slice_output_dir),
        'slice_dir': str(slice_dir),
        'slice_summary_json': str(slice_summary_json),
        'selection_summary_json': str(selected['selection_summary_json']),
        'pairs_jsonl': str(selected['output_pairs_jsonl']),
        'csv_path': str(export_result['csv_path']),
        'dedup_dropped_csv': str(export_result['dedup_dropped_csv']),
        'normalized_slices_dir': str(export_result['normalized_slices_dir']),
        'token_counts_csv': str(export_result['token_counts_csv']),
        'token_distribution_png': str(export_result['token_distribution_png']),
        'split_manifest_json': str(export_result['split_manifest_json']),
        'dedup_mode': args.dedup_mode,
        'summary_json': str(export_result['summary_json']),
    }
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
