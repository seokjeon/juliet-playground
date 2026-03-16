from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from shared.dataset_dedup import ROLE_SORT_ORDER, dedupe_pairs_by_normalized_rows
from shared.dataset_normalize import normalize_slice_function_names
from shared.dataset_sources import (
    find_slice_path,
    load_tree_sitter_parsers,
    normalize_artifact_path,
)


def _prepare_export_outputs(*, csv_path: Path, normalized_slices_dir: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    normalized_slices_dir.mkdir(parents=True, exist_ok=True)


def build_step07_export_paths(
    output_dir: Path, dataset_basename: str | None = None
) -> dict[str, Path]:
    if dataset_basename:
        return {
            'csv_path': output_dir / f'{dataset_basename}.csv',
            'dedup_dropped_csv': output_dir / f'{dataset_basename}_dedup_dropped.csv',
            'normalized_slices_dir': output_dir / f'{dataset_basename}_slices',
            'token_counts_csv': output_dir / f'{dataset_basename}_token_counts.csv',
            'token_distribution_png': output_dir / f'{dataset_basename}_token_distribution.png',
            'split_manifest_json': output_dir / f'{dataset_basename}_split_manifest.json',
            'summary_json': output_dir / f'{dataset_basename}_summary.json',
        }
    return {
        'csv_path': output_dir / 'Real_Vul_data.csv',
        'dedup_dropped_csv': output_dir / 'Real_Vul_data_dedup_dropped.csv',
        'normalized_slices_dir': output_dir / 'normalized_slices',
        'token_counts_csv': output_dir / 'normalized_token_counts.csv',
        'token_distribution_png': output_dir / 'slice_token_distribution.png',
        'split_manifest_json': output_dir / 'split_manifest.json',
        'summary_json': output_dir / 'summary.json',
    }


def run_step07_export_wrapper(
    *,
    pairs: list[dict[str, Any]],
    paired_signatures_dir: Path,
    slice_dir: Path,
    output_dir: Path,
    dedup_mode: str,
    dataset_basename: str | None,
    split_assignments_fn: Callable[[list[str]], dict[str, str]],
    summary_metadata: dict[str, Any],
    split_manifest_metadata: dict[str, Any],
    collect_defined_function_names_fn: Callable[
        [Path, dict[str, object]], tuple[set[str], str | None]
    ],
    build_source_file_candidates_fn: Callable[[dict[str, Any], str | None], list[Path]],
    run_step07_export_core_fn: Callable[..., dict[str, Any]] | None = None,
    prepare_target_fn: Callable[[Path, bool], None] | None = None,
    overwrite: bool = False,
) -> dict[str, Any]:
    if not paired_signatures_dir.exists():
        raise FileNotFoundError(f'Paired signatures dir not found: {paired_signatures_dir}')
    if not slice_dir.exists():
        raise FileNotFoundError(f'Slice dir not found: {slice_dir}')
    if dedup_mode not in {'none', 'row'}:
        raise ValueError(f'Unsupported dedup_mode: {dedup_mode}')

    output_dir.mkdir(parents=True, exist_ok=True)
    export_paths = build_step07_export_paths(
        output_dir=output_dir,
        dataset_basename=dataset_basename,
    )
    if prepare_target_fn is not None:
        for target in export_paths.values():
            prepare_target_fn(target, overwrite)

    if run_step07_export_core_fn is None:
        run_step07_export_core_fn = run_step07_export_core

    return run_step07_export_core_fn(
        pairs=pairs,
        paired_signatures_dir=paired_signatures_dir,
        slice_dir=slice_dir,
        csv_path=export_paths['csv_path'],
        dedup_dropped_csv=export_paths['dedup_dropped_csv'],
        normalized_slices_dir=export_paths['normalized_slices_dir'],
        token_counts_csv=export_paths['token_counts_csv'],
        token_distribution_png=export_paths['token_distribution_png'],
        split_manifest_json=export_paths['split_manifest_json'],
        summary_json=export_paths['summary_json'],
        dedup_mode=dedup_mode,
        split_assignments_fn=split_assignments_fn,
        summary_metadata=summary_metadata,
        split_manifest_metadata=split_manifest_metadata,
        collect_defined_function_names_fn=collect_defined_function_names_fn,
        build_source_file_candidates_fn=build_source_file_candidates_fn,
    )


def _collect_surviving_pairs(
    *,
    pairs: list[dict[str, Any]],
    slice_dir: Path,
    tokenizer: object,
    content_token_limit: int,
    count_code_tokens: Callable[[object, str], int],
    collect_defined_function_names_fn: Callable[
        [Path, dict[str, object]], tuple[set[str], str | None]
    ],
    build_source_file_candidates_fn: Callable[[dict[str, Any], str | None], list[Path]],
) -> tuple[
    dict[str, list[dict[str, Any]]],
    Counter,
    Counter,
    dict[str, str],
    set[str],
    set[str],
]:
    parsers = load_tree_sitter_parsers()
    source_func_cache: dict[str, set[str]] = {}
    source_parse_error_cache: dict[str, str] = {}
    source_files_seen: set[str] = set()
    source_files_failed: set[str] = set()

    surviving_pairs: dict[str, list[dict[str, Any]]] = {}
    filtered_pair_reasons = Counter()
    counts = Counter()
    counts['pairs_total'] = len(pairs)

    for pair in pairs:
        pair_id = str(pair['pair_id'])
        testcase_key = str(pair['testcase_key'])
        output_files = pair.get('output_files') or {}
        counterpart_flow_type = str(pair.get('counterpart_flow_type') or '')
        roles = [
            {
                'role': 'b2b',
                'role_name': 'b2b',
                'target': 1,
                'signature_info': pair.get('b2b_signature') or {},
                'signature_path_raw': str(output_files.get('b2b') or ''),
            },
            {
                'role': 'counterpart',
                'role_name': counterpart_flow_type,
                'target': 0,
                'signature_info': pair.get('counterpart_signature') or {},
                'signature_path_raw': str(output_files.get(counterpart_flow_type) or ''),
            },
        ]

        pair_records: list[dict[str, Any]] = []
        pair_invalid_reason: str | None = None

        for role in roles:
            role_name = role['role_name']
            signature_path_raw = str(role['signature_path_raw'])
            if not role_name:
                pair_invalid_reason = 'missing_role_name'
                break
            if not signature_path_raw:
                pair_invalid_reason = 'missing_signature_path'
                break
            signature_path = Path(signature_path_raw)
            if not signature_path.exists():
                pair_invalid_reason = 'missing_signature_file'
                break

            slice_path = find_slice_path(slice_dir, testcase_key, role_name)
            if slice_path is None:
                pair_invalid_reason = 'missing_slice_file'
                break

            signature_payload = json.loads(signature_path.read_text(encoding='utf-8'))
            primary_file_hint = role['signature_info'].get('primary_file')
            source_candidates = build_source_file_candidates_fn(
                signature_payload, primary_file_hint
            )

            user_defined_function_names: set[str] = set()
            for source_path in source_candidates:
                source_key = str(source_path)
                if source_path.exists():
                    source_files_seen.add(source_key)
                if source_key not in source_func_cache:
                    if source_path.exists():
                        names, error = collect_defined_function_names_fn(source_path, parsers)
                    else:
                        names, error = set(), 'missing_source_file'
                    source_func_cache[source_key] = names
                    if error is not None:
                        source_parse_error_cache[source_key] = error
                        if source_path.exists():
                            source_files_failed.add(source_key)
                user_defined_function_names.update(source_func_cache[source_key])

            original_code = slice_path.read_text(encoding='utf-8', errors='replace')
            normalized_code, _, replacement_count = normalize_slice_function_names(
                original_code,
                user_defined_function_names,
            )
            token_count = count_code_tokens(tokenizer, normalized_code)
            exceeds_limit = token_count > content_token_limit
            input_token_count = min(token_count, content_token_limit) + 2

            counts['slices_total'] += 1
            counts[f'ext_{slice_path.suffix.lower()}'] += 1
            if replacement_count > 0:
                counts['slices_normalized'] += 1
                counts['functions_normalized_total'] += replacement_count
            else:
                counts['slices_unchanged'] += 1
            if exceeds_limit:
                counts['slices_over_limit'] += 1

            record = {
                'pair_id': pair_id,
                'testcase_key': testcase_key,
                'role': str(role['role']),
                'role_name': role_name,
                'target': int(role['target']),
                'slice_filename': slice_path.name,
                'extension': slice_path.suffix.lower(),
                'slice_path': str(slice_path),
                'signature_path': str(signature_path),
                'source_signature_path': normalize_artifact_path(signature_path),
                'normalized_code': normalized_code,
                'code_token_count': token_count,
                'input_token_count_with_special': input_token_count,
                'exceeds_510': exceeds_limit,
            }
            pair_records.append(record)

        if pair_invalid_reason is not None:
            filtered_pair_reasons[pair_invalid_reason] += 1
            continue
        if len(pair_records) != 2:
            filtered_pair_reasons['invalid_pair_cardinality'] += 1
            continue
        if any(record['exceeds_510'] for record in pair_records):
            filtered_pair_reasons['over_limit'] += 1
            continue
        surviving_pairs[pair_id] = pair_records

    return (
        surviving_pairs,
        filtered_pair_reasons,
        counts,
        source_parse_error_cache,
        source_files_seen,
        source_files_failed,
    )


def _write_token_counts_csv(token_count_rows: list[dict[str, Any]], token_counts_csv: Path) -> None:
    with token_counts_csv.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                'pair_id',
                'filename',
                'extension',
                'role',
                'code_token_count',
                'input_token_count_with_special',
                'exceeds_510',
            ]
        )
        for row in token_count_rows:
            writer.writerow(
                [
                    row['pair_id'],
                    row['slice_filename'],
                    row['extension'],
                    row['role'],
                    row['code_token_count'],
                    row['input_token_count_with_special'],
                    row['exceeds_510'],
                ]
            )


def _build_ordered_rows(
    surviving_pairs: dict[str, list[dict[str, Any]]],
    split_assignments: dict[str, str],
) -> tuple[list[dict[str, Any]], dict[str, list[str]]]:
    dataset_type_order = [
        label for label in ('train_val', 'test') if label in split_assignments.values()
    ]
    dataset_type_order.extend(
        sorted(
            label for label in set(split_assignments.values()) if label not in {'train_val', 'test'}
        )
    )

    ordered_rows: list[dict[str, Any]] = []
    pair_ids_by_dataset_type: dict[str, list[str]] = {}
    for dataset_type in dataset_type_order:
        pair_ids = sorted(
            pair_id
            for pair_id, value in split_assignments.items()
            if value == dataset_type and pair_id in surviving_pairs
        )
        pair_ids_by_dataset_type[dataset_type] = pair_ids
        for pair_id in pair_ids:
            pair_records = sorted(
                surviving_pairs[pair_id],
                key=lambda row: ROLE_SORT_ORDER.get(str(row['role']), 99),
            )
            for row in pair_records:
                row_with_split = dict(row)
                row_with_split['dataset_type'] = dataset_type
                ordered_rows.append(row_with_split)

    return ordered_rows, pair_ids_by_dataset_type


def _write_dataset_csv_and_slices(
    ordered_rows: list[dict[str, Any]],
    csv_path: Path,
    normalized_slices_dir: Path,
) -> dict[tuple[str, str], int]:
    kept_unique_id_by_pair_role: dict[tuple[str, str], int] = {}
    with csv_path.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                'file_name',
                'unique_id',
                'target',
                'vulnerable_line_numbers',
                'project',
                'source_signature_path',
                'commit_hash',
                'dataset_type',
                'processed_func',
            ]
        )
        for idx, row in enumerate(ordered_rows, start=1):
            output_filename = f'{idx}{row["extension"]}'
            (normalized_slices_dir / output_filename).write_text(
                row['normalized_code'], encoding='utf-8'
            )
            vulnerable_line_numbers = 1 if int(row['target']) == 1 else ''
            kept_unique_id_by_pair_role[(str(row['pair_id']), str(row['role']))] = idx
            writer.writerow(
                [
                    idx,
                    idx,
                    row['target'],
                    vulnerable_line_numbers,
                    'Juliet',
                    row['source_signature_path'],
                    '',
                    row['dataset_type'],
                    row['normalized_code'],
                ]
            )

    return kept_unique_id_by_pair_role


def _write_dedup_audit_csv(dedup_audit_rows: list[dict[str, Any]], dedup_dropped_csv: Path) -> None:
    with dedup_dropped_csv.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                'dropped_row_id',
                'pair_id',
                'testcase_key',
                'role',
                'role_name',
                'target',
                'project',
                'source_signature_path',
                'normalized_code_hash',
                'dedup_reason',
                'dedup_trigger_hashes',
                'matched_kept_pair_id',
                'matched_kept_role',
                'matched_kept_source_signature_path',
                'matched_kept_unique_id',
                'processed_func',
            ]
        )
        for dropped_row_id, row in enumerate(dedup_audit_rows, start=1):
            writer.writerow(
                [
                    dropped_row_id,
                    row['pair_id'],
                    row['testcase_key'],
                    row['role'],
                    row['role_name'],
                    row['target'],
                    row['project'],
                    row['source_signature_path'],
                    row['normalized_code_hash'],
                    row['dedup_reason'],
                    row['dedup_trigger_hashes'],
                    row['matched_kept_pair_id'],
                    row['matched_kept_role'],
                    row['matched_kept_source_signature_path'],
                    row['matched_kept_unique_id'],
                    row['processed_func'],
                ]
            )


def run_step07_export_core(
    *,
    pairs: list[dict[str, Any]],
    paired_signatures_dir: Path,
    slice_dir: Path,
    csv_path: Path,
    dedup_dropped_csv: Path,
    normalized_slices_dir: Path,
    token_counts_csv: Path,
    token_distribution_png: Path,
    split_manifest_json: Path,
    summary_json: Path,
    dedup_mode: str,
    split_assignments_fn: Callable[[list[str]], dict[str, str]],
    summary_metadata: dict[str, Any],
    split_manifest_metadata: dict[str, Any],
    collect_defined_function_names_fn: Callable[
        [Path, dict[str, object]], tuple[set[str], str | None]
    ],
    build_source_file_candidates_fn: Callable[[dict[str, Any], str | None], list[Path]],
) -> dict[str, Any]:
    from shared.slice_tokenizer import (
        CONTENT_TOKEN_LIMIT,
        MAX_LENGTH,
        count_code_tokens,
        load_tokenizer,
        plot_distribution,
    )

    _prepare_export_outputs(csv_path=csv_path, normalized_slices_dir=normalized_slices_dir)

    print('Loading tokenizer for normalized slices...')
    tokenizer = load_tokenizer('microsoft/codebert-base')

    (
        surviving_pairs,
        filtered_pair_reasons,
        counts,
        source_parse_error_cache,
        source_files_seen,
        source_files_failed,
    ) = _collect_surviving_pairs(
        pairs=pairs,
        slice_dir=slice_dir,
        tokenizer=tokenizer,
        content_token_limit=CONTENT_TOKEN_LIMIT,
        count_code_tokens=count_code_tokens,
        collect_defined_function_names_fn=collect_defined_function_names_fn,
        build_source_file_candidates_fn=build_source_file_candidates_fn,
    )

    surviving_pairs, dedup_summary, dedup_audit_rows = dedupe_pairs_by_normalized_rows(
        surviving_pairs=surviving_pairs,
        filtered_pair_reasons=filtered_pair_reasons,
        dedup_mode=dedup_mode,
    )
    dedup_dropped_pairs = len({str(row['pair_id']) for row in dedup_audit_rows})
    dedup_dropped_rows = len(dedup_audit_rows)

    token_count_rows = sorted(
        [row for pair_records in surviving_pairs.values() for row in pair_records],
        key=lambda row: (
            row['pair_id'],
            ROLE_SORT_ORDER.get(str(row['role']), 99),
            row['slice_filename'],
        ),
    )
    _write_token_counts_csv(token_count_rows, token_counts_csv)
    plot_distribution(token_count_rows, token_distribution_png)

    split_assignments = split_assignments_fn(list(surviving_pairs.keys()))
    ordered_rows, pair_ids_by_dataset_type = _build_ordered_rows(
        surviving_pairs,
        split_assignments,
    )
    kept_unique_id_by_pair_role = _write_dataset_csv_and_slices(
        ordered_rows,
        csv_path,
        normalized_slices_dir,
    )

    for audit_row in dedup_audit_rows:
        matched_pair_id = str(audit_row.get('matched_kept_pair_id') or '')
        matched_role = str(audit_row.get('matched_kept_role') or '')
        if matched_pair_id and matched_role:
            audit_row['matched_kept_unique_id'] = str(
                kept_unique_id_by_pair_role.get((matched_pair_id, matched_role), '')
            )

    _write_dedup_audit_csv(dedup_audit_rows, dedup_dropped_csv)

    split_manifest = {
        **split_manifest_metadata,
        'normalized_slices_dir': str(normalized_slices_dir),
        'dedup_dropped_csv': str(dedup_dropped_csv),
        'dedup': dedup_summary,
        'counts': {
            'pairs_total': len(surviving_pairs),
            'train_val': len(pair_ids_by_dataset_type.get('train_val', [])),
            'test': len(pair_ids_by_dataset_type.get('test', [])),
            'rows_total': len(ordered_rows),
            'dedup_dropped_pairs': dedup_dropped_pairs,
            'dedup_dropped_rows': dedup_dropped_rows,
        },
        'pair_ids': {
            'train_val': pair_ids_by_dataset_type.get('train_val', []),
            'test': pair_ids_by_dataset_type.get('test', []),
        },
    }
    split_manifest_json.write_text(
        json.dumps(split_manifest, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )

    token_values = [int(row['code_token_count']) for row in token_count_rows]
    mean_value = (sum(token_values) / len(token_values)) if token_values else 0.0
    sorted_values = sorted(token_values)
    median_value = sorted_values[len(sorted_values) // 2] if sorted_values else 0

    counts['pairs_survived'] = len(surviving_pairs)
    counts['pairs_filtered_out'] = sum(filtered_pair_reasons.values())
    counts['rows_written'] = len(ordered_rows)
    counts['dedup_dropped_pairs'] = dedup_dropped_pairs
    counts['dedup_dropped_rows'] = dedup_dropped_rows
    counts['source_files_total'] = len(source_files_seen)
    counts['source_files_parse_failed'] = len(source_files_failed)
    counts['train_val_pairs'] = len(pair_ids_by_dataset_type.get('train_val', []))
    counts['test_pairs'] = len(pair_ids_by_dataset_type.get('test', []))
    counts['train_val_rows'] = sum(1 for row in ordered_rows if row['dataset_type'] == 'train_val')
    counts['test_rows'] = sum(1 for row in ordered_rows if row['dataset_type'] == 'test')

    summary_payload = {
        **summary_metadata,
        'normalized_slices_dir': str(normalized_slices_dir),
        'dedup_dropped_csv': str(dedup_dropped_csv),
        'split_manifest_json': str(split_manifest_json),
        'dedup': dedup_summary,
        'max_length': MAX_LENGTH,
        'content_token_limit': CONTENT_TOKEN_LIMIT,
        'token_stats': {
            'total': len(token_values),
            'mean': round(mean_value, 6),
            'median': median_value,
            'over_limit_count': sum(1 for value in token_values if value > CONTENT_TOKEN_LIMIT),
        },
        'filtered_pair_reasons': dict(filtered_pair_reasons),
        'source_file_parse_errors': source_parse_error_cache,
        'counts': dict(counts),
    }
    if (
        'token_counts_csv' not in summary_payload
        and 'normalized_token_counts_csv' not in summary_payload
    ):
        summary_payload['token_counts_csv'] = str(token_counts_csv)
    if (
        'token_distribution_png' not in summary_payload
        and 'slice_token_distribution_png' not in summary_payload
    ):
        summary_payload['token_distribution_png'] = str(token_distribution_png)
    summary_json.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    print(json.dumps(summary_payload, ensure_ascii=False))

    return {
        'csv_path': csv_path,
        'dedup_dropped_csv': dedup_dropped_csv,
        'normalized_slices_dir': normalized_slices_dir,
        'token_counts_csv': token_counts_csv,
        'token_distribution_png': token_distribution_png,
        'split_manifest_json': split_manifest_json,
        'summary_json': summary_json,
        'counts': dict(counts),
    }
