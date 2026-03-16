from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Callable

from shared.artifact_layout import build_dataset_export_paths
from shared.csvio import write_csv_rows
from shared.dataset_dedup import ROLE_SORT_ORDER, dedupe_pairs_by_normalized_rows
from shared.dataset_normalize import normalize_slice_function_names
from shared.dataset_sources import (
    find_slice_path,
    load_tree_sitter_parsers,
    normalize_artifact_path,
)
from shared.jsonio import write_json


def _prepare_export_outputs(*, csv_path: Path, normalized_slices_dir: Path) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    normalized_slices_dir.mkdir(parents=True, exist_ok=True)


def build_step07_export_paths(
    output_dir: Path, dataset_basename: str | None = None
) -> dict[str, Path]:
    return build_dataset_export_paths(output_dir, dataset_basename)


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
    export_paths = build_dataset_export_paths(
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


def _build_role_specs(pair: dict[str, Any]) -> list[dict[str, Any]]:
    output_files = pair.get('output_files') or {}
    counterpart_flow_type = str(pair.get('counterpart_flow_type') or '')
    return [
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


def _load_signature_payload(signature_path: Path) -> dict[str, Any]:
    return json.loads(signature_path.read_text(encoding='utf-8'))


def _collect_user_defined_function_names(
    *,
    source_candidates: list[Path],
    parsers: dict[str, object],
    collect_defined_function_names_fn: Callable[
        [Path, dict[str, object]], tuple[set[str], str | None]
    ],
    source_func_cache: dict[str, set[str]],
    source_parse_error_cache: dict[str, str],
    source_files_seen: set[str],
    source_files_failed: set[str],
) -> set[str]:
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
    return user_defined_function_names


def _build_pair_role_record(
    *,
    pair_id: str,
    testcase_key: str,
    role: dict[str, Any],
    slice_dir: Path,
    tokenizer: object,
    content_token_limit: int,
    count_code_tokens: Callable[[object, str], int],
    parsers: dict[str, object],
    collect_defined_function_names_fn: Callable[
        [Path, dict[str, object]], tuple[set[str], str | None]
    ],
    build_source_file_candidates_fn: Callable[[dict[str, Any], str | None], list[Path]],
    source_func_cache: dict[str, set[str]],
    source_parse_error_cache: dict[str, str],
    source_files_seen: set[str],
    source_files_failed: set[str],
    counts: Counter,
) -> tuple[dict[str, Any] | None, str | None]:
    role_name = str(role['role_name'])
    if not role_name:
        return None, 'missing_role_name'

    signature_path_raw = str(role['signature_path_raw'])
    if not signature_path_raw:
        return None, 'missing_signature_path'

    signature_path = Path(signature_path_raw)
    if not signature_path.exists():
        return None, 'missing_signature_file'

    slice_path = find_slice_path(slice_dir, testcase_key, role_name)
    if slice_path is None:
        return None, 'missing_slice_file'

    signature_payload = _load_signature_payload(signature_path)
    primary_file_hint = role['signature_info'].get('primary_file')
    source_candidates = build_source_file_candidates_fn(signature_payload, primary_file_hint)
    user_defined_function_names = _collect_user_defined_function_names(
        source_candidates=source_candidates,
        parsers=parsers,
        collect_defined_function_names_fn=collect_defined_function_names_fn,
        source_func_cache=source_func_cache,
        source_parse_error_cache=source_parse_error_cache,
        source_files_seen=source_files_seen,
        source_files_failed=source_files_failed,
    )

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

    return {
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
    }, None


def _validate_pair_records(pair_records: list[dict[str, Any]]) -> str | None:
    if len(pair_records) != 2:
        return 'invalid_pair_cardinality'
    if any(record['exceeds_510'] for record in pair_records):
        return 'over_limit'
    return None


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
        roles = _build_role_specs(pair)

        pair_records: list[dict[str, Any]] = []
        pair_invalid_reason: str | None = None

        for role in roles:
            record, pair_invalid_reason = _build_pair_role_record(
                pair_id=pair_id,
                testcase_key=testcase_key,
                role=role,
                slice_dir=slice_dir,
                tokenizer=tokenizer,
                content_token_limit=content_token_limit,
                count_code_tokens=count_code_tokens,
                parsers=parsers,
                collect_defined_function_names_fn=collect_defined_function_names_fn,
                build_source_file_candidates_fn=build_source_file_candidates_fn,
                source_func_cache=source_func_cache,
                source_parse_error_cache=source_parse_error_cache,
                source_files_seen=source_files_seen,
                source_files_failed=source_files_failed,
                counts=counts,
            )
            if pair_invalid_reason is not None:
                break
            assert record is not None
            pair_records.append(record)

        if pair_invalid_reason is not None:
            filtered_pair_reasons[pair_invalid_reason] += 1
            continue

        pair_invalid_reason = _validate_pair_records(pair_records)
        if pair_invalid_reason is not None:
            filtered_pair_reasons[pair_invalid_reason] += 1
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
    write_csv_rows(
        token_counts_csv,
        [
            'pair_id',
            'filename',
            'extension',
            'role',
            'code_token_count',
            'input_token_count_with_special',
            'exceeds_510',
        ],
        (
            [
                row['pair_id'],
                row['slice_filename'],
                row['extension'],
                row['role'],
                row['code_token_count'],
                row['input_token_count_with_special'],
                row['exceeds_510'],
            ]
            for row in token_count_rows
        ),
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
    rows: list[list[Any]] = []
    for idx, row in enumerate(ordered_rows, start=1):
        output_filename = f'{idx}{row["extension"]}'
        (normalized_slices_dir / output_filename).write_text(
            row['normalized_code'], encoding='utf-8'
        )
        vulnerable_line_numbers = 1 if int(row['target']) == 1 else ''
        kept_unique_id_by_pair_role[(str(row['pair_id']), str(row['role']))] = idx
        rows.append(
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
    write_csv_rows(
        csv_path,
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
        ],
        rows,
    )

    return kept_unique_id_by_pair_role


def _write_dedup_audit_csv(dedup_audit_rows: list[dict[str, Any]], dedup_dropped_csv: Path) -> None:
    write_csv_rows(
        dedup_dropped_csv,
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
        ],
        (
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
            for dropped_row_id, row in enumerate(dedup_audit_rows, start=1)
        ),
    )


def _collect_and_filter_pairs(
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
    return _collect_surviving_pairs(
        pairs=pairs,
        slice_dir=slice_dir,
        tokenizer=tokenizer,
        content_token_limit=content_token_limit,
        count_code_tokens=count_code_tokens,
        collect_defined_function_names_fn=collect_defined_function_names_fn,
        build_source_file_candidates_fn=build_source_file_candidates_fn,
    )


def _apply_dedup(
    *,
    surviving_pairs: dict[str, list[dict[str, Any]]],
    filtered_pair_reasons: Counter,
    dedup_mode: str,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any], list[dict[str, Any]], int, int]:
    surviving_pairs, dedup_summary, dedup_audit_rows = dedupe_pairs_by_normalized_rows(
        surviving_pairs=surviving_pairs,
        filtered_pair_reasons=filtered_pair_reasons,
        dedup_mode=dedup_mode,
    )
    dedup_dropped_pairs = len({str(row['pair_id']) for row in dedup_audit_rows})
    dedup_dropped_rows = len(dedup_audit_rows)
    return (
        surviving_pairs,
        dedup_summary,
        dedup_audit_rows,
        dedup_dropped_pairs,
        dedup_dropped_rows,
    )


def _write_export_artifacts(
    *,
    surviving_pairs: dict[str, list[dict[str, Any]]],
    split_assignments_fn: Callable[[list[str]], dict[str, str]],
    csv_path: Path,
    normalized_slices_dir: Path,
    token_counts_csv: Path,
    token_distribution_png: Path,
    dedup_audit_rows: list[dict[str, Any]],
    dedup_dropped_csv: Path,
    plot_distribution_fn: Callable[[list[dict[str, Any]], Path], None],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, list[str]]]:
    token_count_rows = sorted(
        [row for pair_records in surviving_pairs.values() for row in pair_records],
        key=lambda row: (
            row['pair_id'],
            ROLE_SORT_ORDER.get(str(row['role']), 99),
            row['slice_filename'],
        ),
    )
    _write_token_counts_csv(token_count_rows, token_counts_csv)
    plot_distribution_fn(token_count_rows, token_distribution_png)

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
    return token_count_rows, ordered_rows, pair_ids_by_dataset_type


def _build_export_summary(
    *,
    summary_metadata: dict[str, Any],
    split_manifest_metadata: dict[str, Any],
    normalized_slices_dir: Path,
    dedup_dropped_csv: Path,
    split_manifest_json: Path,
    token_counts_csv: Path,
    token_distribution_png: Path,
    dedup_summary: dict[str, Any],
    filtered_pair_reasons: Counter,
    counts: Counter,
    source_parse_error_cache: dict[str, str],
    source_files_seen: set[str],
    source_files_failed: set[str],
    surviving_pairs: dict[str, list[dict[str, Any]]],
    pair_ids_by_dataset_type: dict[str, list[str]],
    ordered_rows: list[dict[str, Any]],
    token_count_rows: list[dict[str, Any]],
    dedup_dropped_pairs: int,
    dedup_dropped_rows: int,
    max_length: int,
    content_token_limit: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
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
        'max_length': max_length,
        'content_token_limit': content_token_limit,
        'token_stats': {
            'total': len(token_values),
            'mean': round(mean_value, 6),
            'median': median_value,
            'over_limit_count': sum(1 for value in token_values if value > content_token_limit),
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
    return split_manifest, summary_payload


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
    ) = _collect_and_filter_pairs(
        pairs=pairs,
        slice_dir=slice_dir,
        tokenizer=tokenizer,
        content_token_limit=CONTENT_TOKEN_LIMIT,
        count_code_tokens=count_code_tokens,
        collect_defined_function_names_fn=collect_defined_function_names_fn,
        build_source_file_candidates_fn=build_source_file_candidates_fn,
    )

    (
        surviving_pairs,
        dedup_summary,
        dedup_audit_rows,
        dedup_dropped_pairs,
        dedup_dropped_rows,
    ) = _apply_dedup(
        surviving_pairs=surviving_pairs,
        filtered_pair_reasons=filtered_pair_reasons,
        dedup_mode=dedup_mode,
    )

    token_count_rows, ordered_rows, pair_ids_by_dataset_type = _write_export_artifacts(
        surviving_pairs=surviving_pairs,
        split_assignments_fn=split_assignments_fn,
        csv_path=csv_path,
        normalized_slices_dir=normalized_slices_dir,
        token_counts_csv=token_counts_csv,
        token_distribution_png=token_distribution_png,
        dedup_audit_rows=dedup_audit_rows,
        dedup_dropped_csv=dedup_dropped_csv,
        plot_distribution_fn=plot_distribution,
    )

    split_manifest, summary_payload = _build_export_summary(
        summary_metadata=summary_metadata,
        split_manifest_metadata=split_manifest_metadata,
        normalized_slices_dir=normalized_slices_dir,
        dedup_dropped_csv=dedup_dropped_csv,
        split_manifest_json=split_manifest_json,
        token_counts_csv=token_counts_csv,
        token_distribution_png=token_distribution_png,
        dedup_summary=dedup_summary,
        filtered_pair_reasons=filtered_pair_reasons,
        counts=counts,
        source_parse_error_cache=source_parse_error_cache,
        source_files_seen=source_files_seen,
        source_files_failed=source_files_failed,
        surviving_pairs=surviving_pairs,
        pair_ids_by_dataset_type=pair_ids_by_dataset_type,
        ordered_rows=ordered_rows,
        token_count_rows=token_count_rows,
        dedup_dropped_pairs=dedup_dropped_pairs,
        dedup_dropped_rows=dedup_dropped_rows,
        max_length=MAX_LENGTH,
        content_token_limit=CONTENT_TOKEN_LIMIT,
    )
    write_json(split_manifest_json, split_manifest)
    write_json(summary_json, summary_payload)
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
