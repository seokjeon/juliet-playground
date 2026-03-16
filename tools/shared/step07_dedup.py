from __future__ import annotations

from collections import Counter
from typing import Any

from shared.step07_normalize import normalized_code_md5

ROLE_SORT_ORDER = {'b2b': 0, 'counterpart': 1}


def unique_in_order(values: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not value or value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def build_dedup_audit_row(
    *,
    record: dict[str, Any],
    dedup_reason: str,
    dedup_trigger_hashes: list[str],
    matched_kept_record: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        'pair_id': str(record['pair_id']),
        'testcase_key': str(record['testcase_key']),
        'role': str(record['role']),
        'role_name': str(record['role_name']),
        'target': int(record['target']),
        'project': 'Juliet',
        'source_signature_path': str(record.get('source_signature_path') or ''),
        'normalized_code_hash': str(record.get('normalized_code_hash') or ''),
        'dedup_reason': dedup_reason,
        'dedup_trigger_hashes': '|'.join(dedup_trigger_hashes),
        'matched_kept_pair_id': str(matched_kept_record.get('pair_id') or '')
        if matched_kept_record
        else '',
        'matched_kept_role': str(matched_kept_record.get('role') or '')
        if matched_kept_record
        else '',
        'matched_kept_source_signature_path': (
            str(matched_kept_record.get('source_signature_path') or '')
            if matched_kept_record
            else ''
        ),
        'matched_kept_unique_id': '',
        'processed_func': str(record['normalized_code']),
    }


def dedupe_pairs_by_normalized_rows(
    *,
    surviving_pairs: dict[str, list[dict[str, Any]]],
    filtered_pair_reasons: Counter,
    dedup_mode: str,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, Any], list[dict[str, Any]]]:
    if dedup_mode not in {'none', 'row'}:
        raise ValueError(f'Unsupported dedup_mode: {dedup_mode}')

    ordered_pair_ids = list(surviving_pairs.keys())
    row_occurrences: dict[str, list[dict[str, Any]]] = {}
    label_by_hash: dict[str, int] = {}
    colliding_hashes: set[str] = set()
    rows_before = 0

    for pair_id in ordered_pair_ids:
        pair_records = sorted(
            surviving_pairs[pair_id],
            key=lambda row: ROLE_SORT_ORDER.get(str(row['role']), 99),
        )
        for record in pair_records:
            code_hash = normalized_code_md5(str(record['normalized_code']))
            record['normalized_code_hash'] = code_hash
            target = int(record['target'])
            rows_before += 1
            row_occurrences.setdefault(code_hash, []).append(
                {
                    'pair_id': pair_id,
                    'testcase_key': str(record['testcase_key']),
                    'role': str(record['role']),
                    'target': target,
                }
            )
            old_target = label_by_hash.get(code_hash)
            if old_target is None:
                label_by_hash[code_hash] = target
            elif old_target != target:
                colliding_hashes.add(code_hash)

    duplicate_hash_groups = 0
    duplicate_row_occurrences = 0
    for code_hash, occurrences in row_occurrences.items():
        if code_hash in colliding_hashes:
            continue
        if len(occurrences) > 1:
            duplicate_hash_groups += 1
            duplicate_row_occurrences += len(occurrences) - 1

    collision_row_occurrences = sum(
        len(row_occurrences[code_hash]) for code_hash in colliding_hashes
    )

    if dedup_mode == 'none':
        deduped_pairs = surviving_pairs
        pairs_dropped_duplicate = 0
        pairs_dropped_collision = 0
        dedup_audit_rows: list[dict[str, Any]] = []
    else:
        deduped_pairs: dict[str, list[dict[str, Any]]] = {}
        dedup_audit_rows = []
        kept_record_by_hash: dict[str, dict[str, Any]] = {}
        seen_hashes: set[str] = set()
        pairs_dropped_duplicate = 0
        pairs_dropped_collision = 0

        for pair_id in ordered_pair_ids:
            pair_records = sorted(
                surviving_pairs[pair_id],
                key=lambda row: ROLE_SORT_ORDER.get(str(row['role']), 99),
            )
            pair_hashes = [str(record['normalized_code_hash']) for record in pair_records]
            collision_trigger_hashes = unique_in_order(
                [code_hash for code_hash in pair_hashes if code_hash in colliding_hashes]
            )
            duplicate_trigger_hashes = unique_in_order(
                [code_hash for code_hash in pair_hashes if code_hash in seen_hashes]
            )

            if collision_trigger_hashes:
                filtered_pair_reasons['dedup_row_hash_collision'] += 1
                pairs_dropped_collision += 1
                for record in pair_records:
                    dedup_audit_rows.append(
                        build_dedup_audit_row(
                            record=record,
                            dedup_reason='collision_pair',
                            dedup_trigger_hashes=collision_trigger_hashes,
                            matched_kept_record=None,
                        )
                    )
                continue
            if duplicate_trigger_hashes:
                filtered_pair_reasons['dedup_duplicate_normalized_slice'] += 1
                pairs_dropped_duplicate += 1
                for record in pair_records:
                    dedup_audit_rows.append(
                        build_dedup_audit_row(
                            record=record,
                            dedup_reason='duplicate_pair',
                            dedup_trigger_hashes=duplicate_trigger_hashes,
                            matched_kept_record=kept_record_by_hash.get(
                                str(record['normalized_code_hash'])
                            ),
                        )
                    )
                continue

            deduped_pairs[pair_id] = pair_records
            for record in pair_records:
                code_hash = str(record['normalized_code_hash'])
                seen_hashes.add(code_hash)
                kept_record_by_hash[code_hash] = record

    rows_after = sum(len(records) for records in deduped_pairs.values())
    dedup_summary = {
        'mode': dedup_mode,
        'selection_order': 'input_pair_order',
        'row_hash_method': 'md5(compact_whitespace(normalized_code))',
        'pairs_before': len(surviving_pairs),
        'pairs_after': len(deduped_pairs),
        'pairs_dropped_duplicate': pairs_dropped_duplicate,
        'pairs_dropped_collision': pairs_dropped_collision,
        'rows_before': rows_before,
        'rows_after': rows_after,
        'rows_removed': rows_before - rows_after,
        'row_hashes_unique': len(row_occurrences),
        'duplicate_hash_groups': duplicate_hash_groups,
        'duplicate_row_occurrences': duplicate_row_occurrences,
        'collision_hash_groups': len(colliding_hashes),
        'collision_row_occurrences': collision_row_occurrences,
    }
    return deduped_pairs, dedup_summary, dedup_audit_rows
