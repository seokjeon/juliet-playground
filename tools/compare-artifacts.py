#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.artifact_layout import (
    TRAIN_PATCHED_COUNTERPARTS_BASENAME,
    build_dataset_export_paths,
    build_pair_trace_paths,
    build_patched_pairing_paths,
)
from shared.jsonio import load_json, load_jsonl

VOLATILE_KEYS = {
    'generated_at',
    'started_at',
    'ended_at',
    'duration_sec',
    'output_dir',
    'normalized_slices_dir',
    'pairs_jsonl',
    'paired_signatures_dir',
    'slice_dir',
    'dedup_dropped_csv',
    'split_manifest_json',
    'csv_path',
    'token_counts_csv',
    'token_distribution_png',
    'normalized_token_counts_csv',
    'real_vul_data_csv',
    'source_pairs_jsonl',
    'source_leftover_counterparts_jsonl',
    'source_split_manifest_json',
    'signature_output_dir',
    'output_pairs_jsonl',
    'selection_summary_json',
    'metadata_json',
    'step07_summary_json',
    'step07_split_manifest_json',
    'step07b_summary_json',
    'slice_summary_json',
    'summary_json',
    'slice_output_dir',
    'signature_db_dir',
    'dataset_export_dir',
    'run_dir',
    'pipeline_root',
    'infer_results_root',
    'infer_run_dir',
    'signatures_root',
    'signature_output_dir',
    'signature_non_empty_dir',
    'analysis_result_csv',
    'analysis_no_issue_files',
    'stdout_log',
    'stderr_log',
    'input_manifest',
    'source_root',
    'committed_taint_config_path',
    'generated_taint_config_path',
    'selected_taint_config_path',
    'trace_jsonl',
}


@dataclass
class Reporter:
    limit: int
    lines: list[str]
    changes: int = 0

    def add(self, line: str = '') -> None:
        self.lines.append(line)

    def section(self, title: str) -> None:
        if self.lines:
            self.lines.append('')
        self.lines.append(title)

    def note_change(self, message: str) -> None:
        self.changes += 1
        self.lines.append(message)

    def render(self) -> str:
        if not self.lines:
            return 'No differences found.\n'
        return '\n'.join(self.lines).rstrip() + '\n'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Compare before/after pipeline or dataset export artifacts.'
    )
    parser.add_argument('before', type=Path, help='Before artifact directory')
    parser.add_argument('after', type=Path, help='After artifact directory')
    parser.add_argument(
        '--limit', type=int, default=20, help='Max preview entries per changed section'
    )
    return parser.parse_args()


def detect_artifact_kind(path: Path) -> str:
    path = path.resolve()
    if not path.exists() or not path.is_dir():
        raise FileNotFoundError(f'Artifact path not found or not a directory: {path}')
    primary_dataset_paths = build_dataset_export_paths(path)
    if (path / 'run_summary.json').exists():
        return 'pipeline_run'
    if (
        primary_dataset_paths['summary_json'].exists()
        and primary_dataset_paths['split_manifest_json'].exists()
        and primary_dataset_paths['csv_path'].exists()
    ):
        return 'dataset_export'
    raise ValueError(
        'Unsupported artifact directory. Expected a pipeline run dir or 07_dataset_export* dir: '
        f'{path}'
    )


def normalize_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: normalize_json_value(val)
            for key, val in sorted(value.items())
            if key not in VOLATILE_KEYS
        }
    if isinstance(value, list):
        return [normalize_json_value(item) for item in value]
    return value


def diff_json(before: Any, after: Any, prefix: str = '') -> list[str]:
    diffs: list[str] = []
    if before.__class__ is not after.__class__:
        diffs.append(f'{prefix}: type {type(before).__name__} -> {type(after).__name__}')
        return diffs
    if isinstance(before, dict):
        keys = sorted(set(before) | set(after))
        for key in keys:
            path = f'{prefix}.{key}' if prefix else key
            if key not in before:
                diffs.append(f'{path}: added={after[key]!r}')
            elif key not in after:
                diffs.append(f'{path}: removed')
            else:
                diffs.extend(diff_json(before[key], after[key], path))
        return diffs
    if isinstance(before, list):
        if before != after:
            diffs.append(f'{prefix}: list changed (len {len(before)} -> {len(after)})')
        return diffs
    if before != after:
        diffs.append(f'{prefix}: {before!r} -> {after!r}')
    return diffs


def load_csv_rows(path: Path) -> list[dict[str, str]]:
    with path.open(newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def sha1_text(text: str) -> str:
    return hashlib.sha1(str(text).encode('utf-8')).hexdigest()


def make_real_vul_key(row: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        str(row.get('dataset_type') or ''),
        str(row.get('target') or ''),
        str(row.get('source_signature_path') or ''),
        sha1_text(str(row.get('processed_func') or '')),
    )


def make_dedup_key(row: dict[str, str]) -> tuple[str, str, str, str]:
    return (
        str(row.get('role') or ''),
        str(row.get('source_signature_path') or ''),
        str(row.get('normalized_code_hash') or ''),
        str(row.get('dedup_reason') or ''),
    )


def make_token_count_key(row: dict[str, str]) -> tuple[str, str, str]:
    return (
        str(row.get('pair_id') or ''),
        str(row.get('role') or ''),
        str(row.get('filename') or ''),
    )


def preview(items: list[str], limit: int) -> list[str]:
    return items[:limit]


def report_json_diff(reporter: Reporter, label: str, before_path: Path, after_path: Path) -> None:
    if not before_path.exists() and not after_path.exists():
        return
    if before_path.exists() != after_path.exists():
        reporter.note_change(
            f'- {label}: presence differs ({before_path.exists()} -> {after_path.exists()})'
        )
        return
    before = normalize_json_value(load_json(before_path))
    after = normalize_json_value(load_json(after_path))
    diffs = diff_json(before, after)
    if diffs:
        reporter.note_change(f'- {label}: changed ({len(diffs)} key-level diffs)')
        for item in preview(diffs, reporter.limit):
            reporter.add(f'  * {item}')


def report_keyed_csv_diff(
    reporter: Reporter,
    label: str,
    before_path: Path,
    after_path: Path,
    key_fn,
) -> None:
    if not before_path.exists() and not after_path.exists():
        return
    if before_path.exists() != after_path.exists():
        reporter.note_change(
            f'- {label}: presence differs ({before_path.exists()} -> {after_path.exists()})'
        )
        return
    before_rows = load_csv_rows(before_path)
    after_rows = load_csv_rows(after_path)
    before_map = {key_fn(row): row for row in before_rows}
    after_map = {key_fn(row): row for row in after_rows}

    added = sorted(set(after_map) - set(before_map))
    removed = sorted(set(before_map) - set(after_map))
    changed = sorted(
        key for key in before_map if key in after_map and before_map[key] != after_map[key]
    )
    if added or removed or changed:
        reporter.note_change(
            f'- {label}: added={len(added)} removed={len(removed)} changed={len(changed)}'
        )
        for item in preview([f'added {key!r}' for key in added], reporter.limit):
            reporter.add(f'  * {item}')
        for item in preview([f'removed {key!r}' for key in removed], reporter.limit):
            reporter.add(f'  * {item}')
        for item in preview([f'changed {key!r}' for key in changed], reporter.limit):
            reporter.add(f'  * {item}')


def project_pair(row: dict[str, Any]) -> dict[str, Any]:
    return {
        'counterpart_flow_type': row.get('counterpart_flow_type'),
        'b2b_bug_trace_length': row.get('b2b_bug_trace_length'),
        'counterpart_bug_trace_length': row.get('counterpart_bug_trace_length'),
        'b2b_procedure': (row.get('b2b_signature') or {}).get('procedure'),
        'counterpart_procedure': (row.get('counterpart_signature') or {}).get('procedure'),
    }


def report_pairs_jsonl_diff(reporter: Reporter, before_path: Path, after_path: Path) -> None:
    if before_path.exists() != after_path.exists():
        reporter.note_change(
            f'- 05_pair_trace_ds/pairs.jsonl: presence differs ({before_path.exists()} -> {after_path.exists()})'
        )
        return
    before_map = {row['testcase_key']: project_pair(row) for row in load_jsonl(before_path)}
    after_map = {row['testcase_key']: project_pair(row) for row in load_jsonl(after_path)}
    added = sorted(set(after_map) - set(before_map))
    removed = sorted(set(before_map) - set(after_map))
    changed = sorted(
        key for key in before_map if key in after_map and before_map[key] != after_map[key]
    )
    if added or removed or changed:
        reporter.note_change(
            f'- 05_pair_trace_ds/pairs.jsonl: added={len(added)} removed={len(removed)} changed={len(changed)}'
        )
        for item in preview([f'added {key}' for key in added], reporter.limit):
            reporter.add(f'  * {item}')
        for item in preview([f'removed {key}' for key in removed], reporter.limit):
            reporter.add(f'  * {item}')
        for item in preview([f'changed {key}' for key in changed], reporter.limit):
            reporter.add(f'  * {item}')


def report_leftovers_diff(reporter: Reporter, before_path: Path, after_path: Path) -> None:
    if before_path.exists() != after_path.exists():
        reporter.note_change(
            f'- 05_pair_trace_ds/leftover_counterparts.jsonl: presence differs ({before_path.exists()} -> {after_path.exists()})'
        )
        return
    before_grouped: dict[str, list[tuple[Any, ...]]] = {}
    after_grouped: dict[str, list[tuple[Any, ...]]] = {}
    for target, rows in (
        (before_grouped, load_jsonl(before_path)),
        (after_grouped, load_jsonl(after_path)),
    ):
        for row in rows:
            key = str(row.get('testcase_key') or '')
            target.setdefault(key, []).append(
                (
                    row.get('best_flow_type'),
                    row.get('bug_trace_length'),
                    row.get('procedure'),
                    row.get('primary_file'),
                    row.get('primary_line'),
                )
            )
        for key in target:
            target[key] = sorted(target[key])
    added = sorted(set(after_grouped) - set(before_grouped))
    removed = sorted(set(before_grouped) - set(after_grouped))
    changed = sorted(
        key
        for key in before_grouped
        if key in after_grouped and before_grouped[key] != after_grouped[key]
    )
    if added or removed or changed:
        reporter.note_change(
            f'- 05_pair_trace_ds/leftover_counterparts.jsonl: added={len(added)} removed={len(removed)} changed={len(changed)}'
        )
        for item in preview([f'added {key}' for key in added], reporter.limit):
            reporter.add(f'  * {item}')
        for item in preview([f'removed {key}' for key in removed], reporter.limit):
            reporter.add(f'  * {item}')
        for item in preview([f'changed {key}' for key in changed], reporter.limit):
            reporter.add(f'  * {item}')


def compare_dataset_export(before_dir: Path, after_dir: Path, reporter: Reporter) -> None:
    reporter.section('Dataset Export')
    for dataset_basename in (None, TRAIN_PATCHED_COUNTERPARTS_BASENAME):
        before_paths = build_dataset_export_paths(before_dir, dataset_basename)
        after_paths = build_dataset_export_paths(after_dir, dataset_basename)
        report_json_diff(
            reporter,
            before_paths['summary_json'].name,
            before_paths['summary_json'],
            after_paths['summary_json'],
        )
        report_json_diff(
            reporter,
            before_paths['split_manifest_json'].name,
            before_paths['split_manifest_json'],
            after_paths['split_manifest_json'],
        )
        report_keyed_csv_diff(
            reporter,
            before_paths['csv_path'].name,
            before_paths['csv_path'],
            after_paths['csv_path'],
            make_real_vul_key,
        )
        report_keyed_csv_diff(
            reporter,
            before_paths['dedup_dropped_csv'].name,
            before_paths['dedup_dropped_csv'],
            after_paths['dedup_dropped_csv'],
            make_dedup_key,
        )
        report_keyed_csv_diff(
            reporter,
            before_paths['token_counts_csv'].name,
            before_paths['token_counts_csv'],
            after_paths['token_counts_csv'],
            make_token_count_key,
        )


def compare_pair_trace(before_dir: Path, after_dir: Path, reporter: Reporter) -> None:
    reporter.section('Pair Trace Dataset')
    before_paths = build_pair_trace_paths(before_dir)
    after_paths = build_pair_trace_paths(after_dir)
    before_patched_paths = build_patched_pairing_paths(before_dir)
    after_patched_paths = build_patched_pairing_paths(after_dir)
    report_json_diff(
        reporter,
        before_paths['summary_json'].name,
        before_paths['summary_json'],
        after_paths['summary_json'],
    )
    report_pairs_jsonl_diff(
        reporter,
        before_paths['pairs_jsonl'],
        after_paths['pairs_jsonl'],
    )
    report_leftovers_diff(
        reporter,
        before_paths['leftover_counterparts_jsonl'],
        after_paths['leftover_counterparts_jsonl'],
    )
    report_json_diff(
        reporter,
        before_patched_paths['selection_summary_json'].name,
        before_patched_paths['selection_summary_json'],
        after_patched_paths['selection_summary_json'],
    )


def compare_pipeline_runs(before_run: Path, after_run: Path, reporter: Reporter) -> None:
    compare_pair_trace(
        before_run / '05_pair_trace_ds',
        after_run / '05_pair_trace_ds',
        reporter,
    )
    compare_dataset_export(
        before_run / '07_dataset_export',
        after_run / '07_dataset_export',
        reporter,
    )


def main() -> int:
    args = parse_args()
    before = args.before.resolve()
    after = args.after.resolve()

    try:
        before_kind = detect_artifact_kind(before)
        after_kind = detect_artifact_kind(after)
        if before_kind != after_kind:
            print(
                f'Artifact kind mismatch: before={before_kind}, after={after_kind}',
                file=sys.stderr,
            )
            return 1
    except (FileNotFoundError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    reporter = Reporter(limit=args.limit, lines=[])
    reporter.add(f'Kind: {before_kind}')
    reporter.add(f'Before: {before}')
    reporter.add(f'After:  {after}')

    if before_kind == 'dataset_export':
        compare_dataset_export(before, after, reporter)
    elif before_kind == 'pipeline_run':
        compare_pipeline_runs(before, after, reporter)
    else:
        print(f'Unsupported artifact kind: {before_kind}', file=sys.stderr)
        return 1

    reporter.section('Overall')
    if reporter.changes == 0:
        reporter.add('No differences found.')
    else:
        reporter.add(f'Differences found in {reporter.changes} sections.')

    print(reporter.render(), end='')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
