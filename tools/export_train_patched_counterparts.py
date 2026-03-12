#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from generate_slices import process_signature_db
from paths import PROJECT_HOME, RESULT_DIR

CPP_LIKE_SUFFIXES = {'.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hh', '.hxx'}
ROLE_SORT_ORDER = {'b2b': 0, 'counterpart': 1}
DATASET_BASENAME = 'train_patched_counterparts'
PROJECT_HOME_PATH = Path(PROJECT_HOME).resolve()


def normalize_artifact_path(path: Path | str) -> str:
    raw = str(path or '').strip()
    if not raw:
        return ''
    candidate = Path(raw)
    if not candidate.is_absolute():
        return str(candidate)
    resolved = candidate.resolve()
    try:
        return str(resolved.relative_to(PROJECT_HOME_PATH))
    except ValueError:
        return str(resolved)


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


def find_latest_pipeline_run_dir(pipeline_root: Path) -> Path:
    if not pipeline_root.exists():
        raise FileNotFoundError(f'Pipeline root not found: {pipeline_root}')
    candidates = [p for p in pipeline_root.iterdir() if p.is_dir() and p.name.startswith('run-')]
    latest = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if latest is None:
        raise FileNotFoundError(f'No run-* directories found under: {pipeline_root}')
    return latest


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


def remove_target(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def prepare_target(path: Path, overwrite: bool) -> None:
    if path.exists():
        if not overwrite:
            raise FileExistsError(
                f'Target already exists: {path}. Re-run with --overwrite to replace it.'
            )
        remove_target(path)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if not isinstance(obj, dict):
                raise ValueError(f'Expected JSON object at line {lineno} in {path}')
            records.append(obj)
    return records


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


def load_signature_payload(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f'Signature JSON not found: {path}')
    with path.open('r', encoding='utf-8') as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError(f'Signature JSON must be an object: {path}')
    return payload


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


def extract_std_bug_trace(bug_trace: Any) -> list[dict[str, Any]]:
    if not isinstance(bug_trace, list) or not bug_trace:
        return []
    first = bug_trace[0]
    if isinstance(first, dict):
        return [node for node in bug_trace if isinstance(node, dict)]
    if isinstance(first, list):
        valid_lists = [sub for sub in bug_trace if isinstance(sub, list)]
        if not valid_lists:
            return []
        selected = max(valid_lists, key=len)
        return [node for node in selected if isinstance(node, dict)]
    return []


def load_tree_sitter_parsers() -> dict[str, object]:
    try:
        from tree_sitter import Parser
        from tree_sitter_languages import get_language
    except Exception:
        return {}

    parsers: dict[str, object] = {}
    for language_name in ('c', 'cpp'):
        parser = Parser()
        lang = get_language(language_name)
        if hasattr(parser, 'set_language'):
            parser.set_language(lang)
        else:
            parser.language = lang
        parsers[language_name] = parser
    return parsers


def candidate_languages_for_source(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix in CPP_LIKE_SUFFIXES:
        return ['cpp', 'c']
    return ['c', 'cpp']


def node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode('utf-8', errors='ignore')


def extract_function_name_from_declarator(node, source_bytes: bytes) -> str | None:
    if node is None:
        return None

    current = node
    for _ in range(12):
        next_node = current.child_by_field_name('declarator')
        if next_node is None:
            break
        current = next_node

    if current.type in {'identifier', 'field_identifier'}:
        return node_text(current, source_bytes)

    name_node = current.child_by_field_name('name')
    if name_node is not None and name_node.type in {'identifier', 'field_identifier'}:
        return node_text(name_node, source_bytes)

    stack = [current]
    while stack:
        candidate = stack.pop()
        if candidate.type in {'identifier', 'field_identifier'}:
            return node_text(candidate, source_bytes)
        stack.extend(reversed(candidate.children))
    return None


def extract_defined_function_names(root_node, source_bytes: bytes) -> set[str]:
    names: set[str] = set()
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == 'function_definition':
            declarator = node.child_by_field_name('declarator')
            name = extract_function_name_from_declarator(declarator, source_bytes)
            if name:
                names.add(name)
        stack.extend(reversed(node.children))
    return names


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


def dedupe_paths(paths: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        deduped.append(path)
        seen.add(key)
    return deduped


def build_source_file_candidates(
    signature_payload: dict[str, Any], primary_file_hint: str | None
) -> list[Path]:
    candidates: list[Path] = []

    bug_trace = extract_std_bug_trace(signature_payload.get('bug_trace', []))
    for node in bug_trace:
        filename = node.get('filename')
        if filename:
            candidates.append(Path(str(filename)))

    top_file_raw = signature_payload.get('file')
    top_file_path: Path | None = None
    if top_file_raw:
        top_file_path = Path(str(top_file_raw))
        candidates.append(top_file_path)

    if primary_file_hint:
        primary_path = Path(primary_file_hint)
        if primary_path.is_absolute():
            candidates.append(primary_path)
        else:
            basename = primary_path.name
            matches = [path for path in candidates if path.name == basename]
            if matches:
                candidates.extend(matches)
            elif top_file_path is not None:
                candidates.append(top_file_path.parent / basename)

    return dedupe_paths(candidates)


def lex_c_like(code: str) -> list[dict[str, str]]:
    tokens: list[dict[str, str]] = []
    i = 0
    n = len(code)

    while i < n:
        ch = code[i]

        if ch.isspace():
            j = i + 1
            while j < n and code[j].isspace():
                j += 1
            tokens.append({'kind': 'ws', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('//', i):
            j = i + 2
            while j < n and code[j] != '\n':
                j += 1
            tokens.append({'kind': 'comment', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('/*', i):
            j = i + 2
            while j < n - 1 and code[j : j + 2] != '*/':
                j += 1
            j = min(n, j + 2 if j < n - 1 else n)
            tokens.append({'kind': 'comment', 'text': code[i:j]})
            i = j
            continue

        if ch == '"':
            j = i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == '"':
                    j += 1
                    break
                j += 1
            tokens.append({'kind': 'string', 'text': code[i:j]})
            i = j
            continue

        if ch == "'":
            j = i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == "'":
                    j += 1
                    break
                j += 1
            tokens.append({'kind': 'char', 'text': code[i:j]})
            i = j
            continue

        if ch.isalpha() or ch == '_':
            j = i + 1
            while j < n and (code[j].isalnum() or code[j] == '_'):
                j += 1
            tokens.append({'kind': 'identifier', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('->', i) or code.startswith('::', i):
            tokens.append({'kind': 'punct', 'text': code[i : i + 2]})
            i += 2
            continue

        tokens.append({'kind': 'punct', 'text': ch})
        i += 1

    return tokens


def previous_meaningful_token(tokens: list[dict[str, str]], index: int) -> dict[str, str] | None:
    for j in range(index - 1, -1, -1):
        token = tokens[j]
        if token['kind'] in {'ws', 'comment'}:
            continue
        return token
    return None


def next_meaningful_token(tokens: list[dict[str, str]], index: int) -> dict[str, str] | None:
    for j in range(index + 1, len(tokens)):
        token = tokens[j]
        if token['kind'] in {'ws', 'comment'}:
            continue
        return token
    return None


def normalize_slice_function_names(
    code: str, user_defined_function_names: set[str]
) -> tuple[str, dict[str, str], int]:
    if not user_defined_function_names:
        return code, {}, 0

    tokens = lex_c_like(code)
    placeholder_map: dict[str, str] = {}
    replacements = 0

    for idx, token in enumerate(tokens):
        if token['kind'] != 'identifier':
            continue
        name = token['text']
        if name not in user_defined_function_names:
            continue

        prev_token = previous_meaningful_token(tokens, idx)
        next_token = next_meaningful_token(tokens, idx)

        if next_token is None or next_token['text'] != '(':
            continue
        if prev_token is not None and prev_token['text'] in {'.', '->', '::'}:
            continue

        placeholder = placeholder_map.get(name)
        if placeholder is None:
            placeholder = f'FUNC_{len(placeholder_map) + 1}'
            placeholder_map[name] = placeholder
        if token['text'] != placeholder:
            token['text'] = placeholder
            replacements += 1

    return ''.join(token['text'] for token in tokens), placeholder_map, replacements


def find_slice_path(slice_dir: Path, testcase_key: str, role_name: str) -> Path | None:
    candidates = [
        slice_dir / f'slice_{testcase_key}_{role_name}.c',
        slice_dir / f'slice_{testcase_key}_{role_name}.cpp',
    ]
    existing = [path for path in candidates if path.exists()]
    if len(existing) > 1:
        raise RuntimeError(
            f'Multiple slice candidates found for {testcase_key}/{role_name}: {existing}'
        )
    return existing[0] if existing else None


def compact_code_for_hash(code: str) -> str:
    return ''.join(str(code).split())


def normalized_code_md5(code: str) -> str:
    return hashlib.md5(compact_code_for_hash(code).encode('utf-8')).hexdigest()


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


def export_dataset(
    *,
    pairs: list[dict[str, Any]],
    paired_signatures_dir: Path,
    slice_dir: Path,
    dataset_export_dir: Path,
    overwrite: bool,
    dedup_mode: str,
) -> dict[str, Any]:
    from tokenize_slices import (
        CONTENT_TOKEN_LIMIT,
        MAX_LENGTH,
        count_code_tokens,
        load_tokenizer,
        plot_distribution,
    )

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
    normalized_slices_dir.mkdir(parents=True, exist_ok=True)

    print('Loading tokenizer for normalized slices...')
    tokenizer = load_tokenizer('microsoft/codebert-base')

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
            source_candidates = build_source_file_candidates(signature_payload, primary_file_hint)

            user_defined_function_names: set[str] = set()
            for source_path in source_candidates:
                source_key = str(source_path)
                if source_path.exists():
                    source_files_seen.add(source_key)
                if source_key not in source_func_cache:
                    if source_path.exists():
                        names, error = collect_defined_function_names(source_path, parsers)
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
            exceeds_limit = token_count > CONTENT_TOKEN_LIMIT
            input_token_count = min(token_count, CONTENT_TOKEN_LIMIT) + 2

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

    plot_distribution(token_count_rows, token_distribution_png)

    ordered_rows: list[dict[str, Any]] = []
    for pair_id in sorted(surviving_pairs.keys()):
        pair_records = sorted(
            surviving_pairs[pair_id],
            key=lambda row: ROLE_SORT_ORDER.get(str(row['role']), 99),
        )
        for row in pair_records:
            row_with_split = dict(row)
            row_with_split['dataset_type'] = 'train_val'
            ordered_rows.append(row_with_split)

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
        kept_unique_id_by_pair_role: dict[tuple[str, str], int] = {}
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

    for audit_row in dedup_audit_rows:
        matched_pair_id = str(audit_row.get('matched_kept_pair_id') or '')
        matched_role = str(audit_row.get('matched_kept_role') or '')
        if matched_pair_id and matched_role:
            audit_row['matched_kept_unique_id'] = str(
                kept_unique_id_by_pair_role.get((matched_pair_id, matched_role), '')
            )

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

    split_manifest = {
        'dataset_basename': DATASET_BASENAME,
        'output_dir': str(dataset_export_dir),
        'normalized_slices_dir': str(normalized_slices_dir),
        'paired_signatures_dir': str(paired_signatures_dir),
        'slice_dir': str(slice_dir),
        'dedup_dropped_csv': str(dedup_dropped_csv),
        'dedup': dedup_summary,
        'split_unit': 'pair_id',
        'split_mode': 'inherited_train_val_only',
        'counts': {
            'pairs_total': len(surviving_pairs),
            'train_val': len(surviving_pairs),
            'test': 0,
            'rows_total': len(ordered_rows),
            'dedup_dropped_pairs': dedup_dropped_pairs,
            'dedup_dropped_rows': dedup_dropped_rows,
        },
        'pair_ids': {
            'train_val': sorted(surviving_pairs.keys()),
            'test': [],
        },
    }
    split_manifest_json.write_text(
        json.dumps(split_manifest, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
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
    counts['train_val_pairs'] = len(surviving_pairs)
    counts['test_pairs'] = 0
    counts['train_val_rows'] = len(ordered_rows)
    counts['test_rows'] = 0

    summary_payload = {
        'dataset_basename': DATASET_BASENAME,
        'paired_signatures_dir': str(paired_signatures_dir),
        'slice_dir': str(slice_dir),
        'output_dir': str(dataset_export_dir),
        'normalized_slices_dir': str(normalized_slices_dir),
        'csv_path': str(csv_path),
        'dedup_dropped_csv': str(dedup_dropped_csv),
        'token_counts_csv': str(token_counts_csv),
        'token_distribution_png': str(token_distribution_png),
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
    summary_json.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
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
