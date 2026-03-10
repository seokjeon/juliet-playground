#!/usr/bin/env python3
from __future__ import annotations

import csv
import datetime
import hashlib
import io
import json
import random
from collections import Counter
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import shlex
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional

import typer

from paths import PROJECT_HOME, RESULT_DIR, PULSE_TAINT_CONFIG

CPP_LIKE_SUFFIXES = {'.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hh', '.hxx'}
ROLE_SORT_ORDER = {'b2b': 0, 'counterpart': 1}


def now_ts() -> str:
    return datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')


def now_iso_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha256_file(path: Path) -> Optional[str]:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def command_to_string(cmd: List[str]) -> str:
    return ' '.join(shlex.quote(x) for x in cmd)


def run_command(step_key: str, cmd: List[str], cwd: Path,
                logs_dir: Path) -> Dict[str, object]:
    started_at = now_iso_utc()
    t0 = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    duration_sec = round(time.perf_counter() - t0, 6)
    ended_at = now_iso_utc()

    logs_dir.mkdir(parents=True, exist_ok=True)
    stdout_log = logs_dir / f'{step_key}.stdout.log'
    stderr_log = logs_dir / f'{step_key}.stderr.log'
    stdout_log.write_text(proc.stdout or '', encoding='utf-8')
    stderr_log.write_text(proc.stderr or '', encoding='utf-8')

    if proc.stdout:
        print(proc.stdout, end='' if proc.stdout.endswith('\n') else '\n')
    if proc.stderr:
        print(proc.stderr, file=sys.stderr, end='' if proc.stderr.endswith('\n') else '\n')

    result = {
        'command': command_to_string(cmd),
        'cwd': str(cwd),
        'returncode': proc.returncode,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': duration_sec,
        'stdout_log': str(stdout_log),
        'stderr_log': str(stderr_log),
    }
    if proc.returncode != 0:
        raise RuntimeError(
            f'[{step_key}] failed with return code {proc.returncode}: {result["command"]}')
    return result


def run_internal_step(step_key: str, logs_dir: Path,
                      fn: Callable[[], Dict[str, object]]) -> Dict[str, object]:
    started_at = now_iso_utc()
    t0 = time.perf_counter()
    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    result_payload: Dict[str, object] = {}
    captured_exc: Exception | None = None

    try:
        with redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
            payload = fn()
            if isinstance(payload, dict):
                result_payload = payload
    except Exception as exc:  # pragma: no cover - surfaced to caller
        captured_exc = exc
    finally:
        duration_sec = round(time.perf_counter() - t0, 6)
        ended_at = now_iso_utc()
        logs_dir.mkdir(parents=True, exist_ok=True)
        stdout_text = stdout_buffer.getvalue()
        stderr_text = stderr_buffer.getvalue()
        stdout_log = logs_dir / f'{step_key}.stdout.log'
        stderr_log = logs_dir / f'{step_key}.stderr.log'
        stdout_log.write_text(stdout_text, encoding='utf-8')
        stderr_log.write_text(stderr_text, encoding='utf-8')
        if stdout_text:
            print(stdout_text, end='' if stdout_text.endswith('\n') else '\n')
        if stderr_text:
            print(stderr_text, file=sys.stderr, end='' if stderr_text.endswith('\n') else '\n')

    if captured_exc is not None:
        raise captured_exc

    result = {
        'executor': 'internal',
        'returncode': 0,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': duration_sec,
        'stdout_log': str(stdout_log),
        'stderr_log': str(stderr_log),
    }
    result.update(result_payload)
    return result


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
    return source_bytes[node.start_byte:node.end_byte].decode('utf-8', errors='ignore')


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


def collect_defined_function_names(source_path: Path,
                                   parsers: dict[str, object]) -> tuple[set[str], str | None]:
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
        except Exception as exc:  # pragma: no cover - parser errors are rare and data-dependent
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


def build_source_file_candidates(signature_payload: dict[str, Any],
                                 primary_file_hint: str | None) -> list[Path]:
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
            while j < n - 1 and code[j:j + 2] != '*/':
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
            tokens.append({'kind': 'punct', 'text': code[i:i + 2]})
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


def normalize_slice_function_names(code: str,
                                   user_defined_function_names: set[str]) -> tuple[str, dict[str, str], int]:
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


def load_pairs_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            pair_id = obj.get('pair_id')
            testcase_key = obj.get('testcase_key')
            if not pair_id or not testcase_key:
                raise ValueError(f'Missing pair_id/testcase_key at line {lineno} in {path}')
            records.append(obj)
    return records


def find_slice_path(slice_dir: Path, testcase_key: str, role_name: str) -> Path | None:
    candidates = [
        slice_dir / f'slice_{testcase_key}_{role_name}.c',
        slice_dir / f'slice_{testcase_key}_{role_name}.cpp',
    ]
    existing = [path for path in candidates if path.exists()]
    if len(existing) > 1:
        raise RuntimeError(f'Multiple slice candidates found for {testcase_key}/{role_name}: {existing}')
    return existing[0] if existing else None


def compute_pair_split(pair_ids: list[str], train_ratio: float,
                       seed: int) -> dict[str, str]:
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


def export_dataset_from_pipeline(*,
                                 pairs_jsonl: Path,
                                 paired_signatures_dir: Path,
                                 slice_dir: Path,
                                 output_dir: Path,
                                 split_seed: int,
                                 train_ratio: float) -> dict[str, object]:
    from tokenize_slices import (CONTENT_TOKEN_LIMIT, MAX_LENGTH, count_code_tokens,
                                 load_tokenizer, plot_distribution)

    if not pairs_jsonl.exists():
        raise FileNotFoundError(f'Pairs JSONL not found: {pairs_jsonl}')
    if not paired_signatures_dir.exists():
        raise FileNotFoundError(f'Paired signatures dir not found: {paired_signatures_dir}')
    if not slice_dir.exists():
        raise FileNotFoundError(f'Slice dir not found: {slice_dir}')
    if not (0.0 < train_ratio < 1.0):
        raise ValueError(f'train_ratio must be between 0 and 1: {train_ratio}')

    output_dir.mkdir(parents=True, exist_ok=True)
    normalized_slices_dir = output_dir / 'normalized_slices'
    normalized_slices_dir.mkdir(parents=True, exist_ok=True)

    real_vul_data_csv = output_dir / 'Real_Vul_data.csv'
    normalized_token_counts_csv = output_dir / 'normalized_token_counts.csv'
    slice_token_distribution_png = output_dir / 'slice_token_distribution.png'
    split_manifest_json = output_dir / 'split_manifest.json'
    summary_json = output_dir / 'summary.json'

    print('Loading tokenizer for normalized slices...')
    tokenizer = load_tokenizer('microsoft/codebert-base')

    pairs = load_pairs_jsonl(pairs_jsonl)
    parsers = load_tree_sitter_parsers()
    source_func_cache: dict[str, set[str]] = {}
    source_parse_error_cache: dict[str, str] = {}
    source_files_seen: set[str] = set()
    source_files_failed: set[str] = set()

    normalized_slice_records: list[dict[str, Any]] = []
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
                'normalized_code': normalized_code,
                'code_token_count': token_count,
                'input_token_count_with_special': input_token_count,
                'exceeds_510': exceeds_limit,
            }
            normalized_slice_records.append(record)
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

    token_count_rows = sorted(
        normalized_slice_records,
        key=lambda row: (row['pair_id'], ROLE_SORT_ORDER.get(str(row['role']), 99), row['slice_filename']),
    )
    with normalized_token_counts_csv.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'pair_id',
            'filename',
            'extension',
            'role',
            'code_token_count',
            'input_token_count_with_special',
            'exceeds_510',
        ])
        for row in token_count_rows:
            writer.writerow([
                row['pair_id'],
                row['slice_filename'],
                row['extension'],
                row['role'],
                row['code_token_count'],
                row['input_token_count_with_special'],
                row['exceeds_510'],
            ])

    plot_distribution(token_count_rows, slice_token_distribution_png)

    split_map = compute_pair_split(list(surviving_pairs.keys()), train_ratio=train_ratio, seed=split_seed)

    ordered_rows: list[dict[str, Any]] = []
    for dataset_type in ('train_val', 'test'):
        pair_ids = sorted(pair_id for pair_id, value in split_map.items() if value == dataset_type)
        for pair_id in pair_ids:
            pair_records = sorted(
                surviving_pairs[pair_id],
                key=lambda row: ROLE_SORT_ORDER.get(str(row['role']), 99),
            )
            for row in pair_records:
                row_with_split = dict(row)
                row_with_split['dataset_type'] = dataset_type
                ordered_rows.append(row_with_split)

    with real_vul_data_csv.open('w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'file_name',
            'unique_id',
            'target',
            'vulnerable_line_numbers',
            'project',
            'commit_hash',
            'dataset_type',
            'processed_func',
        ])
        for idx, row in enumerate(ordered_rows, start=1):
            output_filename = f'{idx}{row["extension"]}'
            (normalized_slices_dir / output_filename).write_text(row['normalized_code'], encoding='utf-8')
            vulnerable_line_numbers = 1 if int(row['target']) == 1 else ''
            writer.writerow([
                idx,
                idx,
                row['target'],
                vulnerable_line_numbers,
                'Juliet',
                '',
                row['dataset_type'],
                row['normalized_code'],
            ])

    split_manifest = {
        'output_dir': str(output_dir),
        'normalized_slices_dir': str(normalized_slices_dir),
        'pairs_jsonl': str(pairs_jsonl),
        'paired_signatures_dir': str(paired_signatures_dir),
        'slice_dir': str(slice_dir),
        'split_unit': 'pair_id',
        'train_ratio': train_ratio,
        'test_ratio': round(1.0 - train_ratio, 6),
        'seed': split_seed,
        'counts': {
            'pairs_total': len(surviving_pairs),
            'train_val': sum(1 for v in split_map.values() if v == 'train_val'),
            'test': sum(1 for v in split_map.values() if v == 'test'),
            'rows_total': len(ordered_rows),
        },
        'pair_ids': {
            'train_val': sorted(pair_id for pair_id, value in split_map.items() if value == 'train_val'),
            'test': sorted(pair_id for pair_id, value in split_map.items() if value == 'test'),
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
    counts['source_files_total'] = len(source_files_seen)
    counts['source_files_parse_failed'] = len(source_files_failed)
    counts['train_val_pairs'] = sum(1 for v in split_map.values() if v == 'train_val')
    counts['test_pairs'] = sum(1 for v in split_map.values() if v == 'test')
    counts['train_val_rows'] = sum(1 for row in ordered_rows if row['dataset_type'] == 'train_val')
    counts['test_rows'] = sum(1 for row in ordered_rows if row['dataset_type'] == 'test')

    summary_payload = {
        'pairs_jsonl': str(pairs_jsonl),
        'paired_signatures_dir': str(paired_signatures_dir),
        'slice_dir': str(slice_dir),
        'output_dir': str(output_dir),
        'normalized_slices_dir': str(normalized_slices_dir),
        'real_vul_data_csv': str(real_vul_data_csv),
        'normalized_token_counts_csv': str(normalized_token_counts_csv),
        'slice_token_distribution_png': str(slice_token_distribution_png),
        'split_manifest_json': str(split_manifest_json),
        'max_length': MAX_LENGTH,
        'content_token_limit': CONTENT_TOKEN_LIMIT,
        'seed': split_seed,
        'train_ratio': train_ratio,
        'test_ratio': round(1.0 - train_ratio, 6),
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
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    print(json.dumps(summary_payload, ensure_ascii=False))

    return {
        'summary_json': str(summary_json),
        'output_dir': str(output_dir),
        'normalized_slices_dir': str(normalized_slices_dir),
        'real_vul_data_csv': str(real_vul_data_csv),
        'normalized_token_counts_csv': str(normalized_token_counts_csv),
        'slice_token_distribution_png': str(slice_token_distribution_png),
        'split_manifest_json': str(split_manifest_json),
    }


def main(
    cwes: Optional[List[int]] = typer.Argument(None),
    all_cwes: bool = typer.Option(
        False, '--all', help='Run the pipeline for all CWEs in the testcase directory'),
    files: List[str] = typer.Option(
        [], '--files', help='Run infer for specific files (repeatable); if set, cwes and --all are ignored'),
    manifest: Path = typer.Option(
        Path(PROJECT_HOME) / 'experiments' / 'epic001_manifest_comment_scan' / 'inputs' / 'manifest.xml',
        '--manifest',
        help='Input manifest.xml path'),
    source_root: Path = typer.Option(
        Path(PROJECT_HOME) / 'juliet-test-suite-v1.3' / 'C',
        '--source-root',
        help='Juliet C source root'),
    pipeline_root: Path = typer.Option(
        Path(RESULT_DIR) / 'pipeline-runs',
        '--pipeline-root',
        help='Root directory for pipeline runs'),
    run_id: Optional[str] = typer.Option(
        None,
        '--run-id',
        help='Run id under pipeline root (default: run-<YYYY.MM.DD-HH:MM:SS>)'),
    committed_taint_config: Path = typer.Option(
        Path(PULSE_TAINT_CONFIG),
        '--committed-taint-config',
        help='Committed taint config path for fallback/reference'),
    pair_split_seed: int = typer.Option(
        1234,
        '--pair-split-seed',
        help='Random seed for pair-level train/test split'),
    pair_train_ratio: float = typer.Option(
        0.8,
        '--pair-train-ratio',
        help='Train ratio for pair-level train/test split'),
):
    if not manifest.exists():
        raise typer.BadParameter(f'Manifest not found: {manifest}')
    if not source_root.exists():
        raise typer.BadParameter(f'Source root not found: {source_root}')
    if not committed_taint_config.exists():
        raise typer.BadParameter(f'Committed taint config not found: {committed_taint_config}')
    if not files and not all_cwes and not cwes:
        raise typer.BadParameter('Provide cwes, use --all, or use --files')
    if not (0.0 < pair_train_ratio < 1.0):
        raise typer.BadParameter(f'pair_train_ratio must be between 0 and 1: {pair_train_ratio}')

    if run_id is None:
        run_id = f'run-{now_ts()}'

    pipeline_root = pipeline_root.resolve()
    run_dir = (pipeline_root / run_id).resolve()
    run_dir.mkdir(parents=True, exist_ok=True)

    # Paths per stage
    manifest_dir = run_dir / '01_manifest'
    taint_dir = run_dir / '02a_taint'
    flow_dir = run_dir / '02b_flow'
    infer_results_root = run_dir / '03_infer-results'
    signatures_root = run_dir / '03_signatures'
    trace_dir = run_dir / '04_trace_flow'
    pair_dir = run_dir / '05_pair_trace_ds'
    slice_stage_dir = run_dir / '06_slices'
    dataset_stage_dir = run_dir / '07_dataset_export'
    logs_dir = run_dir / 'logs'

    manifest_with_comments_xml = manifest_dir / 'manifest_with_comments.xml'
    generated_taint_config = taint_dir / 'pulse-taint-config.json'

    function_names_unique_csv = flow_dir / 'function_names_unique.csv'
    function_inventory_summary_json = flow_dir / 'function_inventory_summary.json'
    function_names_categorized_jsonl = flow_dir / 'function_names_categorized.jsonl'
    grouped_family_role_json = flow_dir / 'grouped_family_role.json'
    category_summary_json = flow_dir / 'category_summary.json'
    manifest_with_testcase_flows_xml = flow_dir / 'manifest_with_testcase_flows.xml'
    testcase_flow_summary_json = flow_dir / 'testcase_flow_summary.json'

    infer_summary_json = run_dir / '03_infer_summary.json'
    trace_strict_jsonl = trace_dir / 'trace_flow_match_strict.jsonl'
    pairs_jsonl = pair_dir / 'pairs.jsonl'
    leftover_counterparts_jsonl = pair_dir / 'leftover_counterparts.jsonl'
    paired_signatures_dir = pair_dir / 'paired_signatures'
    paired_trace_summary_json = pair_dir / 'summary.json'
    slice_dir = slice_stage_dir / 'slice'
    slice_summary_json = slice_stage_dir / 'summary.json'
    normalized_slices_dir = dataset_stage_dir / 'normalized_slices'
    real_vul_data_csv = dataset_stage_dir / 'Real_Vul_data.csv'
    normalized_token_counts_csv = dataset_stage_dir / 'normalized_token_counts.csv'
    slice_token_distribution_png = dataset_stage_dir / 'slice_token_distribution.png'
    dataset_split_manifest_json = dataset_stage_dir / 'split_manifest.json'
    dataset_summary_json = dataset_stage_dir / 'summary.json'
    run_summary_path = run_dir / 'run_summary.json'

    source_testcases_root = source_root / 'testcases'

    scan_script = Path(PROJECT_HOME) / 'experiments' / 'epic001_manifest_comment_scan' / 'scripts' / 'scan_manifest_comments.py'
    code_field_script = Path(PROJECT_HOME) / 'experiments' / 'epic001a_code_field_inventory' / 'scripts' / 'extract_unique_code_fields.py'
    function_inventory_script = Path(PROJECT_HOME) / 'experiments' / 'epic001b_function_inventory' / 'scripts' / 'extract_function_inventory.py'
    categorize_script = Path(PROJECT_HOME) / 'experiments' / 'epic001b_function_inventory' / 'scripts' / 'categorize_function_names.py'
    flow_partition_script = Path(PROJECT_HOME) / 'experiments' / 'epic001c_testcase_flow_partition' / 'scripts' / 'add_flow_tags_to_testcase.py'
    infer_script = Path(PROJECT_HOME) / 'tools' / 'run-infer-all-juliet.py'
    filter_script = Path(PROJECT_HOME) / 'experiments' / 'epic001d_trace_flow_filter' / 'scripts' / 'filter_traces_by_flow.py'
    pair_script = Path(PROJECT_HOME) / 'tools' / 'build-paired-trace-signatures.py'
    slice_script = Path(PROJECT_HOME) / 'tools' / 'generate_slices.py'

    started_at = now_iso_utc()
    start_perf = time.perf_counter()
    steps: Dict[str, Dict[str, object]] = {}
    status = 'success'
    error_message: Optional[str] = None
    selected_taint_config: Optional[Path] = None
    selected_reason: Optional[str] = None
    infer_summary: Dict[str, object] = {}
    signature_non_empty_dir: Optional[Path] = None

    try:
        # Step 01: manifest -> manifest_with_comments.xml
        steps['01_manifest_comment_scan'] = run_command(
            '01_manifest_comment_scan',
            [
                sys.executable,
                str(scan_script),
                '--manifest', str(manifest),
                '--source-root', str(source_root),
                '--output-xml', str(manifest_with_comments_xml),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        # Step 02a: with_comments -> taint config
        steps['02a_code_field_inventory'] = run_command(
            '02a_code_field_inventory',
            [
                sys.executable,
                str(code_field_script),
                '--input-xml', str(manifest_with_comments_xml),
                '--source-root', str(source_root),
                '--output-dir', str(taint_dir),
                '--pulse-taint-config-output', str(generated_taint_config),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        # Step 02b-1: function inventory
        steps['02b_function_inventory_extract'] = run_command(
            '02b_function_inventory_extract',
            [
                sys.executable,
                str(function_inventory_script),
                '--input-xml', str(manifest_with_comments_xml),
                '--output-csv', str(function_names_unique_csv),
                '--output-summary', str(function_inventory_summary_json),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        # Step 02b-2: categorize functions
        steps['02b_function_inventory_categorize'] = run_command(
            '02b_function_inventory_categorize',
            [
                sys.executable,
                str(categorize_script),
                '--input-csv', str(function_names_unique_csv),
                '--manifest-xml', str(manifest_with_comments_xml),
                '--source-root', str(source_testcases_root),
                '--output-jsonl', str(function_names_categorized_jsonl),
                '--output-nested-json', str(grouped_family_role_json),
                '--output-summary', str(category_summary_json),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        # Step 02b-3: build manifest_with_testcase_flows.xml
        steps['02b_testcase_flow_partition'] = run_command(
            '02b_testcase_flow_partition',
            [
                sys.executable,
                str(flow_partition_script),
                '--input-xml', str(manifest_with_comments_xml),
                '--function-categories-jsonl', str(function_names_categorized_jsonl),
                '--output-xml', str(manifest_with_testcase_flows_xml),
                '--summary-json', str(testcase_flow_summary_json),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if generated_taint_config.exists():
            selected_taint_config = generated_taint_config
            selected_reason = 'generated'
        else:
            selected_taint_config = committed_taint_config.resolve()
            selected_reason = 'fallback_committed'

        # Step 03: infer + signature
        infer_cmd = [
            sys.executable,
            str(infer_script),
            '--pulse-taint-config', str(selected_taint_config),
            '--infer-results-root', str(infer_results_root),
            '--signatures-root', str(signatures_root),
            '--summary-json', str(infer_summary_json),
        ]
        if files:
            for f in files:
                infer_cmd.extend(['--files', f])
        elif all_cwes:
            infer_cmd.append('--all')
        else:
            infer_cmd[2:2] = [str(x) for x in cwes or []]

        steps['03_infer_and_signature'] = run_command(
            '03_infer_and_signature',
            infer_cmd,
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if not infer_summary_json.exists():
            raise RuntimeError(f'Infer summary JSON not found: {infer_summary_json}')
        infer_summary = json.loads(infer_summary_json.read_text(encoding='utf-8'))

        signature_non_empty_raw = infer_summary.get('signature_non_empty_dir')
        if signature_non_empty_raw:
            signature_non_empty_dir = Path(signature_non_empty_raw)
        else:
            signature_output_dir = infer_summary.get('signature_output_dir')
            if not signature_output_dir:
                raise RuntimeError('signature_output_dir not found in infer summary')
            signature_non_empty_dir = Path(signature_output_dir) / 'non_empty'

        if not signature_non_empty_dir.exists():
            raise RuntimeError(f'Signature non_empty directory not found: {signature_non_empty_dir}')

        # Step 04: filter traces by testcase flow
        steps['04_trace_flow_filter'] = run_command(
            '04_trace_flow_filter',
            [
                sys.executable,
                str(filter_script),
                '--flow-xml', str(manifest_with_testcase_flows_xml),
                '--signatures-dir', str(signature_non_empty_dir),
                '--output-dir', str(trace_dir),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if not trace_strict_jsonl.exists():
            raise RuntimeError(f'Expected strict trace output not found: {trace_strict_jsonl}')

        # Step 05: pair strict traces and export signature-style testcase dirs
        steps['05_pair_trace_dataset'] = run_command(
            '05_pair_trace_dataset',
            [
                sys.executable,
                str(pair_script),
                '--trace-jsonl', str(trace_strict_jsonl),
                '--output-dir', str(pair_dir),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if not pairs_jsonl.exists():
            raise RuntimeError(f'Expected pairs output not found: {pairs_jsonl}')
        if not paired_signatures_dir.exists():
            raise RuntimeError(f'Expected paired signatures dir not found: {paired_signatures_dir}')
        if not paired_trace_summary_json.exists():
            raise RuntimeError(f'Expected paired trace summary not found: {paired_trace_summary_json}')

        # Step 06: generate source slices from paired signatures
        steps['06_generate_slices'] = run_command(
            '06_generate_slices',
            [
                sys.executable,
                str(slice_script),
                '--signature-db-dir', str(paired_signatures_dir),
                '--output-dir', str(slice_stage_dir),
            ],
            cwd=Path(PROJECT_HOME),
            logs_dir=logs_dir,
        )

        if not slice_dir.exists():
            raise RuntimeError(f'Expected slice dir not found: {slice_dir}')
        if not slice_summary_json.exists():
            raise RuntimeError(f'Expected slice summary not found: {slice_summary_json}')

        # Step 07: normalize slices, tokenize, filter, split, and export dataset
        steps['07_dataset_export'] = run_internal_step(
            '07_dataset_export',
            logs_dir=logs_dir,
            fn=lambda: export_dataset_from_pipeline(
                pairs_jsonl=pairs_jsonl,
                paired_signatures_dir=paired_signatures_dir,
                slice_dir=slice_dir,
                output_dir=dataset_stage_dir,
                split_seed=pair_split_seed,
                train_ratio=pair_train_ratio,
            ),
        )

        if not normalized_slices_dir.exists():
            raise RuntimeError(f'Expected normalized slices dir not found: {normalized_slices_dir}')
        if not real_vul_data_csv.exists():
            raise RuntimeError(f'Expected Real_Vul_data.csv not found: {real_vul_data_csv}')
        if not normalized_token_counts_csv.exists():
            raise RuntimeError(f'Expected normalized token counts CSV not found: {normalized_token_counts_csv}')
        if not slice_token_distribution_png.exists():
            raise RuntimeError(f'Expected token distribution plot not found: {slice_token_distribution_png}')
        if not dataset_split_manifest_json.exists():
            raise RuntimeError(f'Expected dataset split manifest not found: {dataset_split_manifest_json}')
        if not dataset_summary_json.exists():
            raise RuntimeError(f'Expected dataset summary JSON not found: {dataset_summary_json}')

    except Exception as exc:
        status = 'failed'
        error_message = str(exc)

    ended_at = now_iso_utc()
    total_duration_sec = round(time.perf_counter() - start_perf, 6)

    committed_taint_config = committed_taint_config.resolve()
    generated_taint_config = generated_taint_config.resolve()
    selected_taint_config_str = str(selected_taint_config.resolve()) if selected_taint_config else None

    summary_payload = {
        'status': status,
        'error_message': error_message,
        'started_at': started_at,
        'ended_at': ended_at,
        'duration_sec': total_duration_sec,
        'pipeline_root': str(pipeline_root),
        'run_id': run_id,
        'run_dir': str(run_dir),
        'input_manifest': str(manifest.resolve()),
        'source_root': str(source_root.resolve()),
        'mode': 'files' if files else ('all' if all_cwes else 'cwes'),
        'all_cwes': all_cwes,
        'cwes': cwes or [],
        'files': files,
        'pair_split_seed': pair_split_seed,
        'pair_train_ratio': pair_train_ratio,
        'committed_taint_config_path': str(committed_taint_config),
        'generated_taint_config_path': str(generated_taint_config),
        'selected_taint_config_path': selected_taint_config_str,
        'selected_reason': selected_reason,
        'sha256': {
            'committed_taint_config': sha256_file(committed_taint_config),
            'generated_taint_config': sha256_file(generated_taint_config),
            'selected_taint_config': sha256_file(Path(selected_taint_config_str)) if selected_taint_config_str else None,
        },
        'steps': steps,
        'outputs': {
            'manifest_with_comments_xml': str(manifest_with_comments_xml),
            'generated_taint_config': str(generated_taint_config),
            'manifest_with_testcase_flows_xml': str(manifest_with_testcase_flows_xml),
            'infer_summary_json': str(infer_summary_json),
            'signature_non_empty_dir': str(signature_non_empty_dir) if signature_non_empty_dir else None,
            'trace_flow_match_strict_jsonl': str(trace_strict_jsonl),
            'pairs_jsonl': str(pairs_jsonl),
            'leftover_counterparts_jsonl': str(leftover_counterparts_jsonl),
            'paired_signatures_dir': str(paired_signatures_dir),
            'paired_trace_summary_json': str(paired_trace_summary_json),
            'slice_dir': str(slice_dir),
            'slice_summary_json': str(slice_summary_json),
            'dataset_export_dir': str(dataset_stage_dir),
            'normalized_slices_dir': str(normalized_slices_dir),
            'real_vul_data_csv': str(real_vul_data_csv),
            'normalized_token_counts_csv': str(normalized_token_counts_csv),
            'slice_token_distribution_png': str(slice_token_distribution_png),
            'dataset_split_manifest_json': str(dataset_split_manifest_json),
            'dataset_summary_json': str(dataset_summary_json),
        },
        'infer_summary': infer_summary,
    }

    run_summary_path.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )

    print(json.dumps(summary_payload, ensure_ascii=False))

    if status != 'success':
        raise typer.Exit(code=1)


if __name__ == '__main__':
    typer.run(main)
