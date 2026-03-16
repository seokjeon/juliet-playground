from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from shared.fs import prepare_output_dir
from shared.paths import RESULT_DIR
from shared.pipeline_runs import find_latest_pipeline_run_dir
from shared.signatures import load_signature_payload, stable_signature_ref, stable_trace_ref

COUNTERPART_FLOW_TYPES = {
    'g2b',
    'g2b1',
    'g2b2',
    'b2g',
    'b2g1',
    'b2g2',
}


@dataclass(frozen=True)
class StrictTraceRecord:
    testcase_key: str
    trace_file: Path
    best_flow_type: str
    bug_trace_length: int
    procedure: str | None
    primary_file: str | None
    primary_line: int | None
    raw: dict[str, Any]


def infer_run_dir_from_trace_jsonl(trace_jsonl: Path) -> Path | None:
    if trace_jsonl.name != 'trace_flow_match_strict.jsonl':
        return None
    if trace_jsonl.parent.name != '04_trace_flow':
        return None
    return trace_jsonl.parent.parent


def resolve_paths(
    *,
    trace_jsonl: Path | None = None,
    output_dir: Path | None = None,
    pipeline_root: Path = Path(RESULT_DIR) / 'pipeline-runs',
    run_dir: Path | None = None,
) -> tuple[Path, Path, Path | None]:
    resolved_run_dir = run_dir.resolve() if run_dir is not None else None

    if trace_jsonl is None:
        if resolved_run_dir is None:
            resolved_run_dir = find_latest_pipeline_run_dir(pipeline_root.resolve())
        resolved_trace_jsonl = resolved_run_dir / '04_trace_flow' / 'trace_flow_match_strict.jsonl'
    else:
        resolved_trace_jsonl = trace_jsonl.resolve()
        if resolved_run_dir is None:
            resolved_run_dir = infer_run_dir_from_trace_jsonl(resolved_trace_jsonl)

    if output_dir is None:
        if resolved_run_dir is None:
            raise ValueError(
                '--output-dir is required when --trace-jsonl is outside the standard '
                'pipeline run layout.'
            )
        resolved_output_dir = resolved_run_dir / '05_pair_trace_ds'
    else:
        resolved_output_dir = output_dir.resolve()

    return resolved_trace_jsonl, resolved_output_dir, resolved_run_dir


def validate_args(trace_jsonl: Path) -> None:
    if not trace_jsonl.exists():
        raise FileNotFoundError(f'Strict trace JSONL not found: {trace_jsonl}')
    if not trace_jsonl.is_file():
        raise FileNotFoundError(f'Strict trace JSONL is not a file: {trace_jsonl}')


def load_strict_records(trace_jsonl: Path) -> list[StrictTraceRecord]:
    records: list[StrictTraceRecord] = []
    with trace_jsonl.open('r', encoding='utf-8') as f:
        for lineno, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            testcase_key = (obj.get('testcase_key') or '').strip()
            trace_file_raw = (obj.get('trace_file') or '').strip()
            best_flow_type = (obj.get('best_flow_type') or '').strip()
            if not testcase_key or not trace_file_raw or not best_flow_type:
                raise ValueError(f'Missing required keys at line {lineno} in {trace_jsonl}: {obj}')
            records.append(
                StrictTraceRecord(
                    testcase_key=testcase_key,
                    trace_file=Path(trace_file_raw),
                    best_flow_type=best_flow_type,
                    bug_trace_length=int(obj.get('bug_trace_length', 0) or 0),
                    procedure=obj.get('procedure'),
                    primary_file=obj.get('primary_file'),
                    primary_line=obj.get('primary_line'),
                    raw=obj,
                )
            )
    return records


def group_by_testcase(
    records: list[StrictTraceRecord],
) -> dict[str, list[StrictTraceRecord]]:
    grouped: dict[str, list[StrictTraceRecord]] = defaultdict(list)
    for record in records:
        grouped[record.testcase_key].append(record)
    return grouped


def record_sort_key(record: StrictTraceRecord) -> tuple[Any, ...]:
    return (
        -record.bug_trace_length,
        stable_trace_ref(record.trace_file),
        record.best_flow_type,
        record.procedure or '',
    )


def select_best_record(records: list[StrictTraceRecord]) -> StrictTraceRecord | None:
    if not records:
        return None
    return sorted(records, key=record_sort_key)[0]


def make_pair_id(
    testcase_key: str,
    b2b_record: StrictTraceRecord,
    b2b_payload: dict[str, Any],
    counterpart_record: StrictTraceRecord,
    counterpart_payload: dict[str, Any],
) -> str:
    seed = '||'.join(
        [
            testcase_key,
            b2b_record.best_flow_type,
            stable_signature_ref(b2b_payload, b2b_record.trace_file),
            counterpart_record.best_flow_type,
            stable_signature_ref(counterpart_payload, counterpart_record.trace_file),
        ]
    )
    return hashlib.sha1(seed.encode('utf-8')).hexdigest()[:16]


def signature_meta(payload: dict[str, Any], record: StrictTraceRecord) -> dict[str, Any]:
    return {
        'trace_file': str(record.trace_file),
        'best_flow_type': record.best_flow_type,
        'bug_trace_length': record.bug_trace_length,
        'procedure': record.procedure,
        'primary_file': record.primary_file,
        'primary_line': record.primary_line,
        'signature_key': payload.get('key'),
        'signature_hash': payload.get('hash'),
    }


def build_paired_trace_dataset(
    *, trace_jsonl: Path, output_dir: Path, overwrite: bool = False, run_dir: Path | None = None
) -> dict[str, Any]:
    validate_args(trace_jsonl)
    prepare_output_dir(output_dir, overwrite)

    paired_signatures_dir = output_dir / 'paired_signatures'
    paired_signatures_dir.mkdir(parents=True, exist_ok=True)

    pairs_jsonl = output_dir / 'pairs.jsonl'
    leftovers_jsonl = output_dir / 'leftover_counterparts.jsonl'
    summary_json = output_dir / 'summary.json'

    strict_records = load_strict_records(trace_jsonl)
    grouped = group_by_testcase(strict_records)

    pair_candidates: list[dict[str, Any]] = []
    summary_counter = Counter()
    counterpart_flow_counter = Counter()

    for testcase_key, records in sorted(grouped.items()):
        summary_counter['testcases_total'] += 1

        b2b_records = [r for r in records if r.best_flow_type == 'b2b']
        counterpart_records = [r for r in records if r.best_flow_type in COUNTERPART_FLOW_TYPES]

        if not b2b_records:
            summary_counter['testcases_without_b2b'] += 1
            continue
        if not counterpart_records:
            summary_counter['testcases_without_counterpart'] += 1
            continue

        summary_counter['testcases_with_b2b_and_counterpart'] += 1

        selected_b2b = select_best_record(b2b_records)
        assert selected_b2b is not None
        if len(b2b_records) > 1:
            summary_counter['testcases_multi_b2b'] += 1

        sorted_counterparts = sorted(counterpart_records, key=record_sort_key)
        selected_counterpart = sorted_counterparts[0]
        unselected_counterparts = sorted_counterparts[1:]

        pair_candidates.append(
            {
                'testcase_key': testcase_key,
                'selection_reason': 'longest_bug_trace',
                'b2b': selected_b2b,
                'counterpart': selected_counterpart,
                'leftovers': unselected_counterparts,
            }
        )
        counterpart_flow_counter[selected_counterpart.best_flow_type] += 1

    final_pairs: list[dict[str, Any]] = []
    leftovers: list[dict[str, Any]] = []
    for pair in pair_candidates:
        testcase_key = pair['testcase_key']
        b2b_record: StrictTraceRecord = pair['b2b']
        counterpart_record: StrictTraceRecord = pair['counterpart']

        b2b_payload = load_signature_payload(b2b_record.trace_file)
        counterpart_payload = load_signature_payload(counterpart_record.trace_file)
        pair_id = make_pair_id(
            testcase_key=testcase_key,
            b2b_record=b2b_record,
            b2b_payload=b2b_payload,
            counterpart_record=counterpart_record,
            counterpart_payload=counterpart_payload,
        )

        testcase_dir = paired_signatures_dir / testcase_key
        testcase_dir.mkdir(parents=True, exist_ok=True)

        b2b_output_path = testcase_dir / 'b2b.json'
        counterpart_output_path = testcase_dir / f'{counterpart_record.best_flow_type}.json'

        b2b_export = dict(b2b_payload)
        b2b_export['pairing_meta'] = {
            'pair_id': pair_id,
            'testcase_key': testcase_key,
            'role': 'b2b',
            'selection_reason': pair['selection_reason'],
            'trace_file': str(b2b_record.trace_file),
            'best_flow_type': b2b_record.best_flow_type,
            'bug_trace_length': b2b_record.bug_trace_length,
        }
        counterpart_export = dict(counterpart_payload)
        counterpart_export['pairing_meta'] = {
            'pair_id': pair_id,
            'testcase_key': testcase_key,
            'role': 'counterpart',
            'selection_reason': pair['selection_reason'],
            'trace_file': str(counterpart_record.trace_file),
            'best_flow_type': counterpart_record.best_flow_type,
            'bug_trace_length': counterpart_record.bug_trace_length,
        }

        b2b_output_path.write_text(
            json.dumps(b2b_export, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8',
        )
        counterpart_output_path.write_text(
            json.dumps(counterpart_export, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8',
        )

        final_pairs.append(
            {
                'pair_id': pair_id,
                'testcase_key': testcase_key,
                'selection_reason': pair['selection_reason'],
                'b2b_flow_type': b2b_record.best_flow_type,
                'b2b_trace_file': str(b2b_record.trace_file),
                'b2b_bug_trace_length': b2b_record.bug_trace_length,
                'b2b_signature': signature_meta(b2b_payload, b2b_record),
                'counterpart_flow_type': counterpart_record.best_flow_type,
                'counterpart_trace_file': str(counterpart_record.trace_file),
                'counterpart_bug_trace_length': counterpart_record.bug_trace_length,
                'counterpart_signature': signature_meta(counterpart_payload, counterpart_record),
                'output_files': {
                    'b2b': str(b2b_output_path),
                    counterpart_record.best_flow_type: str(counterpart_output_path),
                },
            }
        )

        for leftover in pair['leftovers']:
            leftovers.append(
                {
                    'testcase_key': testcase_key,
                    'related_pair_id': pair_id,
                    'trace_file': str(leftover.trace_file),
                    'best_flow_type': leftover.best_flow_type,
                    'bug_trace_length': leftover.bug_trace_length,
                    'procedure': leftover.procedure,
                    'primary_file': leftover.primary_file,
                    'primary_line': leftover.primary_line,
                    'dropped_reason': 'not_selected_longest_bug_trace',
                }
            )

    with pairs_jsonl.open('w', encoding='utf-8') as f:
        for record in final_pairs:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')

    with leftovers_jsonl.open('w', encoding='utf-8') as f:
        for record in leftovers:
            f.write(json.dumps(record, ensure_ascii=False) + '\n')

    summary_payload = {
        'trace_jsonl': str(trace_jsonl),
        'output_dir': str(output_dir),
        'paired_signatures_dir': str(paired_signatures_dir),
        'run_dir': str(run_dir) if run_dir else None,
        'pairs_jsonl': str(pairs_jsonl),
        'leftover_counterparts_jsonl': str(leftovers_jsonl),
        'records_total': len(strict_records),
        'summary_counts': dict(summary_counter),
        'paired_testcases': len(final_pairs),
        'leftover_counterparts': len(leftovers),
        'selected_counterpart_flow_counts': dict(counterpart_flow_counter),
    }
    summary_json.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    print(json.dumps(summary_payload, ensure_ascii=False))
    return summary_payload
