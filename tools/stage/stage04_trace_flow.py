from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from shared.jsonio import write_jsonl, write_summary_json
from shared.juliet_keys import derive_testcase_key_from_file_name

TARGET_TAGS = {'flaw', 'comment_flaw', 'comment_fix'}


@dataclass(frozen=True)
class FlowPoint:
    file_name: str
    line: int
    tag: str


def load_flow_index(flow_xml: Path) -> tuple[dict[str, dict[str, list[FlowPoint]]], dict[str, int]]:
    root = ET.parse(flow_xml).getroot()
    index: dict[str, dict[str, list[FlowPoint]]] = {}
    stats = {'testcases': 0, 'testcases_with_flow': 0, 'keys_indexed': 0, 'duplicate_keys': 0}

    for testcase in root.findall('testcase'):
        stats['testcases'] += 1
        per_flow: dict[str, list[FlowPoint]] = defaultdict(list)
        key_candidates: set[str] = set()

        for file_elem in testcase.findall('file'):
            key = derive_testcase_key_from_file_name(file_elem.attrib.get('path', ''))
            if key:
                key_candidates.add(key)

        for flow in testcase.findall('flow'):
            flow_type = flow.attrib.get('type', '')
            if not flow_type:
                continue
            for child in list(flow):
                if child.tag not in TARGET_TAGS:
                    continue
                file_name = Path(child.attrib.get('file', '')).name
                line = int(child.attrib.get('line', '0') or 0)
                if not file_name or line <= 0:
                    continue
                per_flow[flow_type].append(FlowPoint(file_name=file_name, line=line, tag=child.tag))
                key = derive_testcase_key_from_file_name(file_name)
                if key:
                    key_candidates.add(key)

        if not per_flow:
            continue
        stats['testcases_with_flow'] += 1

        canonical = {
            k: sorted(v, key=lambda p: (p.file_name, p.line, p.tag)) for k, v in per_flow.items()
        }
        for key in key_candidates:
            if key in index:
                stats['duplicate_keys'] += 1
                # 같은 키가 중복되면 첫번째를 유지 (대부분 동일 testcase 중복 매핑)
                continue
            index[key] = canonical
            stats['keys_indexed'] += 1

    return index, stats


def build_trace_line_set(trace_obj: dict) -> set[tuple[str, int]]:
    points: set[tuple[str, int]] = set()
    for step in trace_obj.get('bug_trace', []):
        file_name = Path(step.get('filename', '')).name
        line = int(step.get('line_number', 0) or 0)
        if file_name and line > 0:
            points.add((file_name, line))
    file_name = Path(trace_obj.get('file', '')).name
    line = int(trace_obj.get('line', 0) or 0)
    if file_name and line > 0:
        points.add((file_name, line))
    return points


def match_trace_to_flows(
    trace_lines: set[tuple[str, int]], flows: dict[str, list[FlowPoint]]
) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for flow_type, points in flows.items():
        unique_points = {(p.file_name, p.line) for p in points}
        hit_unique = sum(1 for pt in unique_points if pt in trace_lines)
        by_tag = Counter()
        for p in points:
            if (p.file_name, p.line) in trace_lines:
                by_tag[p.tag] += 1

        total_unique = len(unique_points)
        coverage = (hit_unique / total_unique) if total_unique else 0.0
        results[flow_type] = {
            'total_points': total_unique,
            'hit_points': hit_unique,
            'coverage': round(coverage, 6),
            'hit_tag_counts': dict(by_tag),
            'strict_match': (total_unique > 0 and hit_unique == total_unique),
            'any_match': hit_unique > 0,
        }
    return results


def choose_best_flow(flow_match: dict[str, dict]) -> tuple[str | None, dict | None]:
    if not flow_match:
        return None, None
    ranked = sorted(
        flow_match.items(),
        key=lambda kv: (
            1 if kv[1]['strict_match'] else 0,
            kv[1]['hit_points'],
            kv[1]['coverage'],
            kv[1]['total_points'],
            kv[0],
        ),
        reverse=True,
    )
    best_type, best = ranked[0]
    if best['hit_points'] == 0:
        return None, None
    return best_type, best


def filter_traces_by_flow(
    *, flow_xml: Path, signatures_dir: Path, output_dir: Path
) -> dict[str, object]:
    if not flow_xml.exists():
        raise FileNotFoundError(f'Flow XML not found: {flow_xml}')
    if not signatures_dir.exists():
        raise FileNotFoundError(f'Signatures dir not found: {signatures_dir}')

    flow_index, flow_index_stats = load_flow_index(flow_xml)

    all_records: list[dict] = []
    strict_records: list[dict] = []
    partial_records: list[dict] = []

    stats = Counter()
    matched_flow_counter = Counter()

    for dir_path in sorted(p for p in signatures_dir.iterdir() if p.is_dir()):
        testcase_key = dir_path.name
        if testcase_key == 'analysis':
            continue

        flows = flow_index.get(testcase_key)
        if not flows:
            for trace_file in sorted(dir_path.glob('*.json')):
                stats['traces_total'] += 1
                stats['traces_without_flow_index'] += 1
                all_records.append(
                    {
                        'trace_file': str(trace_file),
                        'testcase_key': testcase_key,
                        'status': 'no_flow_index',
                    }
                )
            continue

        for trace_file in sorted(dir_path.glob('*.json')):
            stats['traces_total'] += 1
            trace_obj = json.loads(trace_file.read_text(encoding='utf-8'))
            trace_lines = build_trace_line_set(trace_obj)
            flow_match = match_trace_to_flows(trace_lines, flows)
            best_flow, best_meta = choose_best_flow(flow_match)

            if best_flow is None:
                status = 'no_flow_hit'
                stats['traces_no_flow_hit'] += 1
            elif best_meta['strict_match']:
                status = 'strict_match'
                stats['traces_strict_match'] += 1
                matched_flow_counter[best_flow] += 1
            else:
                status = 'partial_match'
                stats['traces_partial_match'] += 1
                matched_flow_counter[best_flow] += 1

            rec = {
                'trace_file': str(trace_file),
                'testcase_key': testcase_key,
                'procedure': trace_obj.get('procedure'),
                'primary_file': Path(trace_obj.get('file', '')).name,
                'primary_line': trace_obj.get('line'),
                'bug_trace_length': len(trace_obj.get('bug_trace', [])),
                'status': status,
                'best_flow_type': best_flow,
                'best_flow_meta': best_meta,
                'flow_match': flow_match,
            }
            all_records.append(rec)
            if status == 'strict_match':
                strict_records.append(rec)
            if status in {'strict_match', 'partial_match'}:
                partial_records.append(rec)

    output_dir.mkdir(parents=True, exist_ok=True)
    all_path = output_dir / 'trace_flow_match_all.jsonl'
    strict_path = output_dir / 'trace_flow_match_strict.jsonl'
    matched_path = output_dir / 'trace_flow_match_partial_or_strict.jsonl'
    summary_path = output_dir / 'summary.json'

    write_jsonl(all_path, all_records)
    write_jsonl(strict_path, strict_records)
    write_jsonl(matched_path, partial_records)

    summary = {
        'flow_xml': str(flow_xml),
        'signatures_dir': str(signatures_dir),
        'output_dir': str(output_dir),
        'flow_index': flow_index_stats,
        'trace_stats': dict(stats),
        'matched_best_flow_counts': dict(matched_flow_counter),
        'output_files': {
            'all': str(all_path),
            'strict': str(strict_path),
            'partial_or_strict': str(matched_path),
        },
    }
    write_summary_json(summary_path, summary)
    return summary
