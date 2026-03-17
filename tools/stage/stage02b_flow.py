from __future__ import annotations

import copy
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

from shared.artifact_layout import path_strings
from shared.jsonio import write_stage_summary, write_summary_json

COMMENT_TAGS = {'comment_flaw', 'comment_fix'}
PYC_C_FUNC_RE = re.compile(
    r'^(CWE|cwe)(?P<cwe_number>\d+)_(?P<cwe_name>.*)__(?P<function_variant>.*)_(?P<flow_variant>\d+)(?P<subfile_id>[a-z]*)_(?P<function_name>[^.]*)$',
    re.IGNORECASE,
)
FLOW_PARTITION_TARGET_TAGS = ('comment_flaw', 'comment_fix', 'flaw')
FLOW_OUTPUT_TAG_BY_INPUT_TAG = {'comment_flaw': 'flaw', 'comment_fix': 'fix', 'flaw': 'flaw'}
FLOW_ORIGIN_BY_INPUT_TAG = {
    'comment_flaw': 'comment_flaw',
    'comment_fix': 'comment_fix',
    'flaw': 'manifest_flaw',
}
MANIFEST_FLAW_ORIGIN, COMMENT_FLAW_ORIGIN = 'manifest_flaw', 'comment_flaw'
BASE_FLOW_ORDER = ('b2b', 'b2g', 'g2b')
FAMILY_TO_FLOW = {
    'b2b_family': 'b2b',
    'b2g_family': 'b2g',
    'g2b_family': 'g2b',
}
FLOW_NUM_SUFFIX = {
    'b2g': re.compile(r'b2g(\d+)', re.IGNORECASE),
    'g2b': re.compile(r'g2b(\d+)', re.IGNORECASE),
}


def split_simple_name(function_name: str) -> str:
    match = PYC_C_FUNC_RE.match(function_name)
    return match.group('function_name') if match else function_name


def classify_flow_family(simple_name: str) -> str:
    low = simple_name.lower()
    if low.startswith('helpergood') or low == 'helperbad':
        return 'helper_family'
    if low in {'goodclass', 'badclass', 'goodbaseclass', 'badbaseclass'}:
        return 'class_family'
    if 'g2b' in low:
        return 'g2b_family'
    if 'b2g' in low:
        return 'b2g_family'
    if 'good' in low and 'bad' not in low:
        return 'g2g_family'
    if 'bad' in low and 'good' not in low:
        return 'b2b_family'
    return 'misc_family'


def build_stage02b_output_paths(output_dir: Path) -> dict[str, Path]:
    return {
        'output_dir': output_dir,
        'manifest_with_testcase_flows_xml': output_dir / 'manifest_with_testcase_flows.xml',
        'summary_json': output_dir / 'summary.json',
    }


def build_function_flow_map_from_manifest_comments(input_xml: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    root = ET.parse(input_xml).getroot()
    for element in root.iter():
        if element.tag not in COMMENT_TAGS:
            continue
        function_name = (element.attrib.get('function') or '').strip()
        if not function_name:
            continue
        flow = FAMILY_TO_FLOW.get(classify_flow_family(split_simple_name(function_name)))
        if flow:
            mapping[function_name] = flow
    return mapping


def infer_function_for_flaw(line_no: int, function_lines: dict[str, list[int]]) -> str | None:
    best_function = None
    best_distance = None
    for function_name, lines in function_lines.items():
        for candidate_line in lines:
            distance = abs(candidate_line - line_no)
            if best_distance is None or distance < best_distance:
                best_distance = distance
                best_function = function_name
    return best_function


def flow_type_from_function(base_flow: str, function_name: str | None) -> str:
    if base_flow not in FLOW_NUM_SUFFIX or not function_name:
        return base_flow
    simple_name = split_simple_name(function_name)
    match = FLOW_NUM_SUFFIX[base_flow].search(simple_name)
    if not match:
        return base_flow
    return f'{base_flow}{match.group(1)}'


def _flow_sort_key(flow_type: str) -> tuple[int, int, str]:
    for index, base in enumerate(BASE_FLOW_ORDER):
        if flow_type == base:
            return (index, -1, flow_type)
        if flow_type.startswith(base):
            suffix = flow_type[len(base) :]
            if suffix.isdigit():
                return (index, int(suffix), flow_type)
            return (index, 10**9, flow_type)
    return (10**9, 10**9, flow_type)


def _normalize_flow_item(*, child: ET.Element, file_path: str, function_name: str) -> ET.Element:
    copied = copy.deepcopy(child)
    copied.tag = FLOW_OUTPUT_TAG_BY_INPUT_TAG[child.tag]
    copied.attrib['file'] = file_path
    copied.attrib['function'] = function_name
    copied.attrib['origin'] = FLOW_ORIGIN_BY_INPUT_TAG[child.tag]
    copied.attrib.pop('inferred_function', None)
    return copied


def _cwe_prefix_from_file_path(file_path: str) -> str | None:
    file_name = Path(file_path).name.strip()
    if not file_name:
        return None
    prefix = file_name.split('_', 1)[0].strip().upper()
    return prefix or None


def _cwe_prefix_from_flaw_name(name: str) -> str | None:
    prefix = name.split(':', 1)[0].strip().replace('-', '').upper()
    return prefix or None


def _manifest_flaw_cwe_matches_file(item: ET.Element) -> bool | None:
    file_prefix = _cwe_prefix_from_file_path(item.attrib.get('file', ''))
    name_prefix = _cwe_prefix_from_flaw_name(item.attrib.get('name', ''))
    if not file_prefix or not name_prefix:
        return None
    return file_prefix == name_prefix


def _dedup_flow_items(items: list[ET.Element]) -> tuple[list[ET.Element], int]:
    grouped: dict[tuple[str, str, str], list[tuple[int, ET.Element]]] = defaultdict(list)
    for index, item in enumerate(items):
        grouped[
            (
                item.tag,
                item.attrib.get('file', ''),
                str(item.attrib.get('line', '')),
            )
        ].append((index, item))

    keep_indices: set[int] = set()
    removed_comment_flaw = 0
    for key, members in grouped.items():
        tag = key[0]
        filtered_members = members
        if tag == 'flaw':
            manifest_match_state = {
                index: _manifest_flaw_cwe_matches_file(member)
                for index, member in members
                if member.attrib.get('origin') == MANIFEST_FLAW_ORIGIN
            }
            has_matching_manifest = any(state is True for state in manifest_match_state.values())
            if has_matching_manifest:
                filtered_members = [
                    (index, member)
                    for index, member in members
                    if not (
                        member.attrib.get('origin') == MANIFEST_FLAW_ORIGIN
                        and manifest_match_state.get(index) is False
                    )
                ]

        origins = {member.attrib.get('origin', '') for _, member in filtered_members}
        if tag == 'flaw' and MANIFEST_FLAW_ORIGIN in origins and COMMENT_FLAW_ORIGIN in origins:
            for index, member in filtered_members:
                if member.attrib.get('origin') == COMMENT_FLAW_ORIGIN:
                    removed_comment_flaw += 1
                    continue
                keep_indices.add(index)
            continue

        for index, _ in filtered_members:
            keep_indices.add(index)

    deduped = [item for index, item in enumerate(items) if index in keep_indices]
    return deduped, removed_comment_flaw


def _resolve_flow_assignment(
    *, child: ET.Element, function_lines: dict[str, list[int]], fn_to_flow: dict[str, str]
) -> tuple[str, str] | None:
    function_name: str | None
    if child.tag in COMMENT_TAGS:
        function_name = child.attrib.get('function')
    else:
        line_no = int(child.attrib.get('line', '0') or 0)
        function_name = infer_function_for_flaw(line_no, function_lines)

    flow = fn_to_flow.get(function_name or '')
    if flow is None:
        return None
    return flow_type_from_function(flow, function_name), function_name or ''


def _add_flow_tags_to_tree(
    *,
    tree: ET.ElementTree,
    input_xml: Path,
    fn_to_flow: dict[str, str],
    output_xml: Path,
    summary_json: Path | None = None,
    prune_single_child_flows: bool = True,
) -> dict[str, object]:
    root = tree.getroot()
    per_flow_counts = Counter()
    tag_counts = Counter()
    unresolved_flaw = 0
    unresolved_comment = 0
    testcase_count = 0
    dedup_removed_comment_flaw = 0

    for testcase in root.findall('testcase'):
        testcase_count += 1
        for old_flow in list(testcase.findall('flow')):
            testcase.remove(old_flow)

        flow_buckets: dict[str, list[ET.Element]] = defaultdict(list)
        for file_elem in testcase.findall('file'):
            file_path = file_elem.attrib.get('path', '')
            function_lines: dict[str, list[int]] = defaultdict(list)
            for child in list(file_elem):
                if child.tag not in COMMENT_TAGS:
                    continue
                function_name = child.attrib.get('function')
                if function_name:
                    function_lines[function_name].append(int(child.attrib.get('line', '0') or 0))

            for child in list(file_elem):
                if child.tag not in FLOW_PARTITION_TARGET_TAGS:
                    continue

                assignment = _resolve_flow_assignment(
                    child=child,
                    function_lines=function_lines,
                    fn_to_flow=fn_to_flow,
                )
                if assignment is None:
                    if child.tag in COMMENT_TAGS:
                        unresolved_comment += 1
                    else:
                        unresolved_flaw += 1
                    continue

                flow_type, function_name = assignment

                copied = _normalize_flow_item(
                    child=child,
                    file_path=file_path,
                    function_name=function_name,
                )
                flow_buckets[flow_type].append(copied)

        for flow_type in sorted(flow_buckets, key=_flow_sort_key):
            items, removed = _dedup_flow_items(flow_buckets[flow_type])
            dedup_removed_comment_flaw += removed
            if not items:
                continue
            if prune_single_child_flows and len(items) == 1:
                continue

            flow_elem = ET.Element('flow', {'type': flow_type})
            for item in items:
                flow_elem.append(item)
                per_flow_counts[flow_type] += 1
                tag_counts[item.tag] += 1
            testcase.append(flow_elem)

    output_xml.parent.mkdir(parents=True, exist_ok=True)
    try:
        ET.indent(tree, space='  ')
    except AttributeError:
        pass
    tree.write(output_xml, encoding='utf-8', xml_declaration=True)

    summary = {
        'input_xml': str(input_xml),
        'output_xml': str(output_xml),
        'testcases': testcase_count,
        'flow_tag_item_counts': dict(
            sorted(per_flow_counts.items(), key=lambda item: _flow_sort_key(item[0]))
        ),
        'tag_counts_in_flows': dict(tag_counts),
        'unresolved_comment_records': unresolved_comment,
        'unresolved_flaw_records': unresolved_flaw,
        'dedup_removed_comment_flaw_records': dedup_removed_comment_flaw,
    }
    if summary_json is not None:
        write_summary_json(summary_json, summary, echo=False)
    return summary


def add_flow_tags_to_testcase(
    *,
    input_xml: Path,
    output_xml: Path,
    summary_json: Path | None = None,
    prune_single_child_flows: bool = True,
) -> dict[str, object]:
    if not input_xml.exists():
        raise FileNotFoundError(f'Input XML not found: {input_xml}')

    return _add_flow_tags_to_tree(
        tree=ET.parse(input_xml),
        input_xml=input_xml,
        fn_to_flow=build_function_flow_map_from_manifest_comments(input_xml),
        output_xml=output_xml,
        summary_json=summary_json,
        prune_single_child_flows=prune_single_child_flows,
    )


def run_stage02b_flow(
    *,
    input_xml: Path,
    output_dir: Path,
    prune_single_child_flows: bool = True,
) -> dict[str, object]:
    output_paths = build_stage02b_output_paths(output_dir)
    partition_result = add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_paths['manifest_with_testcase_flows_xml'],
        summary_json=None,
        prune_single_child_flows=prune_single_child_flows,
    )
    artifacts = path_strings(output_paths)
    stats = {'testcases': int(partition_result['testcases'])}
    write_stage_summary(output_paths['summary_json'], artifacts=artifacts, stats=stats, echo=False)
    return {'artifacts': artifacts, 'stats': stats}
