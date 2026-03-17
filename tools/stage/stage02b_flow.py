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
BASE_FLOW_ORDER = ('b2b', 'b2g', 'g2b')
FAMILY_TO_FLOW = {
    'b2b_family': 'b2b',
    'b2g_family': 'b2g',
    'g2b_family': 'g2b',
}
FLOW_NUM_SUFFIX = {
    'b2g': re.compile(r'b2g(\d+)(?:sink)?$', re.IGNORECASE),
    'g2b': re.compile(r'g2b(\d+)(?:sink)?$', re.IGNORECASE),
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


def _add_flow_tags_to_tree(
    *,
    tree: ET.ElementTree,
    input_xml: Path,
    fn_to_flow: dict[str, str],
    output_xml: Path,
    summary_json: Path | None = None,
) -> dict[str, object]:
    root = tree.getroot()
    per_flow_counts = Counter()
    tag_counts = Counter()
    unresolved_flaw = 0
    unresolved_comment = 0
    testcase_count = 0

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
                line_no = int(child.attrib.get('line', '0') or 0)
                if function_name:
                    function_lines[function_name].append(line_no)

            for child in list(file_elem):
                if child.tag not in FLOW_PARTITION_TARGET_TAGS:
                    continue

                line_no = int(child.attrib.get('line', '0') or 0)
                inferred_function = None
                if child.tag in COMMENT_TAGS:
                    function_name = child.attrib.get('function')
                    flow = fn_to_flow.get(function_name or '')
                    if flow is None:
                        unresolved_comment += 1
                        continue
                    flow_type = flow_type_from_function(flow, function_name)
                else:
                    inferred_function = infer_function_for_flaw(line_no, function_lines)
                    flow = fn_to_flow.get(inferred_function or '')
                    if flow is None:
                        unresolved_flaw += 1
                        continue
                    flow_type = flow_type_from_function(flow, inferred_function)

                copied = copy.deepcopy(child)
                copied.attrib['file'] = file_path
                if inferred_function:
                    copied.attrib['inferred_function'] = inferred_function
                flow_buckets[flow_type].append(copied)
                per_flow_counts[flow_type] += 1
                tag_counts[child.tag] += 1

        for flow_type in sorted(flow_buckets, key=_flow_sort_key):
            flow_elem = ET.Element('flow', {'type': flow_type})
            for item in flow_buckets[flow_type]:
                flow_elem.append(item)
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
    }
    if summary_json is not None:
        write_summary_json(summary_json, summary, echo=False)
    return summary


def add_flow_tags_to_testcase(
    *,
    input_xml: Path,
    output_xml: Path,
    summary_json: Path | None = None,
) -> dict[str, object]:
    if not input_xml.exists():
        raise FileNotFoundError(f'Input XML not found: {input_xml}')

    return _add_flow_tags_to_tree(
        tree=ET.parse(input_xml),
        input_xml=input_xml,
        fn_to_flow=build_function_flow_map_from_manifest_comments(input_xml),
        output_xml=output_xml,
        summary_json=summary_json,
    )


def run_stage02b_flow(
    *,
    input_xml: Path,
    output_dir: Path,
) -> dict[str, object]:
    output_paths = build_stage02b_output_paths(output_dir)
    partition_result = add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_paths['manifest_with_testcase_flows_xml'],
        summary_json=None,
    )
    artifacts = path_strings(output_paths)
    stats = {'testcases': int(partition_result['testcases'])}
    write_stage_summary(output_paths['summary_json'], artifacts=artifacts, stats=stats, echo=False)
    return {'artifacts': artifacts, 'stats': stats}
