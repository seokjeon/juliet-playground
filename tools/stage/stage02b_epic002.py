from __future__ import annotations

import copy
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

from shared.artifact_layout import path_strings
from shared.jsonio import write_stage_summary, write_summary_json

COMMENT_TAGS = {'flaw', 'fix'}
ENTRY_FUNCTION_NAMES = {
    'bad',
    'goodG2B',
    'goodG2B1',
    'goodG2B2',
    'goodB2G',
    'goodB2G1',
    'goodB2G2',
}
FLOW_ROLE_SAFETY = {
    'b2b': {'source': 'bad', 'sink': 'bad'},
    'b2g': {'source': 'bad', 'sink': 'good'},
    'g2b': {'source': 'good', 'sink': 'bad'},
}


def build_stage02b_epic002_output_paths(output_dir: Path) -> dict[str, Path]:
    return {
        'output_dir': output_dir,
        'source_sink_classified_xml': output_dir / 'source_sink_classified.xml',
        'source_sink_exceptions_xml': output_dir / 'source_sink_exceptions.xml',
        'summary_json': output_dir / 'summary.json',
    }


def local_tag(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def find_child_elements(parent: ET.Element, tag_name: str) -> list[ET.Element]:
    return [child for child in parent if local_tag(child.tag) == tag_name]


def get_attr_local(element: ET.Element, attr_name: str) -> str | None:
    if attr_name in element.attrib:
        return element.attrib[attr_name]
    for key, value in element.attrib.items():
        if local_tag(key) == attr_name:
            return value
    return None


def get_flow_function(element: ET.Element) -> str | None:
    function = get_attr_local(element, 'function')
    if function:
        return function
    return get_attr_local(element, 'inferred_function')


def function_tail(function_name: str | None) -> str:
    if not function_name:
        return ''
    return function_name.rsplit('::', 1)[-1]


def is_entry_tail(tail: str) -> bool:
    if tail in ENTRY_FUNCTION_NAMES:
        return True
    return any(tail.endswith(f'_{entry_name}') for entry_name in ENTRY_FUNCTION_NAMES)


def is_constructor(function_name: str | None) -> bool:
    if not function_name or '::' not in function_name:
        return False
    class_name, method_name = function_name.rsplit('::', 1)
    class_short_name = class_name.rsplit('::', 1)[-1]
    return method_name == class_short_name


def is_destructor(function_name: str | None) -> bool:
    return bool(function_name and '::~' in function_name)


def classify_function_role(function_name: str | None) -> str:
    tail = function_tail(function_name)
    tail_lower = tail.lower()
    if 'source' in tail_lower:
        return 'source'
    if tail_lower == 'action' or 'sink' in tail_lower:
        return 'sink'
    if is_entry_tail(tail):
        return 'entry'
    return 'unknown'


def parse_line_number(element: ET.Element) -> int | None:
    raw_line = str(get_attr_local(element, 'line') or '').strip()
    try:
        return int(raw_line)
    except ValueError:
        return None


def has_scope_marker(function_name: str | None) -> bool:
    return bool(function_name and '::' in function_name)


def has_destructor_marker(function_name: str | None) -> bool:
    return bool(function_name and '::~' in function_name)


def is_flow_comment_element(element: ET.Element) -> bool:
    if local_tag(element.tag) in COMMENT_TAGS:
        return get_flow_function(element) is not None
    return False


def classify_pair(comments: list[ET.Element]) -> tuple[dict[str, object] | None, str | None]:
    first, second = comments
    first_function = get_flow_function(first)
    second_function = get_flow_function(second)

    if (get_attr_local(first, 'file'), first_function) == (
        get_attr_local(second, 'file'),
        second_function,
    ):
        first_line = parse_line_number(first)
        second_line = parse_line_number(second)
        if first_line is None or second_line is None:
            return None, 'invalid_line_number'
        if first_line == second_line:
            return None, 'same_function_same_line'

        source, sink = (first, second) if first_line < second_line else (second, first)
        return {'method': 'same_function_line_order', 'source': source, 'sink': sink}, None

    first_role = classify_function_role(first_function)
    second_role = classify_function_role(second_function)
    pair_roles = (first_role, second_role)

    if pair_roles == ('entry', 'entry'):
        first_is_dtor = has_destructor_marker(first_function)
        second_is_dtor = has_destructor_marker(second_function)
        if first_is_dtor ^ second_is_dtor:
            source, sink = (second, first) if first_is_dtor else (first, second)
            return {'method': 'ctor_dtor_rule', 'source': source, 'sink': sink}, None
        return None, 'entry_entry_pair'

    if pair_roles in {('source', 'sink'), ('source', 'entry'), ('entry', 'sink')}:
        return {'method': 'function_name_rule', 'source': first, 'sink': second}, None
    if pair_roles in {('sink', 'source'), ('entry', 'source'), ('sink', 'entry')}:
        return {'method': 'function_name_rule', 'source': second, 'sink': first}, None

    return None, 'unhandled_function_name_pattern'


def class_scope(function_name: str | None) -> str | None:
    if not function_name or '::' not in function_name:
        return None
    return function_name.rsplit('::', 1)[0]


def classify_triplet(comments: list[ET.Element]) -> tuple[dict[str, object] | None, str | None]:
    ctor_candidates = [
        comment for comment in comments if is_constructor(get_flow_function(comment))
    ]
    dtor_candidates = [comment for comment in comments if is_destructor(get_flow_function(comment))]

    if len(ctor_candidates) != 1:
        return None, 'triplet_ctor_count_not_1'
    if not dtor_candidates:
        return None, 'triplet_no_destructor'

    source = ctor_candidates[0]
    source_function = get_flow_function(source)
    source_scope = class_scope(source_function)
    source_file = get_attr_local(source, 'file')

    scoped_dtor_candidates = [
        comment
        for comment in dtor_candidates
        if class_scope(get_flow_function(comment)) == source_scope
        and get_attr_local(comment, 'file') == source_file
    ]
    if not scoped_dtor_candidates:
        scoped_dtor_candidates = dtor_candidates

    manifest_dtor_candidates = [
        comment
        for comment in scoped_dtor_candidates
        if get_attr_local(comment, 'origin') == 'manifest_flaw'
    ]
    sink_pool = manifest_dtor_candidates or scoped_dtor_candidates
    sink = max(sink_pool, key=lambda element: parse_line_number(element) or -1)
    return {'method': 'ctor_dtor_triplet_rule', 'source': source, 'sink': sink}, None


def classify_multi_comment_by_line_extrema(
    comments: list[ET.Element],
) -> tuple[dict[str, object] | None, str | None]:
    with_lines: list[tuple[ET.Element, int]] = []
    for comment in comments:
        line = parse_line_number(comment)
        if line is None:
            return None, 'invalid_line_number'
        with_lines.append((comment, line))

    source, min_line = min(with_lines, key=lambda item: item[1])
    sink, max_line = max(with_lines, key=lambda item: item[1])
    if min_line == max_line:
        return None, 'same_function_same_line'
    return {'method': 'multi_comment_line_extrema', 'source': source, 'sink': sink}, None


def indent_xml(element: ET.Element, level: int = 0) -> None:
    pad = '\n' + level * '  '
    if len(element):
        if not element.text or not element.text.strip():
            element.text = pad + '  '
        for child in element:
            indent_xml(child, level + 1)
        if not element[-1].tail or not element[-1].tail.strip():
            element[-1].tail = pad
    if level and (not element.tail or not element.tail.strip()):
        element.tail = pad


def element_key(element: ET.Element) -> tuple[str, str | None, str | None, str | None, str | None]:
    return (
        local_tag(element.tag),
        get_attr_local(element, 'line'),
        get_attr_local(element, 'function') or get_attr_local(element, 'inferred_function'),
        get_attr_local(element, 'file'),
        get_attr_local(element, 'code'),
    )


def classify_manifest(manifest_xml: Path) -> tuple[dict[str, object], ET.Element, ET.Element]:
    root = ET.parse(manifest_xml).getroot()

    counts = Counter()
    flow_type_counts = Counter()
    ordering_method_counts = Counter()
    exception_comment_count_distribution = Counter()
    exception_reason_counts = Counter()

    classified_root = ET.Element(root.tag)
    exception_root = ET.Element(root.tag)

    for testcase_index, testcase in enumerate(find_child_elements(root, 'testcase'), start=1):
        counts['testcases_total'] += 1
        file_elems = find_child_elements(testcase, 'file')
        classified_flows: list[ET.Element] = []
        skipped_flows: list[ET.Element] = []

        for flow_index, flow in enumerate(find_child_elements(testcase, 'flow'), start=1):
            counts['flows_total'] += 1
            flow_type = str(flow.get('type') or '').strip()
            flow_type_counts[flow_type] += 1

            comments = [
                child
                for child in flow.iter()
                if child is not flow
                and local_tag(child.tag) in COMMENT_TAGS
                and is_flow_comment_element(child)
            ]
            if len(comments) < 2:
                counts['exception_flows_total'] += 1
                counts['exception_flows_comment_count_lt_2'] += 1
                exception_reason_counts['comment_count_lt_2'] += 1
                exception_comment_count_distribution[len(comments)] += 1
                flow_copy = copy.deepcopy(flow)
                flow_copy.attrib['flow_index'] = str(flow_index)
                flow_copy.attrib['skip_reason'] = 'comment_count_lt_2'
                flow_copy.attrib['comment_tag_count'] = str(len(comments))
                skipped_flows.append(flow_copy)
                continue

            if len(comments) == 2:
                classified, error = classify_pair(comments)
            elif len(comments) == 3:
                classified, error = classify_triplet(comments)
                if classified is None:
                    classified, error = classify_multi_comment_by_line_extrema(comments)
            else:
                classified, error = classify_multi_comment_by_line_extrema(comments)

            if error is not None or classified is None:
                counts['exception_flows_total'] += 1
                counts['exception_flows_function_name_rule_failed'] += 1
                if error == 'entry_entry_pair':
                    counts['exception_flows_entry_entry_pair'] += 1
                    functions = [get_flow_function(comment) for comment in comments]
                    if any(has_scope_marker(function_name) for function_name in functions):
                        counts['exception_flows_entry_entry_pair_with_scope'] += 1
                    if any(has_destructor_marker(function_name) for function_name in functions):
                        counts['exception_flows_entry_entry_pair_with_destructor'] += 1
                if len(comments) == 3:
                    functions = [get_flow_function(comment) for comment in comments]
                    if not any(has_scope_marker(function_name) for function_name in functions):
                        counts['exception_flows_triplet_without_scope'] += 1
                    if not any(has_destructor_marker(function_name) for function_name in functions):
                        counts['exception_flows_triplet_without_destructor'] += 1
                exception_reason_counts[error or 'function_name_rule_failed'] += 1
                flow_copy = copy.deepcopy(flow)
                flow_copy.attrib['flow_index'] = str(flow_index)
                flow_copy.attrib['skip_reason'] = error or 'function_name_rule_failed'
                flow_copy.attrib['comment_tag_count'] = str(len(comments))
                skipped_flows.append(flow_copy)
                continue

            counts['classified_flows_total'] += 1
            counts[f'classified_flows_{classified["method"]}'] += 1
            ordering_method_counts[classified['method']] += 1
            source_key = element_key(classified['source'])
            sink_key = element_key(classified['sink'])
            flow_copy = copy.deepcopy(flow)
            flow_copy.attrib['flow_index'] = str(flow_index)
            flow_copy.attrib['classification_method'] = str(classified['method'])
            for child in flow_copy.iter():
                if child is flow_copy or local_tag(child.tag) not in COMMENT_TAGS:
                    continue
                key = element_key(child)
                if key == source_key:
                    child.attrib['role'] = 'source'
                    child.attrib['safety'] = FLOW_ROLE_SAFETY.get(flow_type[:3], {}).get(
                        'source', ''
                    )
                elif key == sink_key:
                    child.attrib['role'] = 'sink'
                    child.attrib['safety'] = FLOW_ROLE_SAFETY.get(flow_type[:3], {}).get('sink', '')
            classified_flows.append(flow_copy)

        if classified_flows:
            counts['testcases_with_classified_flows'] += 1
            classified_testcase = ET.Element('testcase', {'testcase_index': str(testcase_index)})
            for file_elem in file_elems:
                classified_testcase.append(copy.deepcopy(file_elem))
            for classified_flow in classified_flows:
                classified_testcase.append(classified_flow)
            classified_root.append(classified_testcase)
        if skipped_flows:
            counts['testcases_with_skipped_flows'] += 1
            exception_testcase = ET.Element('testcase', {'testcase_index': str(testcase_index)})
            for file_elem in file_elems:
                exception_testcase.append(copy.deepcopy(file_elem))
            for skipped_flow in skipped_flows:
                exception_testcase.append(skipped_flow)
            exception_root.append(exception_testcase)

    payload = {
        'manifest_xml': str(manifest_xml),
        'entry_entry_pair_count': int(exception_reason_counts.get('entry_entry_pair', 0)),
        'entry_entry_pair_with_scope_count': int(
            counts.get('exception_flows_entry_entry_pair_with_scope', 0)
        ),
        'entry_entry_pair_with_destructor_count': int(
            counts.get('exception_flows_entry_entry_pair_with_destructor', 0)
        ),
        'triplet_without_scope_count': int(counts.get('exception_flows_triplet_without_scope', 0)),
        'triplet_without_destructor_count': int(
            counts.get('exception_flows_triplet_without_destructor', 0)
        ),
        'counts': dict(counts),
        'flow_type_counts': dict(sorted(flow_type_counts.items())),
        'ordering_method_counts': dict(sorted(ordering_method_counts.items())),
        'exception_comment_count_distribution': dict(
            sorted(exception_comment_count_distribution.items())
        ),
        'exception_reason_counts': dict(sorted(exception_reason_counts.items())),
    }
    return payload, classified_root, exception_root


def build_classification_summary(
    *,
    manifest_xml: Path,
    output_xml: Path,
    exceptions_xml: Path | None,
    payload: dict[str, object],
) -> dict[str, object]:
    return {
        'manifest_xml': str(manifest_xml),
        'output_xml': str(output_xml),
        'exceptions_xml': str(exceptions_xml) if exceptions_xml is not None else None,
        'entry_entry_pair_count': payload['entry_entry_pair_count'],
        'entry_entry_pair_with_scope_count': payload['entry_entry_pair_with_scope_count'],
        'entry_entry_pair_with_destructor_count': payload['entry_entry_pair_with_destructor_count'],
        'triplet_without_scope_count': payload['triplet_without_scope_count'],
        'triplet_without_destructor_count': payload['triplet_without_destructor_count'],
        'counts': payload['counts'],
        'flow_type_counts': payload['flow_type_counts'],
        'ordering_method_counts': payload['ordering_method_counts'],
        'exception_comment_count_distribution': payload['exception_comment_count_distribution'],
        'exception_reason_counts': payload['exception_reason_counts'],
    }


def write_classification_outputs(
    *,
    manifest_xml: Path,
    output_xml: Path,
    exceptions_xml: Path | None = None,
    summary_json: Path | None = None,
) -> dict[str, object]:
    if not manifest_xml.exists():
        raise FileNotFoundError(f'Manifest XML not found: {manifest_xml}')

    payload, classified_root, exception_root = classify_manifest(manifest_xml)
    summary = build_classification_summary(
        manifest_xml=manifest_xml,
        output_xml=output_xml,
        exceptions_xml=exceptions_xml,
        payload=payload,
    )

    output_xml.parent.mkdir(parents=True, exist_ok=True)
    indent_xml(classified_root)
    ET.ElementTree(classified_root).write(output_xml, encoding='utf-8', xml_declaration=True)

    if exceptions_xml is not None:
        exceptions_xml.parent.mkdir(parents=True, exist_ok=True)
        indent_xml(exception_root)
        ET.ElementTree(exception_root).write(exceptions_xml, encoding='utf-8', xml_declaration=True)

    if summary_json is not None:
        summary_json.parent.mkdir(parents=True, exist_ok=True)
        write_summary_json(summary_json, summary, echo=False)

    return summary


def run_stage02b_epic002(*, input_xml: Path, output_dir: Path) -> dict[str, object]:
    output_paths = build_stage02b_epic002_output_paths(output_dir)
    summary = write_classification_outputs(
        manifest_xml=input_xml,
        output_xml=output_paths['source_sink_classified_xml'],
        exceptions_xml=output_paths['source_sink_exceptions_xml'],
        summary_json=None,
    )
    artifacts = path_strings(output_paths)
    stats = dict(summary.get('counts') or {})
    extra = {
        'input_xml': str(input_xml),
        'flow_type_counts': summary.get('flow_type_counts') or {},
        'ordering_method_counts': summary.get('ordering_method_counts') or {},
        'exception_comment_count_distribution': summary.get('exception_comment_count_distribution')
        or {},
        'exception_reason_counts': summary.get('exception_reason_counts') or {},
        'entry_entry_pair_count': summary.get('entry_entry_pair_count', 0),
        'entry_entry_pair_with_scope_count': summary.get('entry_entry_pair_with_scope_count', 0),
        'entry_entry_pair_with_destructor_count': summary.get(
            'entry_entry_pair_with_destructor_count',
            0,
        ),
        'triplet_without_scope_count': summary.get('triplet_without_scope_count', 0),
        'triplet_without_destructor_count': summary.get('triplet_without_destructor_count', 0),
    }
    write_stage_summary(
        output_paths['summary_json'],
        artifacts=artifacts,
        stats=stats,
        extra=extra,
        echo=False,
    )
    return {'artifacts': artifacts, 'stats': stats, **extra}
