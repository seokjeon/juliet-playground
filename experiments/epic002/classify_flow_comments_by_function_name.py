#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

COMMENT_TAGS = {'comment_flaw', 'comment_fix'}
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
FIELD_GUIDE = {
    'top_level': {
        'counts': '전체 testcase/flow 처리 통계',
        'flow_type_counts': 'flow type(b2b, b2g, g2b 등)별 개수',
        'ordering_method_counts': 'source/sink 순서를 어떤 방식으로 정했는지에 대한 통계',
        'exception_comment_count_distribution': '예외 flow에서 comment_flaw/comment_fix 태그가 몇 개였는지 분포',
        'exception_reason_counts': '예외가 발생한 이유별 개수',
        'testcases': 'testcase별 상세 분류 결과',
    },
    'classified_flow': {
        'flow_index': '해당 testcase 안에서 몇 번째 flow인지',
        'flow_type': 'Juliet flow type. 예: b2b, b2g, g2b, g2b1',
        'classification_method': 'source/sink를 어떤 규칙으로 정했는지',
        'source': '이 flow에서 source로 판단된 comment 태그 정보',
        'sink': '이 flow에서 sink로 판단된 comment 태그 정보',
    },
    'role_payload': {
        'tag': '원래 XML 태그 이름(comment_flaw 또는 comment_fix)',
        'manifest_file': 'manifest 안에 기록된 파일명',
        'function': '해당 comment가 속한 함수명',
        'line': 'manifest에 기록된 줄 번호',
        'xml_code': 'manifest XML의 code 속성 문자열',
        'role': '이 스크립트가 부여한 역할(source 또는 sink)',
        'safety': 'flow type 기준 안전/취약 방향. bad 또는 good',
    },
    'classification_method_values': {
        'same_function_line_order': '같은 함수 안에 comment 2개가 있을 때 줄 번호 순서로 source/sink를 결정',
        'function_name_rule': 'Juliet 함수명 규칙(Source, Sink, bad, goodG2B 등)으로 source/sink를 결정',
    },
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            'Classify flow-level comment_flaw/comment_fix tags using only function-name rules '
            'plus same-function line order.'
        )
    )
    parser.add_argument(
        '--manifest-xml',
        type=Path,
        required=True,
        help='입력 manifest_with_testcase_flows.xml 경로',
    )
    parser.add_argument(
        '--output-json',
        type=Path,
        required=True,
        help='source/sink 분류 결과를 저장할 JSON 경로',
    )
    parser.add_argument(
        '--exceptions-xml',
        type=Path,
        default=None,
        help='분류하지 못한 flow를 저장할 XML 경로 (선택)',
    )
    parser.add_argument(
        '--summary-json',
        type=Path,
        default=None,
        help='요약 통계만 따로 저장할 JSON 경로 (선택)',
    )
    return parser.parse_args()


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

    # Juliet 전용 규칙: 현재 manifest에서는 source/sink 이름이 섞여있어, 우선순위가 깨지는 경우는 없음
    if is_constructor(function_name) or 'Source' in tail:
        return 'source'
    if (
        is_destructor(function_name)
        or tail == 'action'
        or 'VaSink' in tail
        or 'vasink' in tail
        or 'Sink' in tail
    ):
        return 'sink'
    if is_entry_tail(tail):
        return 'entry'
    return 'unknown'


def parse_line_number(element: ET.Element) -> int | None:
    raw_line = str(element.get('line') or '').strip()
    try:
        return int(raw_line)
    except ValueError:
        return None


def make_role_payload(element: ET.Element, role: str, flow_type: str) -> dict[str, object]:
    return {
        'tag': element.tag,
        'manifest_file': element.get('file'),
        'function': element.get('function'),
        'line': parse_line_number(element),
        'xml_code': element.get('code'),
        'role': role,
        'safety': FLOW_ROLE_SAFETY.get(flow_type[:3], {}).get(role),
    }


def classify_pair(comments: list[ET.Element]) -> tuple[dict[str, object] | None, str | None]:
    first, second = comments
    first_function = first.get('function')
    second_function = second.get('function')

    # 단일 함수내에 source/sink가 모두 존재하는 경우
    if (first.get('file'), first_function) == (second.get('file'), second_function):
        first_line = parse_line_number(first)
        second_line = parse_line_number(second)
        if first_line is None or second_line is None:
            return None, 'invalid_line_number'
        if first_line == second_line:
            return None, 'same_function_same_line'
        
        source, sink = (first, second) if first_line < second_line else (second, first)
        return {
            'method': 'same_function_line_order',
            'source': source,
            'sink': sink,
        }, None

    # 다중 함수를 거쳐 source/sink가 존재하는 경우
    first_role = classify_function_role(first_function)
    second_role = classify_function_role(second_function)
    pair_roles = (first_role, second_role)

    if pair_roles in {('source', 'sink'), ('source', 'entry'), ('entry', 'sink')}:
        return {'method': 'function_name_rule', 'source': first, 'sink': second}, None
    if pair_roles in {('sink', 'source'), ('entry', 'source'), ('sink', 'entry')}:
        return {'method': 'function_name_rule', 'source': second, 'sink': first}, None

    return None, 'unhandled_function_name_pattern'


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


def classify_manifest(manifest_xml: Path) -> tuple[dict[str, object], ET.Element]:
    # 입력: manifest XML 파일 경로
    # 출력: JSON 저장용 분류 결과와 예외 flow를 담은 XML 루트
    # 작업: 각 testcase/flow를 돌며 source/sink를 분류하고 통계를 세고 예외를 모음
    root = ET.parse(manifest_xml).getroot()

    counts = Counter()
    flow_type_counts = Counter()
    ordering_method_counts = Counter()
    exception_comment_count_distribution = Counter()
    exception_reason_counts = Counter()

    results: list[dict[str, object]] = []
    exception_root = ET.Element(root.tag)
    
    # testcase 태그
    for testcase_index, testcase in enumerate(root.findall('testcase'), start=1):
        counts['testcases_total'] += 1
        file_elems = testcase.findall('file')
        classified_flows: list[dict[str, object]] = []
        skipped_flows: list[ET.Element] = []

        # flow 태그
        for flow_index, flow in enumerate(testcase.findall('flow'), start=1):
            counts['flows_total'] += 1
            flow_type = str(flow.get('type') or '').strip()
            flow_type_counts[flow_type] += 1

            comments = [child for child in flow if child.tag in COMMENT_TAGS]
            if len(comments) != 2:
                counts['exception_flows_total'] += 1
                counts['exception_flows_comment_count_not_2'] += 1
                exception_reason_counts['comment_count_not_2'] += 1
                exception_comment_count_distribution[len(comments)] += 1
                flow_copy = copy.deepcopy(flow)
                flow_copy.attrib['skip_reason'] = 'comment_count_not_2'
                flow_copy.attrib['comment_tag_count'] = str(len(comments))
                skipped_flows.append(flow_copy)
                continue

            # flow 태그로부터 source/sink 분류하는 로직
            classified, error = classify_pair(comments)
            if error is not None or classified is None:
                counts['exception_flows_total'] += 1
                counts['exception_flows_function_name_rule_failed'] += 1
                exception_reason_counts[error or 'function_name_rule_failed'] += 1
                flow_copy = copy.deepcopy(flow)
                flow_copy.attrib['skip_reason'] = error or 'function_name_rule_failed'
                flow_copy.attrib['comment_tag_count'] = '2'
                skipped_flows.append(flow_copy)
                continue

            counts['classified_flows_total'] += 1
            counts[f'classified_flows_{classified["method"]}'] += 1
            ordering_method_counts[classified['method']] += 1
            classified_flows.append(
                {
                    'flow_index': flow_index,
                    'flow_type': flow_type,
                    'classification_method': classified['method'],
                    'source': make_role_payload(classified['source'], 'source', flow_type),
                    'sink': make_role_payload(classified['sink'], 'sink', flow_type),
                }
            )

        if classified_flows:
            counts['testcases_with_classified_flows'] += 1
        if skipped_flows:
            counts['testcases_with_skipped_flows'] += 1
            exception_testcase = ET.Element('testcase', {'testcase_index': str(testcase_index)})
            for file_elem in file_elems:
                exception_testcase.append(copy.deepcopy(file_elem))
            for skipped_flow in skipped_flows:
                exception_testcase.append(skipped_flow)
            exception_root.append(exception_testcase)

        results.append(
            {
                'testcase_index': testcase_index,
                'manifest_files': [str(file_elem.get('path') or '').strip() for file_elem in file_elems],
                'classified_flow_count': len(classified_flows),
                'classified_flows': classified_flows,
            }
        )

    payload = {
        'manifest_xml': str(manifest_xml),
        'field_guide': FIELD_GUIDE,
        # 전체 통계
        'counts': dict(counts),
        # flow type 별 통계
        'flow_type_counts': dict(sorted(flow_type_counts.items())),
        # 분류 방법 별 통계(단일함수 or 다중함수)
        'ordering_method_counts': dict(sorted(ordering_method_counts.items())),
        # exception flow 의 comment_flaw | comment_fix 태그 개수
        'exception_comment_count_distribution': dict(sorted(exception_comment_count_distribution.items())),
        # 예외 이유별 개수
        'exception_reason_counts': dict(sorted(exception_reason_counts.items())),
        # 테스트케이스별 상세 결과
        'testcases': results,
    }
    return payload, exception_root


def main() -> int:
    args = parse_args()
    manifest_xml = args.manifest_xml.resolve()
    output_json = args.output_json.resolve()
    exceptions_xml = args.exceptions_xml.resolve() if args.exceptions_xml is not None else None
    summary_json = args.summary_json.resolve() if args.summary_json is not None else None

    if not manifest_xml.exists():
        raise FileNotFoundError(f'Manifest XML not found: {manifest_xml}')

    payload, exception_root = classify_manifest(manifest_xml)
    payload['output_json'] = str(output_json)
    payload['exceptions_xml'] = str(exceptions_xml) if exceptions_xml is not None else None

    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    if exceptions_xml is not None:
        exceptions_xml.parent.mkdir(parents=True, exist_ok=True)
        indent_xml(exception_root)
        ET.ElementTree(exception_root).write(exceptions_xml, encoding='utf-8', xml_declaration=True)

    summary = {
        'manifest_xml': str(manifest_xml),
        'output_json': str(output_json),
        'exceptions_xml': str(exceptions_xml) if exceptions_xml is not None else None,
        'counts': payload['counts'],
        'flow_type_counts': payload['flow_type_counts'],
        'ordering_method_counts': payload['ordering_method_counts'],
        'exception_comment_count_distribution': payload['exception_comment_count_distribution'],
        'exception_reason_counts': payload['exception_reason_counts'],
    }
    if summary_json is not None:
        summary_json.parent.mkdir(parents=True, exist_ok=True)
        summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
