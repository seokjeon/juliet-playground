#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

TARGET_TAGS = ("comment_flaw", "comment_fix", "flaw")
BASE_FLOW_ORDER = ("b2b", "b2g", "g2b")
FAMILY_TO_FLOW = {
    "b2b_family": "b2b",
    "b2g_family": "b2g",
    "g2b_family": "g2b",
}
FLOW_NUM_SUFFIX = {
    "b2g": re.compile(r"b2g(\d+)$", re.IGNORECASE),
    "g2b": re.compile(r"g2b(\d+)$", re.IGNORECASE),
}


def load_function_flow_map(categorized_jsonl: Path) -> dict[str, str]:
    mapping: dict[str, str] = {}
    with categorized_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            obj = json.loads(line)
            fn = obj.get("function_name")
            fam = obj.get("flow_family")
            flow = FAMILY_TO_FLOW.get(fam)
            if fn and flow:
                mapping[fn] = flow
    return mapping


def infer_function_for_flaw(line_no: int, function_lines: dict[str, list[int]]) -> str | None:
    if not function_lines:
        return None
    best_fn = None
    best_dist = None
    for fn, lines in function_lines.items():
        for ln in lines:
            dist = abs(ln - line_no)
            if best_dist is None or dist < best_dist:
                best_dist = dist
                best_fn = fn
    return best_fn


def flow_type_from_function(base_flow: str, function_name: str | None) -> str:
    if base_flow not in FLOW_NUM_SUFFIX or not function_name:
        return base_flow
    m = FLOW_NUM_SUFFIX[base_flow].search(function_name)
    if not m:
        return base_flow
    return f"{base_flow}{m.group(1)}"


def _flow_sort_key(flow_type: str) -> tuple[int, int, str]:
    for i, base in enumerate(BASE_FLOW_ORDER):
        if flow_type == base:
            return (i, -1, flow_type)
        if flow_type.startswith(base):
            suffix = flow_type[len(base) :]
            if suffix.isdigit():
                return (i, int(suffix), flow_type)
            return (i, 10**9, flow_type)
    return (10**9, 10**9, flow_type)


def indent(elem: ET.Element, level: int = 0) -> None:
    i = "\n" + level * "  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        for child in elem:
            indent(child, level + 1)
        if not elem[-1].tail or not elem[-1].tail.strip():
            elem[-1].tail = i
    if level and (not elem.tail or not elem.tail.strip()):
        elem.tail = i


def main() -> int:
    parser = argparse.ArgumentParser(description="Add per-testcase flow tags (b2b/b2g/g2b).")
    parser.add_argument(
        "--input-xml",
        type=Path,
        default=Path("experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml"),
    )
    parser.add_argument(
        "--function-categories-jsonl",
        type=Path,
        default=Path("experiments/epic001b_function_inventory/outputs/function_names_categorized.jsonl"),
    )
    parser.add_argument(
        "--output-xml",
        type=Path,
        default=Path("experiments/epic001c_testcase_flow_partition/outputs/manifest_with_testcase_flows.xml"),
    )
    parser.add_argument(
        "--summary-json",
        type=Path,
        default=Path("experiments/epic001c_testcase_flow_partition/outputs/summary.json"),
    )
    args = parser.parse_args()

    if not args.input_xml.exists():
        raise FileNotFoundError(f"Input XML not found: {args.input_xml}")
    if not args.function_categories_jsonl.exists():
        raise FileNotFoundError(f"Function categories JSONL not found: {args.function_categories_jsonl}")

    fn_to_flow = load_function_flow_map(args.function_categories_jsonl)
    tree = ET.parse(args.input_xml)
    root = tree.getroot()

    per_flow_counts = Counter()
    tag_counts = Counter()
    unresolved_flaw = 0
    unresolved_comment = 0
    testcase_count = 0

    for testcase in root.findall("testcase"):
        testcase_count += 1

        for old_flow in list(testcase.findall("flow")):
            testcase.remove(old_flow)

        flow_buckets: dict[str, list[ET.Element]] = defaultdict(list)

        for file_elem in testcase.findall("file"):
            file_path = file_elem.attrib.get("path", "")
            function_lines: dict[str, list[int]] = defaultdict(list)

            for child in list(file_elem):
                if child.tag in ("comment_flaw", "comment_fix"):
                    fn = child.attrib.get("function")
                    line_no = int(child.attrib.get("line", "0") or 0)
                    if fn:
                        function_lines[fn].append(line_no)

            for child in list(file_elem):
                if child.tag not in TARGET_TAGS:
                    continue

                line_no = int(child.attrib.get("line", "0") or 0)
                inferred_function = None

                if child.tag in ("comment_flaw", "comment_fix"):
                    fn = child.attrib.get("function")
                    flow = fn_to_flow.get(fn or "")
                    if flow is None:
                        unresolved_comment += 1
                        continue
                    flow_type = flow_type_from_function(flow, fn)
                else:
                    inferred_function = infer_function_for_flaw(line_no, function_lines)
                    flow = fn_to_flow.get(inferred_function or "")
                    if flow is None:
                        unresolved_flaw += 1
                        continue
                    flow_type = flow_type_from_function(flow, inferred_function)

                copied = copy.deepcopy(child)
                copied.attrib["file"] = file_path
                if inferred_function:
                    copied.attrib["inferred_function"] = inferred_function
                flow_buckets[flow_type].append(copied)
                per_flow_counts[flow_type] += 1
                tag_counts[child.tag] += 1

        for flow in sorted(flow_buckets.keys(), key=_flow_sort_key):
            items = flow_buckets[flow]
            if not items:
                continue
            flow_elem = ET.Element("flow", {"type": flow})
            for item in items:
                flow_elem.append(item)
            testcase.append(flow_elem)

    args.output_xml.parent.mkdir(parents=True, exist_ok=True)
    indent(root)
    tree.write(args.output_xml, encoding="utf-8", xml_declaration=True)

    summary = {
        "input_xml": str(args.input_xml),
        "function_categories_jsonl": str(args.function_categories_jsonl),
        "output_xml": str(args.output_xml),
        "testcases": testcase_count,
        "flow_tag_item_counts": dict(sorted(per_flow_counts.items(), key=lambda kv: _flow_sort_key(kv[0]))),
        "tag_counts_in_flows": dict(tag_counts),
        "unresolved_comment_records": unresolved_comment,
        "unresolved_flaw_records": unresolved_flaw,
    }
    args.summary_json.parent.mkdir(parents=True, exist_ok=True)
    args.summary_json.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
