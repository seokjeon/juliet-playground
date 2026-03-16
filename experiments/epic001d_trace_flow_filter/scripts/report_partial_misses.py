#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from shared.juliet_keys import derive_testcase_key_from_file_name
from stage.trace_flow import FlowPoint, TARGET_TAGS, load_flow_index


def load_trace_lines(trace_file: Path) -> set[tuple[str, int]]:
    obj = json.loads(trace_file.read_text(encoding="utf-8"))
    s: set[tuple[str, int]] = set()
    for step in obj.get("bug_trace", []):
        fn = Path(step.get("filename", "")).name
        ln = int(step.get("line_number", 0) or 0)
        if fn and ln > 0:
            s.add((fn, ln))
    fn = Path(obj.get("file", "")).name
    ln = int(obj.get("line", 0) or 0)
    if fn and ln > 0:
        s.add((fn, ln))
    return s


def main() -> int:
    ap = argparse.ArgumentParser(description="Report missed flow points for partial trace matches")
    ap.add_argument("--flow-xml", type=Path, default=Path("experiments/epic001c_testcase_flow_partition/outputs/manifest_with_testcase_flows.xml"))
    ap.add_argument("--all-match-jsonl", type=Path, default=Path("experiments/epic001d_trace_flow_filter/outputs/trace_flow_match_all.jsonl"))
    ap.add_argument("--output-dir", type=Path, default=Path("experiments/epic001d_trace_flow_filter/outputs"))
    args = ap.parse_args()

    flow_index = load_flow_index(args.flow_xml)

    partial_rows = []
    miss_tag_counter = Counter()
    miss_point_counter = Counter()

    with args.all_match_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            rec = json.loads(line)
            if rec.get("status") != "partial_match":
                continue
            testcase_key = rec.get("testcase_key")
            flow_type = rec.get("best_flow_type")
            trace_file = Path(rec.get("trace_file"))
            flows = flow_index.get(testcase_key, {})
            points = flows.get(flow_type, []) if flow_type else []
            if not points or not trace_file.exists():
                continue

            trace_lines = load_trace_lines(trace_file)
            unique = {}
            for p in points:
                unique[(p.file_name, p.line)] = p.tag

            missing = []
            hit = []
            for (file_name, line_no), tag in sorted(unique.items(), key=lambda x: (x[0][0], x[0][1])):
                if (file_name, line_no) in trace_lines:
                    hit.append({"file": file_name, "line": line_no, "tag": tag})
                else:
                    miss = {"file": file_name, "line": line_no, "tag": tag}
                    missing.append(miss)
                    miss_tag_counter[tag] += 1
                    miss_point_counter[(file_name, line_no, tag)] += 1

            partial_rows.append(
                {
                    "trace_file": rec.get("trace_file"),
                    "testcase_key": testcase_key,
                    "best_flow_type": flow_type,
                    "coverage": rec.get("best_flow_meta", {}).get("coverage"),
                    "hit_points": len(hit),
                    "missing_points": len(missing),
                    "missing": missing,
                    "hit": hit,
                }
            )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_jsonl = args.output_dir / "partial_miss_report.jsonl"
    out_summary = args.output_dir / "partial_miss_summary.json"

    with out_jsonl.open("w", encoding="utf-8") as f:
        for row in partial_rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    top_missing_points = [
        {"file": k[0], "line": k[1], "tag": k[2], "count": v}
        for k, v in miss_point_counter.most_common(50)
    ]

    summary = {
        "partial_traces": len(partial_rows),
        "missing_tag_counts": dict(miss_tag_counter),
        "top_missing_points": top_missing_points,
        "output_jsonl": str(out_jsonl),
    }
    out_summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
