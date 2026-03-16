#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from pathlib import Path

from shared.juliet_keys import derive_testcase_key_from_file_name as key_from_file_name
import xml.etree.ElementTree as ET


def load_flow_types(flow_xml: Path) -> dict[str, set[str]]:
    root = ET.parse(flow_xml).getroot()
    res: dict[str, set[str]] = {}
    for tc in root.findall("testcase"):
        keys = set()
        types = set()
        for f in tc.findall("file"):
            k = key_from_file_name(f.attrib.get("path", ""))
            if k:
                keys.add(k)
        for fl in tc.findall("flow"):
            t = fl.attrib.get("type")
            if t:
                types.add(t)
        for k in keys:
            res.setdefault(k, set()).update(types)
    return res


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--flow-xml", type=Path, default=Path("experiments/epic001c_testcase_flow_partition/outputs/manifest_with_testcase_flows.xml"))
    ap.add_argument("--all-match-jsonl", type=Path, default=Path("experiments/epic001d_trace_flow_filter/outputs/trace_flow_match_all.jsonl"))
    ap.add_argument("--output-dir", type=Path, default=Path("experiments/epic001d_trace_flow_filter/outputs"))
    args = ap.parse_args()

    flow_types_by_key = load_flow_types(args.flow_xml)
    traces_by_key = defaultdict(list)
    with args.all_match_jsonl.open("r", encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            traces_by_key[o.get("testcase_key")].append(o)

    rows = []
    c = Counter()
    for key, traces in sorted(traces_by_key.items()):
        ftypes = flow_types_by_key.get(key, set())
        nonb2b = sorted([t for t in ftypes if not t.startswith("b2b")])
        if not nonb2b:
            continue
        c["keys_with_nonb2b_flow"] += 1
        any_nonb2b_hit = False
        for t in traces:
            fm = t.get("flow_match", {})
            for ft in nonb2b:
                if fm.get(ft, {}).get("hit_points", 0) > 0:
                    any_nonb2b_hit = True
                    break
            if any_nonb2b_hit:
                break

        if any_nonb2b_hit:
            c["keys_nonb2b_hit"] += 1
        else:
            c["keys_nonb2b_not_hit"] += 1
            rows.append(
                {
                    "testcase_key": key,
                    "flow_types": sorted(ftypes),
                    "trace_count": len(traces),
                    "best_flow_types_seen": sorted(set(t.get("best_flow_type") for t in traces if t.get("best_flow_type"))),
                    "trace_files": [t.get("trace_file") for t in traces],
                }
            )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    out_json = args.output_dir / "nonb2b_flow_present_but_not_hit.json"
    out_summary = args.output_dir / "nonb2b_flow_present_but_not_hit_summary.json"
    out_json.write_text(json.dumps(rows, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    summary = {
        "counts": dict(c),
        "output": str(out_json),
    }
    out_summary.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
