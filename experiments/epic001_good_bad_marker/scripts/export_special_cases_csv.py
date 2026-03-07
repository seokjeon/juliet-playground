#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path
import xml.etree.ElementTree as ET


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export special-case rows from good_bad_lines.xml")
    p.add_argument(
        "--xml",
        default="experiments/epic001_good_bad_marker/outputs/good_bad_lines.xml",
        help="Input XML path",
    )
    p.add_argument(
        "--out",
        default="experiments/epic001_good_bad_marker/outputs/special_cases.csv",
        help="Output CSV path",
    )
    return p.parse_args()


def collect_invalid_rows(xml_path: Path) -> list[dict[str, str]]:
    tree = ET.parse(xml_path)
    root = tree.getroot()

    rows: list[dict[str, str]] = []
    for tc in root.findall("testcase"):
        for file_el in tc.findall("file"):
            file_path = file_el.get("path", "")

            for node in list(file_el):
                if node.tag not in {"flaw", "fix"}:
                    continue

                is_valid = node.get("is_valid_syntax", "")
                if is_valid == "true":
                    continue

                rows.append(
                    {
                        "case_type": "invalid_syntax",
                        "file": file_path,
                        "kind": "bad" if node.tag == "flaw" else "good",
                        "line": node.get("line", ""),
                        "line_text": node.get("line_text", ""),
                        "evidence": node.get("evidence", ""),
                        "validation_reason": node.get("validation_reason", ""),
                        "is_valid_syntax": is_valid,
                    }
                )

    def line_key(v: str) -> int:
        try:
            return int(v)
        except Exception:
            return 10**9

    rows.sort(
        key=lambda r: (
            r["validation_reason"],
            r["file"],
            line_key(r["line"]),
            r["kind"],
        )
    )
    return rows


def write_csv(rows: list[dict[str, str]], out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "case_type",
        "file",
        "kind",
        "line",
        "line_text",
        "evidence",
        "validation_reason",
        "is_valid_syntax",
    ]
    with out_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main() -> None:
    args = parse_args()
    xml_path = Path(args.xml)
    out_path = Path(args.out)

    if not xml_path.exists():
        raise SystemExit(f"Input XML not found: {xml_path}")

    rows = collect_invalid_rows(xml_path)
    write_csv(rows, out_path)
    print(f"[special-cases] rows={len(rows)} out={out_path}")


if __name__ == "__main__":
    main()
