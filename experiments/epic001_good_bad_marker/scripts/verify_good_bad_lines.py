#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
from collections import Counter
import xml.etree.ElementTree as ET

REQUIRED_ATTRS = {
    "line",
    "name",
    "line_text",
    "evidence",
    "is_valid_syntax",
    "validation_reason",
}


def load_manifest_groups(input_dir: Path, manifest_path: Path) -> list[tuple[str, ...]]:
    cwe_prefix = input_dir.name
    root = ET.parse(manifest_path).getroot()
    groups: list[tuple[str, ...]] = []
    for tc in root.findall("testcase"):
        paths = []
        for f in tc.findall("file"):
            p = f.get("path", "")
            if not p.startswith(cwe_prefix):
                continue
            if not p.endswith(".c"):
                continue
            if not (input_dir / p).exists():
                continue
            paths.append(p)
        if paths:
            groups.append(tuple(paths))
    return groups


def verify(xml_path: Path, input_dir: Path, manifest_path: Path) -> tuple[bool, list[str], dict[str, int]]:
    errors: list[str] = []
    stats = {"testcase": 0, "file": 0, "flaw": 0, "fix": 0}

    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        return False, [f"XML parse error: {e}"], stats

    root = tree.getroot()
    if root.tag != "container":
        errors.append(f"Root tag must be 'container', got '{root.tag}'")

    output_groups: list[tuple[str, ...]] = []

    for tc in root.findall("testcase"):
        stats["testcase"] += 1
        files = tc.findall("file")
        if not files:
            errors.append("A testcase element has no file child")
            continue

        group_paths: list[str] = []
        for f in files:
            stats["file"] += 1
            path = f.get("path")
            if not path:
                errors.append("file element missing 'path' attribute")
                continue

            group_paths.append(path)
            src = input_dir / path
            if not src.exists():
                errors.append(f"file path does not exist: {path}")
                continue

            try:
                line_count = len(src.read_text(encoding="utf-8", errors="ignore").splitlines())
            except Exception as e:
                errors.append(f"failed to read source file '{path}': {e}")
                continue

            for node in list(f):
                if node.tag not in {"flaw", "fix"}:
                    errors.append(f"unknown child tag under file[{path}]: {node.tag}")
                    continue

                stats[node.tag] += 1

                missing = [k for k in REQUIRED_ATTRS if node.get(k) is None]
                if missing:
                    errors.append(f"{node.tag}[{path}] missing attrs: {', '.join(missing)}")
                    continue

                line_raw = node.get("line", "")
                try:
                    line_no = int(line_raw)
                except ValueError:
                    errors.append(f"{node.tag}[{path}] line is not int: {line_raw}")
                    continue

                if line_no < 1 or line_no > line_count:
                    errors.append(f"{node.tag}[{path}] line out of range: {line_no}/{line_count}")

                syntax = node.get("is_valid_syntax", "")
                if syntax not in {"true", "false"}:
                    errors.append(f"{node.tag}[{path}] is_valid_syntax must be true/false: {syntax}")

        output_groups.append(tuple(group_paths))

    if not manifest_path.exists():
        errors.append(f"manifest not found: {manifest_path}")
    else:
        expected_groups = load_manifest_groups(input_dir, manifest_path)

        norm_out = Counter(tuple(sorted(g)) for g in output_groups)
        norm_expected = Counter(tuple(sorted(g)) for g in expected_groups)
        if norm_out != norm_expected:
            errors.append("testcase grouping mismatch against manifest.xml")

    ok = len(errors) == 0
    return ok, errors, stats


def write_report(report_path: Path, ok: bool, errors: list[str], stats: dict[str, int]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    lines.append("# Verify Report\n")
    lines.append(f"- status: {'PASS' if ok else 'FAIL'}")
    lines.append(f"- testcase: {stats['testcase']}")
    lines.append(f"- file: {stats['file']}")
    lines.append(f"- flaw: {stats['flaw']}")
    lines.append(f"- fix: {stats['fix']}\n")
    if errors:
        lines.append("## Errors")
        for e in errors:
            lines.append(f"- {e}")
    else:
        lines.append("## Errors")
        lines.append("- none")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Verify manifest-like good/bad XML output")
    p.add_argument(
        "--xml",
        default="experiments/epic001_good_bad_marker/outputs/good_bad_lines.xml",
        help="Path to XML output to validate",
    )
    p.add_argument(
        "--input",
        default="juliet-test-suite-v1.3/C/testcases/CWE476_NULL_Pointer_Dereference",
        help="Input directory used for source line-range validation",
    )
    p.add_argument(
        "--manifest",
        default="juliet-test-suite-v1.3/C/manifest.xml",
        help="Juliet manifest.xml path used for testcase grouping validation",
    )
    p.add_argument(
        "--report",
        default="experiments/epic001_good_bad_marker/outputs/verify_report.md",
        help="Markdown verification report path",
    )
    return p.parse_args()


def main() -> None:
    args = parse_args()
    ok, errors, stats = verify(Path(args.xml), Path(args.input), Path(args.manifest))
    write_report(Path(args.report), ok, errors, stats)

    print(
        f"[verify] status={'PASS' if ok else 'FAIL'} testcase={stats['testcase']} file={stats['file']} flaw={stats['flaw']} fix={stats['fix']}"
    )
    if errors:
        for e in errors[:20]:
            print(f"  - {e}")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
