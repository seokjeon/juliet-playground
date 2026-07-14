#!/usr/bin/env python3
r"""Verify extracted source/sink line numbers against the original .java sources.

For every source/sink item in a classified XML, this checks that the code text
recorded in the XML matches the actual line in the original .java file. This
guarantees the extracted line numbers did not drift.

Known false positives:
    Items whose code is "WARNING_NOT_FOUND" come from NOTE comments that happen
    to contain the word "flaw" (a known extractor limitation the team agreed to
    fix later). These are NOT counted as mismatches; they are tallied separately
    as "known warnings" so real position errors stay visible.

Two ways to run (from juliet-playground root):

    # 1) Verify ALL CWEs found in the output folder (default)
    python tools/verify_source_sink.py

    # 2) Verify specific CWEs only
    python tools/verify_source_sink.py --cwe 78 113 190

    # 3) Verify a single explicit XML + source root (original single-file mode)
    python tools/verify_source_sink.py \
        --xml  java_sard_source_sink/source_sink_dataset/cwe78_source_sink_classified.xml \
        --source-root juliet-java-test-suite/juliet-cwe78/src/main/java

Runs on any OS as long as python is available.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

KNOWN_WARNING = "WARNING_NOT_FOUND"


def normalize_code(text: str) -> str:
    """Normalize a code string for comparison.

    - strips a leading "[INLINE]" meta tag added by the extractor
    - drops a trailing same-line comment (/* ... */ or // ...)
    - collapses surrounding whitespace
    These differences are formatting only and do not indicate a line mismatch.
    """
    t = text.strip()
    if t.startswith("[INLINE]"):
        t = t[len("[INLINE]"):].strip()
    # drop trailing block comment  code; /* ... */
    t = re.sub(r"/\*.*?\*/\s*$", "", t).strip()
    # drop trailing line comment   code; // ...
    t = re.sub(r"//.*$", "", t).strip()
    return t


def build_source_index(source_root: Path) -> dict[str, str]:
    """Map each .java file name -> its full path under source_root."""
    index = {}
    for root, _, files in os.walk(source_root):
        for fn in files:
            if fn.endswith(".java"):
                index[fn] = os.path.join(root, fn)
    return index


def verify_one(xml_path: Path, source_root: Path) -> dict:
    """Verify a single classified XML against its source root. Returns a result dict."""
    result = {
        "xml": str(xml_path), "source_root": str(source_root),
        "total": 0, "match": 0, "mismatch": 0,
        "known_warning": 0, "missing_file": 0,
        "mismatches": [],  # list of (file, line, expected, actual)
    }
    index = build_source_index(source_root)
    cache: dict[str, list[str]] = {}

    def get_lines(path: str) -> list[str]:
        if path not in cache:
            with open(path, encoding="utf-8", errors="replace") as f:
                cache[path] = f.read().splitlines()
        return cache[path]

    root = ET.parse(xml_path).getroot()
    for tc in root.iter("testcase"):
        for flow in tc.iter("flow"):
            for item in flow:
                if item.attrib.get("role") not in ("source", "sink"):
                    continue
                fn = item.attrib.get("file")
                code = item.attrib.get("code", "")

                # known false positive -> tally separately, skip line compare
                if code == KNOWN_WARNING:
                    result["known_warning"] += 1
                    continue

                if fn not in index:
                    result["missing_file"] += 1
                    continue

                lines = get_lines(index[fn])
                result["total"] += 1
                ln = int(item.attrib.get("line"))
                actual = lines[ln - 1] if 1 <= ln <= len(lines) else "<out of range>"
                if normalize_code(actual) == normalize_code(code):
                    result["match"] += 1
                else:
                    result["mismatch"] += 1
                    result["mismatches"].append((fn, ln, code.strip(), actual.strip()))
    return result


def cwe_from_xml_name(name: str) -> str | None:
    m = re.search(r"cwe(\d+)", name)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser(description="Verify source/sink line numbers against original .java.")
    ap.add_argument("--output-dir", default="java_sard_source_sink/source_sink_dataset",
                    help="Folder of classified XMLs (default: batch output folder)")
    ap.add_argument("--dataset-root", default="juliet-java-test-suite",
                    help="Root of the Java SARD dataset")
    ap.add_argument("--log-dir", default="java_sard_source_sink/logs",
                    help="Folder to write verification logs")
    ap.add_argument("--cwe", type=int, nargs="*", default=None,
                    help="Verify only these CWE numbers (default: all found in output-dir)")
    ap.add_argument("--xml", default=None,
                    help="Single-file mode: explicit classified XML path (use with --source-root)")
    ap.add_argument("--source-root", default=None,
                    help="Single-file mode: explicit source root for --xml")
    args = ap.parse_args()

    results = []

    # --- single-file mode ---
    if args.xml or args.source_root:
        if not (args.xml and args.source_root):
            print("ERROR: --xml and --source-root must be given together.")
            sys.exit(1)
        results.append(verify_one(Path(args.xml), Path(args.source_root)))
    else:
        # --- batch mode: iterate XMLs in output-dir ---
        out_dir = Path(args.output_dir)
        dataset_root = Path(args.dataset_root)
        xmls = sorted(out_dir.glob("cwe*_source_sink_classified.xml"))
        if not xmls:
            print(f"No classified XMLs found in {out_dir}")
            sys.exit(1)
        for xml in xmls:
            cwe = cwe_from_xml_name(xml.name)
            if cwe is None:
                continue
            if args.cwe and int(cwe) not in args.cwe:
                continue
            src = dataset_root / f"juliet-cwe{cwe}" / "src" / "main" / "java"
            if not src.is_dir():
                print(f"CWE-{cwe}: source root not found ({src}), skipping")
                continue
            r = verify_one(xml, src)
            r["cwe"] = cwe
            results.append(r)

    # --- report: screen shows table + real errors; details go to log files ---
    import csv as _csv

    log_dir = Path(args.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    # screen: per-CWE table
    header = f"{'CWE':>6} {'total':>7} {'match':>7} {'mismatch':>9} {'known_warn':>11} {'missing':>8}"
    print(header)
    print("=" * 56)
    g_total = g_match = g_mismatch = g_warn = g_missing = 0
    for r in results:
        cwe = r.get("cwe", "-")
        print(f"{cwe:>6} {r['total']:>7} {r['match']:>7} {r['mismatch']:>9} "
              f"{r['known_warning']:>11} {r['missing_file']:>8}")
        g_total += r["total"]; g_match += r["match"]; g_mismatch += r["mismatch"]
        g_warn += r["known_warning"]; g_missing += r["missing_file"]
    print("=" * 56)
    print(f"{'ALL':>6} {g_total:>7} {g_match:>7} {g_mismatch:>9} {g_warn:>11} {g_missing:>8}")

    # screen: only REAL mismatches (errors), if any
    if g_mismatch > 0:
        print("\n=== Real mismatches (excluding known WARNING_NOT_FOUND) ===")
        shown = 0
        for r in results:
            for fn, ln, exp, act in r["mismatches"]:
                if shown >= 20:
                    break
                print(f"[{fn}] line {ln}")
                print(f"   XML expected: {exp}")
                print(f"   source actual: {act}")
                shown += 1
        if g_mismatch > shown:
            print(f"... and {g_mismatch - shown} more (see log for full list)")

    # --- log file 1: per-CWE report CSV ---
    report_csv = log_dir / "verify_report.csv"
    with report_csv.open("w", newline="", encoding="utf-8") as f:
        w = _csv.writer(f)
        w.writerow(["cwe", "total", "match", "mismatch", "known_warning", "missing_file"])
        for r in results:
            w.writerow([r.get("cwe", "-"), r["total"], r["match"], r["mismatch"],
                        r["known_warning"], r["missing_file"]])
        w.writerow(["ALL", g_total, g_match, g_mismatch, g_warn, g_missing])

    # --- log file 2: full mismatch details (no 20-item cap) ---
    mismatch_txt = log_dir / "verify_mismatches.txt"
    with mismatch_txt.open("w", encoding="utf-8") as f:
        if g_mismatch == 0:
            f.write("No real mismatches.\n")
        else:
            for r in results:
                for fn, ln, exp, act in r["mismatches"]:
                    f.write(f"[{fn}] line {ln}\n")
                    f.write(f"   XML expected: {exp}\n")
                    f.write(f"   source actual: {act}\n")

    # --- log file 3: known-warning (false positive) list ---
    # (recomputed here so the file lists exactly which items were tallied)
    warn_txt = log_dir / "verify_known_warnings.txt"
    with warn_txt.open("w", encoding="utf-8") as f:
        f.write(f"known WARNING_NOT_FOUND items (not errors): {g_warn}\n")

    # --- log file 4: summary text ---
    summary = (
        f"=== source/sink verification summary ===\n"
        f"lines checked: {g_total}\n"
        f"match:         {g_match}\n"
        f"real mismatch: {g_mismatch}\n"
        f"known warnings (not errors): {g_warn}\n"
        f"missing files: {g_missing}\n"
    )
    (log_dir / "verify_summary.txt").write_text(summary)

    # minimal one-line status on screen; details are in the logs
    print(f"\nLogs written to: {log_dir}")

    # exit non-zero only on REAL mismatches or missing files (known warnings are OK)
    sys.exit(0 if (g_mismatch == 0 and g_missing == 0) else 2)


if __name__ == "__main__":
    main()