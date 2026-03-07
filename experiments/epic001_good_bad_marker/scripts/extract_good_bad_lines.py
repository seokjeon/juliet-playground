#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
import xml.etree.ElementTree as ET

CWE_NAME = "CWE-476: NULL Pointer Dereference"
COMMENT_RE = re.compile(r"//.*|/\*[\s\S]*?\*/", re.MULTILINE)


@dataclass
class MarkerHit:
    kind: str  # flaw|fix
    marker_line: int
    evidence: str


@dataclass
class ExtractedEntry:
    tag: str  # flaw|fix
    line: int
    line_text: str
    evidence: str
    is_valid_syntax: bool
    validation_reason: str


def decide_kind(comment_text: str) -> str | None:
    upper = comment_text.upper()
    flaw = re.search(r"\b(?:POTENTIAL\s+)?FLAW\s*:", upper)
    fix = re.search(r"\bFIX\s*:", upper)
    if not flaw and not fix:
        return None
    if flaw and not fix:
        return "flaw"
    if fix and not flaw:
        return "fix"
    assert flaw is not None and fix is not None
    return "flaw" if flaw.start() <= fix.start() else "fix"


def collect_markers(source: str) -> list[MarkerHit]:
    hits: list[MarkerHit] = []
    for m in COMMENT_RE.finditer(source):
        text = m.group(0)
        kind = decide_kind(text)
        if not kind:
            continue
        marker_line = source.count("\n", 0, m.end()) + 1
        evidence = " ".join(text.split())
        hits.append(MarkerHit(kind=kind, marker_line=marker_line, evidence=evidence))
    return hits


def next_candidate_line(lines: list[str], start_idx0: int) -> int | None:
    i = start_idx0
    n = len(lines)
    residual = ""

    while i < n:
        text = residual if residual else lines[i]
        residual = ""

        while True:
            stripped = text.lstrip()
            if stripped == "":
                i += 1
                break

            if stripped.startswith("//"):
                i += 1
                break

            if stripped.startswith("/*"):
                end = stripped.find("*/")
                if end != -1:
                    text = stripped[end + 2 :]
                    continue

                i += 1
                closed = False
                while i < n:
                    pos = lines[i].find("*/")
                    if pos == -1:
                        i += 1
                        continue
                    residual = lines[i][pos + 2 :]
                    closed = True
                    break
                if not closed:
                    return None
                break

            return i

    return None


def validate_line_syntax(line_text: str) -> tuple[bool, str]:
    s = line_text.strip()

    if not s:
        return False, "empty"
    if s in {"{", "}"}:
        return False, "brace_only"
    if s.startswith("#"):
        return False, "preprocessor"

    if re.match(r"^(if|for|while|switch|else|do)\b", s):
        return True, "control_statement"
    if re.match(r"^(return|break|continue|goto|case|default)\b", s):
        return True, "jump_or_case_statement"
    if s.endswith(";"):
        return True, "semicolon_statement"

    if re.match(
        r"^(static|const|volatile|extern|register|unsigned|signed|long|short|int|char|float|double|void|size_t|wchar_t|struct\b|enum\b|union\b)",
        s,
    ):
        return True, "declaration_like"

    return False, "unrecognized_pattern"


def extract_for_file(c_file: Path) -> list[ExtractedEntry]:
    source = c_file.read_text(encoding="utf-8", errors="ignore")
    lines = source.splitlines()

    entries: list[ExtractedEntry] = []
    for hit in collect_markers(source):
        candidate_idx0 = next_candidate_line(lines, hit.marker_line)
        if candidate_idx0 is None:
            continue

        line_text = lines[candidate_idx0].strip()
        ok, reason = validate_line_syntax(line_text)

        entries.append(
            ExtractedEntry(
                tag=hit.kind,
                line=candidate_idx0 + 1,
                line_text=line_text,
                evidence=hit.evidence,
                is_valid_syntax=ok,
                validation_reason=reason,
            )
        )

    entries.sort(key=lambda e: (e.line, e.tag))
    return entries


def load_testcase_groups(input_dir: Path, manifest_path: Path) -> list[list[str]]:
    if not manifest_path.exists():
        raise SystemExit(f"Manifest not found: {manifest_path}")

    cwe_prefix = input_dir.name
    root = ET.parse(manifest_path).getroot()
    groups: list[list[str]] = []

    for tc in root.findall("testcase"):
        paths = []
        for file_el in tc.findall("file"):
            p = file_el.get("path", "")
            if not p.startswith(cwe_prefix):
                continue
            if not p.endswith(".c"):
                continue
            if not (input_dir / p).exists():
                continue
            paths.append(p)
        if paths:
            groups.append(paths)

    if not groups:
        raise SystemExit(f"No testcase groups found in manifest for prefix: {cwe_prefix}")

    return groups


def build_xml(input_dir: Path, manifest_path: Path, output_xml: Path) -> tuple[int, int, int, int]:
    groups = load_testcase_groups(input_dir, manifest_path)

    root = ET.Element("container")
    testcase_count = 0
    file_count = 0
    flaw_count = 0
    fix_count = 0

    for group in groups:
        testcase_el = ET.SubElement(root, "testcase")
        testcase_count += 1

        for rel_path in group:
            c_file = input_dir / rel_path
            entries = extract_for_file(c_file)
            file_el = ET.SubElement(testcase_el, "file", {"path": rel_path})
            file_count += 1

            for e in entries:
                attrs = {
                    "line": str(e.line),
                    "name": CWE_NAME,
                    "line_text": e.line_text,
                    "evidence": e.evidence,
                    "is_valid_syntax": "true" if e.is_valid_syntax else "false",
                    "validation_reason": e.validation_reason,
                }
                ET.SubElement(file_el, e.tag, attrs)
                if e.tag == "flaw":
                    flaw_count += 1
                else:
                    fix_count += 1

    output_xml.parent.mkdir(parents=True, exist_ok=True)
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    tree.write(output_xml, encoding="utf-8", xml_declaration=True)

    return testcase_count, file_count, flaw_count, fix_count


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract good/bad marker lines from CWE-476 C testcases into manifest-like XML."
    )
    parser.add_argument(
        "--input",
        default="juliet-test-suite-v1.3/C/testcases/CWE476_NULL_Pointer_Dereference",
        help="Input directory containing CWE-476 .c files.",
    )
    parser.add_argument(
        "--manifest",
        default="juliet-test-suite-v1.3/C/manifest.xml",
        help="Juliet manifest.xml path used to preserve testcase grouping.",
    )
    parser.add_argument(
        "--output",
        default="experiments/epic001_good_bad_marker/outputs/good_bad_lines.xml",
        help="Output XML path.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_dir = Path(args.input)
    manifest_path = Path(args.manifest)
    output_xml = Path(args.output)

    if not input_dir.exists():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    tcs, files, flaws, fixes = build_xml(input_dir, manifest_path, output_xml)
    print(f"[extract] testcase={tcs} files={files} flaw={flaws} fix={fixes} output={output_xml}")


if __name__ == "__main__":
    main()
