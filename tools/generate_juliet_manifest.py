#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

from shared.juliet_keys import parse_juliet_case_identity

DEFAULT_SUFFIXES = {'.c', '.cpp', '.java'}


def _parse_cwes(raw_cwes: list[int]) -> set[str]:
    return {str(cwe) for cwe in raw_cwes}


def _group_sort_key(identity: tuple[str, str, str, str, str]) -> tuple[int, str, str, int, str]:
    parent, cwe_number, cwe_name, functional_variant_name, flow_variant_id = identity
    return (
        int(cwe_number),
        cwe_name,
        functional_variant_name,
        int(flow_variant_id),
        parent,
    )


def build_manifest(
    *,
    source_root: Path,
    output_xml: Path,
    suffixes: set[str],
    cwes: set[str] | None = None,
) -> dict[str, object]:
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    groups: dict[tuple[str, str, str, str, str], list[Path]] = defaultdict(list)
    scanned_files = 0
    matched_files = 0

    for path in sorted(source_root.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        scanned_files += 1
        identity = parse_juliet_case_identity(path, allowed_suffixes=suffixes)
        if identity is None:
            continue
        if cwes is not None and identity[1] not in cwes:
            continue
        matched_files += 1
        groups[identity].append(path)

    root = ET.Element('container')
    for identity in sorted(groups, key=_group_sort_key):
        testcase = ET.SubElement(root, 'testcase')
        for path in sorted(groups[identity]):
            ET.SubElement(testcase, 'file', {'path': path.name})

    output_xml.parent.mkdir(parents=True, exist_ok=True)
    tree = ET.ElementTree(root)
    try:
        ET.indent(tree, space='  ')
    except AttributeError:
        pass
    tree.write(output_xml, encoding='utf-8', xml_declaration=True)

    return {
        'source_root': str(source_root),
        'output_xml': str(output_xml),
        'scanned_files': scanned_files,
        'matched_files': matched_files,
        'testcases': len(groups),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description='Generate a compact Juliet-style manifest XML.')
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output-xml', type=Path, required=True)
    parser.add_argument('--cwe', action='append', type=int, default=[])
    parser.add_argument(
        '--suffix',
        action='append',
        default=[],
        help='Source suffix to include, for example .java. Defaults to .c, .cpp, .java.',
    )
    args = parser.parse_args()

    suffixes = {suffix.lower() for suffix in args.suffix} if args.suffix else DEFAULT_SUFFIXES
    payload = build_manifest(
        source_root=args.source_root,
        output_xml=args.output_xml,
        suffixes=suffixes,
        cwes=_parse_cwes(args.cwe) if args.cwe else None,
    )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
