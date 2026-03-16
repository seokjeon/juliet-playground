#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path


def new_stats() -> dict:
    return {
        'total_files': 0,
        'scanned_files': 0,
        'missing_files': 0,
        'parse_failed_files': 0,
        'dropped_comment_lines': 0,
    }


def inc(stats: dict, key: str, n: int = 1) -> None:
    stats[key] += n


def print_summary(output_xml: str, stats: dict) -> None:
    payload = {'output_xml': output_xml, **stats}
    print(json.dumps(payload, ensure_ascii=False))


SOURCE_EXTS = {'.c', '.cpp', '.h'}
FLAW_RE = re.compile(
    r'^\s*/\*+\s*(?!.*\bINCIDENTAL\s+FLAW\b).*\b(?:POTENTIAL\s+)?FLAW\b',
    re.IGNORECASE,
)
FIX_RE = re.compile(r'^\s*/\*+\s*FIX\b', re.IGNORECASE)
FILE_LANG = {'.c': 'c', '.cpp': 'cpp'}


def load_parsers() -> dict[str, object]:
    try:
        from tree_sitter import Parser
        from tree_sitter_languages import get_language
    except Exception:
        return {}

    parsers: dict[str, object] = {}
    for language_name in ('c', 'cpp'):
        parser = Parser()
        lang = get_language(language_name)
        if hasattr(parser, 'set_language'):
            parser.set_language(lang)
        else:
            parser.language = lang
        parsers[language_name] = parser
    return parsers


def _extract_function_name_from_declarator(decl_node, source_bytes: bytes) -> str | None:
    stack = [decl_node]
    while stack:
        node = stack.pop()
        if node.type in {'identifier', 'field_identifier', 'qualified_identifier'}:
            return (
                source_bytes[node.start_byte : node.end_byte]
                .decode('utf-8', errors='ignore')
                .strip()
            )
        stack.extend(reversed(node.children))
    return None


def _match_comments_to_functions(
    spans: list[tuple[int, int, str]],
    comments: list[tuple[int, str, str]],
) -> list[tuple[int, str, str, str | None]]:
    spans = sorted(spans, key=lambda x: (x[0], x[1]))
    comments = sorted(comments, key=lambda x: x[0])
    matched: list[tuple[int, str, str, str | None]] = []
    j = 0
    for line_no, tag, code_text in comments:
        while j < len(spans) and spans[j][1] < line_no:
            j += 1
        function_name: str | None = None
        if j < len(spans):
            start, end, name = spans[j]
            if start <= line_no <= end:
                function_name = name
        matched.append((line_no, tag, code_text, function_name))
    return matched


def _node_first_line_text(node, source_bytes: bytes) -> str:
    text = source_bytes[node.start_byte : node.end_byte].decode('utf-8', errors='ignore')
    return (text.splitlines()[0] if text else '').strip()


def _classify_comment_tag(comment_text: str) -> str | None:
    first_line = comment_text.splitlines()[0] if comment_text else ''
    if FLAW_RE.search(first_line):
        return 'comment_flaw'
    if FIX_RE.search(first_line):
        return 'comment_fix'
    return None


def _parse_file(
    content: str, suffix: str, parsers: dict[str, object]
) -> tuple[list[tuple[int, int, str]], list[tuple[int, str, str]], bool]:
    source_bytes = content.encode('utf-8', errors='ignore')
    language_name = FILE_LANG.get(suffix)
    parser = parsers.get(language_name) if language_name else None
    if not parser:
        return [], [], True
    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return [], [], True
    function_spans: list[tuple[int, int, str]] = []
    comments: list[tuple[int, str, str]] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        if node.type == 'function_definition':
            decl = node.child_by_field_name('declarator')
            if decl is not None:
                name = _extract_function_name_from_declarator(decl, source_bytes)
                if name:
                    function_spans.append((node.start_point[0] + 1, node.end_point[0] + 1, name))
        elif node.type == 'comment':
            comment_text = source_bytes[node.start_byte : node.end_byte].decode(
                'utf-8', errors='ignore'
            )
            tag = _classify_comment_tag(comment_text)
            if tag:
                comment_line = node.start_point[0] + 1
                prev_named = node.prev_named_sibling
                next_named = node.next_named_sibling
                is_inline = bool(prev_named and prev_named.end_point[0] == node.start_point[0])

                if is_inline:
                    comments.append(
                        (
                            prev_named.start_point[0] + 1,
                            tag,
                            f'[INLINE] {_node_first_line_text(prev_named, source_bytes)}',
                        )
                    )
                else:
                    target = next_named
                    while target is not None and target.type == 'comment':
                        target = target.next_named_sibling
                    if target is not None:
                        comments.append(
                            (
                                target.start_point[0] + 1,
                                tag,
                                _node_first_line_text(target, source_bytes),
                            )
                        )
                    else:
                        comments.append((comment_line, tag, 'WARNING_NOT_FOUND'))
        stack.extend(reversed(node.children))
    return function_spans, comments, False


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Scan manifest files and append comment_flaw/comment_fix tags.'
    )
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output-xml', type=Path, required=True)
    args = parser.parse_args()

    if not args.manifest.exists():
        raise FileNotFoundError(f'Manifest not found: {args.manifest}')
    if not args.source_root.exists():
        raise FileNotFoundError(f'Source root not found: {args.source_root}')

    source_index: dict[str, Path] = {}
    for p in args.source_root.rglob('*'):
        if p.is_file() and p.suffix.lower() in SOURCE_EXTS and p.name not in source_index:
            source_index[p.name] = p

    parsers = load_parsers()
    tree = ET.parse(args.manifest)
    root = tree.getroot()
    stats = new_stats()

    for file_elem in root.iter('file'):
        inc(stats, 'total_files')
        src = source_index.get(file_elem.attrib.get('path', ''))
        if src is None:
            inc(stats, 'missing_files')
            continue
        if src.suffix.lower() not in FILE_LANG:
            continue

        inc(stats, 'scanned_files')
        content = src.read_text(encoding='utf-8', errors='ignore')
        function_spans, comments, parse_failed = _parse_file(content, src.suffix.lower(), parsers)
        if parse_failed:
            inc(stats, 'parse_failed_files')
            continue

        for line_no, tag, code_text, function_name in _match_comments_to_functions(
            function_spans, comments
        ):
            if not function_name:
                inc(stats, 'dropped_comment_lines')
                continue

            ET.SubElement(
                file_elem,
                tag,
                {'line': str(line_no), 'code': code_text, 'function': function_name},
            )

    args.output_xml.parent.mkdir(parents=True, exist_ok=True)
    try:
        ET.indent(tree, space='  ')
    except AttributeError:
        pass
    tree.write(args.output_xml, encoding='utf-8', xml_declaration=True)

    print_summary(str(args.output_xml), stats)
    return 0


if __name__ == '__main__':
    main()
