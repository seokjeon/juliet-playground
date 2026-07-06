from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from shared.dataset_sources import load_tree_sitter_parsers
from shared.juliet_manifest import build_manifest_source_index
from shared.source_parsing import (
    PARSER_LANG_BY_SUFFIX,
    SOURCE_EXTS,
    extract_function_name_from_declarator,
    node_first_line_text,
)


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


FLAW_RE = re.compile(
    r'^\s*(?:/\*+|//)\s*(?!.*\bINCIDENTAL\s+FLAW\b).*\b(?:POTENTIAL\s+)?FLAW\b',
    re.IGNORECASE,
)
FIX_RE = re.compile(r'^\s*(?:/\*+|//)\s*FIX\b', re.IGNORECASE)
JAVA_METHOD_NODE_TYPES = {'method_declaration', 'constructor_declaration'}
JAVA_TYPE_NODE_TYPES = {
    'annotation_type_declaration',
    'class_declaration',
    'enum_declaration',
    'interface_declaration',
    'record_declaration',
}
COMMENT_NODE_TYPES = {'comment', 'block_comment', 'line_comment'}


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode('utf-8', errors='ignore').strip()


def _named_child_text(node, source_bytes: bytes) -> str | None:
    name_node = node.child_by_field_name('name')
    if name_node is None:
        return None
    return _node_text(name_node, source_bytes) or None


def _java_method_name(node, source_bytes: bytes) -> str | None:
    method_name = _named_child_text(node, source_bytes)
    if not method_name:
        return None

    scope_names: list[str] = []
    parent = getattr(node, 'parent', None)
    while parent is not None:
        if parent.type in JAVA_TYPE_NODE_TYPES:
            type_name = _named_child_text(parent, source_bytes)
            if type_name:
                scope_names.append(type_name)
        parent = getattr(parent, 'parent', None)

    if not scope_names:
        return method_name
    return f'{"::".join(reversed(scope_names))}::{method_name}'


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
    language_name = PARSER_LANG_BY_SUFFIX.get(suffix)
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
                name = extract_function_name_from_declarator(decl, source_bytes)
                if name:
                    function_spans.append((node.start_point[0] + 1, node.end_point[0] + 1, name))
        elif node.type in JAVA_METHOD_NODE_TYPES:
            name = _java_method_name(node, source_bytes)
            if name:
                function_spans.append((node.start_point[0] + 1, node.end_point[0] + 1, name))
        elif node.type in COMMENT_NODE_TYPES:
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
                            f'[INLINE] {node_first_line_text(prev_named, source_bytes)}',
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
                                node_first_line_text(target, source_bytes),
                            )
                        )
                    else:
                        comments.append((comment_line, tag, 'WARNING_NOT_FOUND'))
        stack.extend(reversed(node.children))
    return function_spans, comments, False


def scan_manifest_comments(
    *, manifest: Path, source_root: Path, output_xml: Path
) -> dict[str, object]:
    if not manifest.exists():
        raise FileNotFoundError(f'Manifest not found: {manifest}')
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    source_index = build_manifest_source_index(
        manifest_xml=manifest,
        source_root=source_root,
        suffixes=SOURCE_EXTS,
    )

    parsers = load_tree_sitter_parsers()
    tree = ET.parse(manifest)
    root = tree.getroot()
    stats = new_stats()

    for file_elem in root.iter('file'):
        inc(stats, 'total_files')
        src = source_index.get(file_elem.attrib.get('path', ''))
        if src is None:
            inc(stats, 'missing_files')
            continue
        if src.suffix.lower() not in PARSER_LANG_BY_SUFFIX:
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

    output_xml.parent.mkdir(parents=True, exist_ok=True)
    try:
        ET.indent(tree, space='  ')
    except AttributeError:
        pass
    tree.write(output_xml, encoding='utf-8', xml_declaration=True)

    return {'output_xml': str(output_xml), **stats}
