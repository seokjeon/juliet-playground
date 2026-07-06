from __future__ import annotations

SOURCE_EXTS = {'.c', '.cpp', '.h', '.java'}
PARSER_LANG_BY_SUFFIX = {'.c': 'c', '.cpp': 'cpp', '.java': 'java'}
IDENTIFIER_NODE_TYPES = {'identifier', 'field_identifier', 'qualified_identifier'}


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode('utf-8', errors='ignore')


def node_first_line_text(node, source_bytes: bytes) -> str:
    text = _node_text(node, source_bytes)
    return (text.splitlines()[0] if text else '').strip()


def extract_function_name_from_declarator(node, source_bytes: bytes) -> str | None:
    if node is None:
        return None

    current = node
    for _ in range(12):
        next_node = current.child_by_field_name('declarator')
        if next_node is None:
            break
        current = next_node

    if current.type in IDENTIFIER_NODE_TYPES:
        return _node_text(current, source_bytes).strip()

    name_node = current.child_by_field_name('name')
    if name_node is not None and name_node.type in IDENTIFIER_NODE_TYPES:
        return _node_text(name_node, source_bytes).strip()

    stack = [current]
    while stack:
        candidate = stack.pop()
        if candidate.type in IDENTIFIER_NODE_TYPES:
            return _node_text(candidate, source_bytes).strip()
        stack.extend(reversed(candidate.children))
    return None
