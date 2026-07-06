from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shared.juliet_keys import JULIET_GROUP_INVENTORY_SUFFIXES, list_juliet_case_group_files
from shared.paths import PROJECT_HOME
from shared.source_parsing import extract_function_name_from_declarator
from shared.traces import extract_std_bug_trace

CPP_LIKE_SUFFIXES = {'.cpp', '.cc', '.cxx', '.c++', '.hpp', '.hh', '.hxx'}
PROJECT_HOME_PATH = Path(PROJECT_HOME).resolve()
IDENTIFIER_NODE_TYPES = {'identifier', 'field_identifier', 'qualified_identifier'}
DECLARED_IDENTIFIER_NODE_TYPES = {'identifier', 'field_identifier'}
TYPE_NAME_NODE_TYPES = {'identifier', 'qualified_identifier', 'type_identifier'}
TYPE_SPECIFIER_NODE_TYPES = {
    'primitive_type',
    'sized_type_specifier',
    'type_identifier',
    'qualified_identifier',
    'template_type',
    'struct_specifier',
    'union_specifier',
    'enum_specifier',
    'class_specifier',
}
FUNCTION_LIKE_DECLARATOR_TYPES = {'function_declarator', 'abstract_function_declarator'}


@dataclass
class IdentifierInventory:
    function_names: set[str] = field(default_factory=set)
    type_names: set[str] = field(default_factory=set)
    variable_names: set[str] = field(default_factory=set)

    def update(self, other: 'IdentifierInventory') -> None:
        self.function_names.update(other.function_names)
        self.type_names.update(other.type_names)
        self.variable_names.update(other.variable_names)

    def merged(self, other: 'IdentifierInventory') -> 'IdentifierInventory':
        merged = IdentifierInventory(
            function_names=set(self.function_names),
            type_names=set(self.type_names),
            variable_names=set(self.variable_names),
        )
        merged.update(other)
        return merged

    def is_empty(self) -> bool:
        return not (self.function_names or self.type_names or self.variable_names)


def normalize_artifact_path(path: Path | str) -> str:
    raw = str(path or '').strip()
    if not raw:
        return ''
    candidate = Path(raw)
    if not candidate.is_absolute():
        return str(candidate)
    resolved = candidate.resolve()
    try:
        return str(resolved.relative_to(PROJECT_HOME_PATH))
    except ValueError:
        return str(resolved)


def load_tree_sitter_parsers() -> dict[str, object]:
    try:
        from tree_sitter import Parser
        from tree_sitter_languages import get_language
    except Exception:
        return {}

    parsers: dict[str, object] = {}
    for language_name in ('c', 'cpp', 'java'):
        parser = Parser()
        try:
            lang = get_language(language_name)
        except Exception:
            continue
        if hasattr(parser, 'set_language'):
            parser.set_language(lang)
        else:
            parser.language = lang
        parsers[language_name] = parser
    return parsers


def candidate_languages_for_source(path: Path) -> list[str]:
    suffix = path.suffix.lower()
    if suffix in CPP_LIKE_SUFFIXES:
        return ['cpp', 'c']
    return ['c', 'cpp']


def node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte : node.end_byte].decode('utf-8', errors='ignore')


def function_tail_alias_for_function_name(name: str) -> str | None:
    if not name or '::' not in name:
        return None

    class_name, method_name = name.rsplit('::', 1)
    class_short_name = class_name.rsplit('::', 1)[-1]
    if method_name in {class_short_name, f'~{class_short_name}'}:
        return None
    return method_name or None


def constructor_alias_for_function_name(name: str) -> str | None:
    if not name or '::' not in name:
        return None

    class_name, method_name = name.rsplit('::', 1)
    class_short_name = class_name.rsplit('::', 1)[-1]
    if not class_short_name:
        return None
    if method_name == class_short_name or method_name == f'~{class_short_name}':
        return class_short_name
    return None


def _extract_named_text(
    node,
    source_bytes: bytes,
    *,
    allowed_types: set[str],
) -> str | None:
    if node is None:
        return None
    if node.type in allowed_types:
        return node_text(node, source_bytes).strip() or None
    name_node = node.child_by_field_name('name')
    if name_node is not None and name_node.type in allowed_types:
        return node_text(name_node, source_bytes).strip() or None
    return None


def _extract_type_alias_name(node, source_bytes: bytes) -> str | None:
    declarator = node.child_by_field_name('declarator')
    if declarator is not None and declarator.type in TYPE_NAME_NODE_TYPES:
        return node_text(declarator, source_bytes).strip() or None
    return _extract_named_text(node, source_bytes, allowed_types=TYPE_NAME_NODE_TYPES)


def _contains_function_like_declarator(node) -> bool:
    stack = [node]
    while stack:
        candidate = stack.pop()
        if candidate.type in FUNCTION_LIKE_DECLARATOR_TYPES:
            return True
        stack.extend(reversed(candidate.children))
    return False


def _extract_declared_identifier_names(node, source_bytes: bytes) -> set[str]:
    names: set[str] = set()
    stack = [node]
    while stack:
        candidate = stack.pop()
        if candidate.type in DECLARED_IDENTIFIER_NODE_TYPES:
            text = node_text(candidate, source_bytes).strip()
            if text:
                names.add(text)
            continue

        declarator = candidate.child_by_field_name('declarator')
        if declarator is not None:
            stack.append(declarator)
            continue

        name_node = candidate.child_by_field_name('name')
        if name_node is not None and name_node.type in DECLARED_IDENTIFIER_NODE_TYPES:
            text = node_text(name_node, source_bytes).strip()
            if text:
                names.add(text)
            continue

        stack.extend(
            reversed(
                [
                    child
                    for child in candidate.children
                    if child.type in DECLARED_IDENTIFIER_NODE_TYPES
                    or child.child_by_field_name('declarator') is not None
                ]
            )
        )
    return names


def _extract_declared_names_from_statement(node, source_bytes: bytes) -> set[str]:
    declarator_nodes = []
    primary_declarator = node.child_by_field_name('declarator')
    if primary_declarator is not None:
        declarator_nodes.append(primary_declarator)

    declarator_nodes.extend(
        child
        for child in node.children
        if child.type in DECLARED_IDENTIFIER_NODE_TYPES
        or child.type in {'init_declarator', 'pointer_declarator', 'array_declarator'}
        or child.child_by_field_name('declarator') is not None
    )

    names: set[str] = set()
    seen: set[tuple[int, int, str]] = set()
    for declarator in declarator_nodes:
        key = (declarator.start_byte, declarator.end_byte, declarator.type)
        if key in seen or _contains_function_like_declarator(declarator):
            continue
        seen.add(key)
        names.update(_extract_declared_identifier_names(declarator, source_bytes))
    return names


def extract_identifier_inventory(root_node, source_bytes: bytes) -> IdentifierInventory:
    inventory = IdentifierInventory()
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.type == 'function_definition':
            declarator = node.child_by_field_name('declarator')
            name = extract_function_name_from_declarator(declarator, source_bytes)
            if name:
                inventory.function_names.add(name)
                function_alias = function_tail_alias_for_function_name(name)
                if function_alias:
                    inventory.function_names.add(function_alias)
                constructor_alias = constructor_alias_for_function_name(name)
                if constructor_alias:
                    inventory.type_names.add(constructor_alias)
        elif node.type in {
            'class_specifier',
            'struct_specifier',
            'union_specifier',
            'enum_specifier',
        }:
            type_name = _extract_named_text(node, source_bytes, allowed_types=TYPE_NAME_NODE_TYPES)
            if type_name:
                inventory.type_names.add(type_name)
        elif node.type in {'type_definition', 'alias_declaration'}:
            alias_name = _extract_type_alias_name(node, source_bytes)
            if alias_name:
                inventory.type_names.add(alias_name)
        elif node.type in {'parameter_declaration', 'field_declaration', 'declaration'}:
            inventory.variable_names.update(
                _extract_declared_names_from_statement(node, source_bytes)
            )
        elif node.type == 'enumerator':
            enumerator_name = _extract_named_text(
                node,
                source_bytes,
                allowed_types=DECLARED_IDENTIFIER_NODE_TYPES | TYPE_NAME_NODE_TYPES,
            )
            if enumerator_name:
                inventory.variable_names.add(enumerator_name)
        stack.extend(reversed(node.children))
    return inventory


def extract_defined_function_names(root_node, source_bytes: bytes) -> set[str]:
    inventory = extract_identifier_inventory(root_node, source_bytes)
    return set(inventory.function_names) | set(inventory.type_names)


def collect_identifier_inventory(
    source_path: Path,
    parsers: dict[str, object],
) -> tuple[IdentifierInventory, str | None]:
    try:
        source_bytes = source_path.read_bytes()
    except Exception as exc:
        return IdentifierInventory(), f'read_error:{exc}'

    last_error: str | None = None
    for language_name in candidate_languages_for_source(source_path):
        parser = parsers.get(language_name)
        if parser is None:
            continue
        try:
            tree = parser.parse(source_bytes)
            return extract_identifier_inventory(tree.root_node, source_bytes), None
        except Exception as exc:
            last_error = f'{language_name}:{exc}'

    if not parsers:
        return IdentifierInventory(), 'parser_unavailable'
    return IdentifierInventory(), last_error or 'parse_failed'


def collect_defined_function_names(
    source_path: Path, parsers: dict[str, object]
) -> tuple[set[str], str | None]:
    inventory, error = collect_identifier_inventory(source_path, parsers)
    return set(inventory.function_names) | set(inventory.type_names), error


def dedupe_paths(paths: list[Path]) -> list[Path]:
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in paths:
        key = str(path)
        if key in seen:
            continue
        deduped.append(path)
        seen.add(key)
    return deduped


def build_source_file_candidates(
    signature_payload: dict[str, Any], primary_file_hint: str | None
) -> list[Path]:
    candidates: list[Path] = []

    bug_trace = extract_std_bug_trace(signature_payload.get('bug_trace', []))
    for node in bug_trace:
        filename = node.get('filename')
        if filename:
            candidates.append(Path(str(filename)))

    top_file_raw = signature_payload.get('file')
    top_file_path: Path | None = None
    if top_file_raw:
        top_file_path = Path(str(top_file_raw))
        candidates.append(top_file_path)

    if primary_file_hint:
        primary_path = Path(primary_file_hint)
        if primary_path.is_absolute():
            candidates.append(primary_path)
        else:
            basename = primary_path.name
            matches = [path for path in candidates if path.name == basename]
            if matches:
                candidates.extend(matches)
            elif top_file_path is not None:
                candidates.append(top_file_path.parent / basename)

    return dedupe_paths(candidates)


def expand_source_candidates_for_identifier_inventory(source_candidates: list[Path]) -> list[Path]:
    expanded: list[Path] = []
    for source_path in dedupe_paths(source_candidates):
        expanded.append(source_path)
        if not source_path.exists():
            continue
        expanded.extend(
            list_juliet_case_group_files(
                source_path,
                allowed_suffixes=JULIET_GROUP_INVENTORY_SUFFIXES,
            )
        )
    return dedupe_paths(expanded)


def find_slice_path(slice_dir: Path, testcase_key: str, role_name: str) -> Path | None:
    candidates = [
        slice_dir / f'slice_{testcase_key}_{role_name}.c',
        slice_dir / f'slice_{testcase_key}_{role_name}.cpp',
    ]
    existing = [path for path in candidates if path.exists()]
    if len(existing) > 1:
        raise RuntimeError(
            f'Multiple slice candidates found for {testcase_key}/{role_name}: {existing}'
        )
    return existing[0] if existing else None
