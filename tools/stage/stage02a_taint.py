from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from shared.csvio import write_csv_rows
from shared.dataset_sources import load_tree_sitter_parsers
from shared.jsonio import write_json, write_stage_summary
from shared.juliet_manifest import build_manifest_source_index
from shared.source_parsing import PARSER_LANG_BY_SUFFIX, SOURCE_EXTS, node_first_line_text

TARGET_COMMENT_TAGS = ('comment_flaw', 'comment_fix')
TARGET_ALL_TAGS = (*TARGET_COMMENT_TAGS, 'flaw')
DEFAULT_PULSE_TAINT_CONFIG_NAME = 'pulse-taint-config.from_juliet.json'
FLOW_AWARE_ENRICHED_XML_NAME = 'source_sink_classified_with_code.xml'
RAND_ALIAS_MAP = {'RAND32': 'rand', 'RAND64': 'rand'}

DEFINE_FUNC_RE = re.compile(r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*(.*)$')
DEFINE_OBJ_RE = re.compile(r'^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b(.*)$')
PP_IF_RE = re.compile(r'^\s*#\s*(if|ifdef|ifndef)\b')
PP_ENDIF_RE = re.compile(r'^\s*#\s*endif\b')
IDENT_RE = re.compile(r'[A-Za-z_][A-Za-z0-9_]*')


@dataclass
class FileContext:
    source_bytes: bytes
    source_lines: list[str]
    line_nodes: dict[int, list[object]]


@dataclass
class MacroDefinition:
    name: str
    kind: str  # function_like | object_like
    body: str
    file: str
    line: int
    conditional: bool
    order: int


@dataclass
class ResolutionResult:
    resolved_names: list[str]
    status: str
    candidate_count: int
    selected_kind: str
    selected_conditional: str


@dataclass(frozen=True)
class TaintInventoryCore:
    all_comment_codes: list[str]
    counts: Counter[str]
    candidate_map: dict[str, list[dict[str, int | str]]]
    function_name_counts: Counter[str]
    duplicate_key_skipped: int
    flaw_records_processed: int
    macro_defs: dict[str, list[MacroDefinition]]
    resolution_map: dict[str, ResolutionResult]
    mode: str = 'legacy'
    source_function_name_counts: Counter[str] | None = None
    sink_function_name_counts: Counter[str] | None = None


@dataclass(frozen=True)
class FlowAwareCodeBackfillResult:
    output_xml: Path
    attempted: int
    succeeded: int
    failed: int
    failed_examples: list[dict[str, int | str]]


def _build_line_nodes(root_node) -> dict[int, list[object]]:
    line_nodes: dict[int, list[object]] = {}
    stack = [root_node]
    while stack:
        node = stack.pop()
        if node.is_named:
            line = node.start_point[0] + 1
            line_nodes.setdefault(line, []).append(node)
        stack.extend(reversed(node.children))
    return line_nodes


def _choose_node(
    line_nodes: dict[int, list[object]], source_bytes: bytes, line_no: int, target_text: str | None
) -> object | None:
    candidates = line_nodes.get(line_no, [])
    if not candidates:
        return None

    if target_text is not None:
        matched = [n for n in candidates if node_first_line_text(n, source_bytes) == target_text]
        if matched:
            return min(matched, key=lambda n: n.end_byte - n.start_byte)

    return min(candidates, key=lambda n: n.end_byte - n.start_byte)


def _extract_calls(node, source_bytes: bytes, target_line: int) -> list[dict[str, int | str]]:
    calls: list[dict[str, int | str]] = []
    seen: set[tuple[str, int]] = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == 'call_expression' and (n.start_point[0] + 1) == target_line:
            fn = n.child_by_field_name('function')
            args = n.child_by_field_name('arguments')
            name = (
                source_bytes[fn.start_byte : fn.end_byte].decode('utf-8', errors='ignore').strip()
                if fn is not None
                else ''
            )
            lname = name.lower()
            if (
                'g2b' in lname
                or 'b2b' in lname
                or 'bad' in lname
                or lname.startswith('global')
                or lname.startswith('helper')
            ):
                stack.extend(reversed(n.children))
                continue
            argc = len(args.named_children) if args is not None else 0
            sig = (name, argc)
            if sig not in seen:
                seen.add(sig)
                calls.append({'name': name, 'argc': argc})
        stack.extend(reversed(n.children))
    return calls


def _load_file_context(src: Path, parsers: dict[str, object]) -> FileContext:
    content = src.read_text(encoding='utf-8', errors='ignore')
    source_bytes = content.encode('utf-8', errors='ignore')
    source_lines = content.splitlines()
    line_nodes: dict[int, list[object]] = {}

    language_name = PARSER_LANG_BY_SUFFIX.get(src.suffix.lower())
    parser = parsers.get(language_name) if language_name else None
    if parser is not None:
        try:
            tree = parser.parse(source_bytes)
            line_nodes = _build_line_nodes(tree.root_node)
        except Exception:
            line_nodes = {}

    return FileContext(source_bytes=source_bytes, source_lines=source_lines, line_nodes=line_nodes)


def _fallback_line_text(ctx: FileContext, line_no: int) -> str:
    if 1 <= line_no <= len(ctx.source_lines):
        return ctx.source_lines[line_no - 1].strip()
    return ''


def _derive_flaw_key(ctx: FileContext, line_no: int) -> str:
    node = _choose_node(ctx.line_nodes, ctx.source_bytes, line_no, target_text=None)
    if node is not None:
        text = node_first_line_text(node, ctx.source_bytes)
        if text:
            return text
    line_text = _fallback_line_text(ctx, line_no)
    return line_text if line_text else 'WARNING_FLAW_CODE_NOT_FOUND'


def _derive_line_text_key(ctx: FileContext, line_no: int) -> str:
    line_text = _fallback_line_text(ctx, line_no)
    if line_text:
        return line_text
    return _derive_flaw_key(ctx, line_no)


def _collect_macro_definitions(source_root: Path) -> dict[str, list[MacroDefinition]]:
    macro_defs: dict[str, list[MacroDefinition]] = {}
    order = 0
    for p in source_root.rglob('*'):
        if not p.is_file() or p.suffix.lower() not in SOURCE_EXTS:
            continue
        try:
            lines = p.read_text(encoding='utf-8', errors='ignore').splitlines()
        except Exception:
            continue
        depth = 0
        for i, line in enumerate(lines, 1):
            if PP_IF_RE.match(line):
                depth += 1

            m_func = DEFINE_FUNC_RE.match(line)
            if m_func:
                name = m_func.group(1)
                body = (m_func.group(3) or '').strip()
                order += 1
                macro_defs.setdefault(name, []).append(
                    MacroDefinition(name, 'function_like', body, str(p), i, depth > 0, order)
                )
            else:
                m_obj = DEFINE_OBJ_RE.match(line)
                if m_obj:
                    name = m_obj.group(1)
                    body = (m_obj.group(2) or '').strip()
                    order += 1
                    macro_defs.setdefault(name, []).append(
                        MacroDefinition(name, 'object_like', body, str(p), i, depth > 0, order)
                    )

            if PP_ENDIF_RE.match(line):
                depth = max(0, depth - 1)
    return macro_defs


def _extract_replacement_identifier(body: str) -> str | None:
    m = IDENT_RE.search(body)
    return m.group(0) if m else None


def _resolve_name(raw_name: str, macro_defs: dict[str, list[MacroDefinition]]) -> ResolutionResult:
    if raw_name in RAND_ALIAS_MAP:
        return ResolutionResult(
            [RAND_ALIAS_MAP[raw_name]], 'rand_alias', 1, 'function_like', 'unknown'
        )

    defs = macro_defs.get(raw_name, [])
    if not defs:
        return ResolutionResult([raw_name], 'no_macro_match', 0, '', '')

    resolved_set: set[str] = set()
    for d in defs:
        ident = _extract_replacement_identifier(d.body)
        if ident:
            resolved_set.add(ident)

    if not resolved_set:
        return ResolutionResult([raw_name], 'unresolved_no_identifier', len(defs), '', '')

    resolved_names = sorted(resolved_set)
    status = 'resolved_multi' if len(resolved_names) > 1 else 'resolved_single'
    selected_kind = 'mixed' if len({d.kind for d in defs}) > 1 else defs[0].kind
    selected_conditional = (
        'mixed' if len({d.conditional for d in defs}) > 1 else str(defs[0].conditional).lower()
    )
    return ResolutionResult(resolved_names, status, len(defs), selected_kind, selected_conditional)


def _build_resolution_map(
    raw_names: set[str], macro_defs: dict[str, list[MacroDefinition]]
) -> dict[str, ResolutionResult]:
    return {name: _resolve_name(name, macro_defs) for name in sorted(raw_names)}


def _apply_resolution_to_candidate_map(
    candidate_map: dict[str, list[dict[str, int | str]]],
    resolution_map: dict[str, ResolutionResult],
) -> dict[str, list[dict[str, int | str]]]:
    resolved_map: dict[str, list[dict[str, int | str]]] = {}
    for code_key, calls in candidate_map.items():
        new_calls: list[dict[str, int | str]] = []
        seen: set[tuple[str, int]] = set()
        for call in calls:
            raw_name = str(call.get('name', '')).strip()
            argc = int(call.get('argc', 0))
            rr = resolution_map.get(
                raw_name, ResolutionResult([raw_name], 'no_macro_match', 0, '', '')
            )
            for resolved_name in rr.resolved_names:
                sig = (resolved_name, argc)
                if sig in seen:
                    continue
                seen.add(sig)
                entry: dict[str, int | str] = {'name': resolved_name, 'argc': argc}
                if raw_name and raw_name != resolved_name:
                    entry['original_name'] = raw_name
                new_calls.append(entry)
        resolved_map[code_key] = new_calls
    return resolved_map


def _count_function_names(candidate_map: dict[str, list[dict[str, int | str]]]) -> Counter[str]:
    name_counts: Counter[str] = Counter()
    for calls in candidate_map.values():
        for call in calls:
            name = str(call.get('name', '')).strip()
            if name:
                name_counts[name] += 1
    return name_counts


def _get_or_load_file_context(
    *,
    file_name: str,
    source_index: dict[str, Path],
    parsers: dict[str, object],
    cache: dict[str, FileContext | None],
) -> FileContext | None:
    if file_name not in cache:
        src = source_index.get(file_name)
        cache[file_name] = _load_file_context(src, parsers) if src is not None else None
    return cache[file_name]


def _build_record_candidate_entry(
    *,
    ctx: FileContext | None,
    line_no: int,
    key: str,
) -> list[dict[str, int | str]]:
    if ctx is None:
        return []
    chosen = _choose_node(ctx.line_nodes, ctx.source_bytes, line_no, target_text=key)
    if chosen is None:
        return []
    return _extract_calls(chosen, ctx.source_bytes, line_no)


def _manifest_has_flow_roles(root: ET.Element) -> bool:
    return any(
        child.attrib.get('role') in {'source', 'sink'}
        for flow in root.iter('flow')
        for child in flow
        if child.tag in {'fix', 'flaw'}
    )


def _derive_code_for_flow_xml(*, ctx: FileContext | None, line_no: int) -> str:
    if ctx is None or line_no <= 0:
        return ''
    derived = _derive_line_text_key(ctx, line_no)
    if derived == 'WARNING_FLAW_CODE_NOT_FOUND':
        return ''
    return derived


def _backfill_flow_aware_code_xml(
    *,
    input_xml: Path,
    source_root: Path,
    output_dir: Path,
) -> FlowAwareCodeBackfillResult | None:
    tree = ET.parse(input_xml)
    root = tree.getroot()
    if not _manifest_has_flow_roles(root):
        return None

    parsers = load_tree_sitter_parsers()
    source_index = build_manifest_source_index(
        manifest_xml=input_xml,
        source_root=source_root,
        suffixes=SOURCE_EXTS,
    )
    ctx_cache: dict[str, FileContext | None] = {}
    attempted = 0
    succeeded = 0
    failed = 0
    failed_examples: list[dict[str, int | str]] = []

    for testcase in root.findall('testcase'):
        for flow in testcase.findall('flow'):
            for child in flow:
                if child.tag not in {'fix', 'flaw'}:
                    continue

                role = child.attrib.get('role')
                if role not in {'source', 'sink'}:
                    continue

                if (child.attrib.get('code') or '').strip():
                    continue

                attempted += 1
                file_name = child.attrib.get('file', '')
                line_no = int(child.attrib.get('line', '0') or 0)
                ctx = _get_or_load_file_context(
                    file_name=file_name,
                    source_index=source_index,
                    parsers=parsers,
                    cache=ctx_cache,
                )
                derived_code = _derive_code_for_flow_xml(ctx=ctx, line_no=line_no)
                child.attrib['code'] = derived_code

                if derived_code:
                    succeeded += 1
                    continue

                failed += 1
                if len(failed_examples) < 10:
                    failed_examples.append(
                        {
                            'file': file_name,
                            'line': line_no,
                            'tag': child.tag,
                            'role': role,
                            'function': child.attrib.get('function', ''),
                        }
                    )

    output_xml = output_dir / FLOW_AWARE_ENRICHED_XML_NAME
    output_xml.parent.mkdir(parents=True, exist_ok=True)
    try:
        ET.indent(tree, space='  ')
    except AttributeError:
        pass
    tree.write(output_xml, encoding='utf-8', xml_declaration=True)

    return FlowAwareCodeBackfillResult(
        output_xml=output_xml,
        attempted=attempted,
        succeeded=succeeded,
        failed=failed,
        failed_examples=failed_examples,
    )


def _write_macro_resolution_csv(
    output_dir: Path, resolution_map: dict[str, ResolutionResult]
) -> dict[str, int]:
    path = output_dir / 'function_name_macro_resolution.csv'
    write_csv_rows(
        path,
        [
            'original_name',
            'resolved_names',
            'resolution_status',
            'candidate_count',
            'selected_kind',
            'selected_conditional',
        ],
        (
            [
                raw_name,
                '|'.join(rr.resolved_names),
                rr.status,
                rr.candidate_count,
                rr.selected_kind,
                rr.selected_conditional,
            ]
            for raw_name in sorted(resolution_map)
            for rr in [resolution_map[raw_name]]
        ),
    )

    statuses = Counter(rr.status for rr in resolution_map.values())
    return {
        'macro_names_detected': sum(
            1 for rr in resolution_map.values() if rr.status != 'no_macro_match'
        ),
        'macro_resolved_count': statuses['resolved_single']
        + statuses['resolved_multi']
        + statuses['rand_alias'],
        'macro_ambiguous_count': statuses['resolved_multi'],
        'macro_unresolved_count': statuses['unresolved_no_identifier'],
        'rand_alias_applied_count': statuses['rand_alias'],
    }


def _build_macro_resolution_stats(resolution_map: dict[str, ResolutionResult]) -> dict[str, int]:
    statuses = Counter(rr.status for rr in resolution_map.values())
    return {
        'macro_names_detected': sum(
            1 for rr in resolution_map.values() if rr.status != 'no_macro_match'
        ),
        'macro_resolved_count': statuses['resolved_single']
        + statuses['resolved_multi']
        + statuses['rand_alias'],
        'macro_ambiguous_count': statuses['resolved_multi'],
        'macro_unresolved_count': statuses['unresolved_no_identifier'],
        'rand_alias_applied_count': statuses['rand_alias'],
    }


def _build_pulse_taint_config(
    source_function_names: list[str],
    sink_function_names: list[str] | None = None,
) -> dict[str, list[dict[str, str]]]:
    all_source_names = sorted(source_function_names)
    all_sink_names = sorted(
        sink_function_names if sink_function_names is not None else source_function_names
    )
    return {
        'pulse-taint-sources': [
            record
            for name in all_source_names
            for record in (
                {'procedure': name, 'taint_target': 'ReturnValue'},
                {'procedure': name, 'taint_target': 'AllArguments'},
            )
        ],
        'pulse-taint-sinks': [
            {'procedure': name, 'taint_target': 'AllArguments'} for name in all_sink_names
        ],
    }


def _write_pulse_taint_config(
    output_path: Path,
    source_function_name_counts: Counter[str],
    sink_function_name_counts: Counter[str] | None = None,
) -> dict[str, int]:
    source_function_names = sorted(source_function_name_counts)
    sink_function_names = (
        sorted(sink_function_name_counts)
        if sink_function_name_counts is not None
        else source_function_names
    )
    config = _build_pulse_taint_config(source_function_names, sink_function_names)
    write_json(output_path, config)
    return {
        'pulse_source_procedures': len(source_function_names),
        'pulse_sink_procedures': len(config['pulse-taint-sinks']),
    }


def _build_legacy_taint_inventory_core(
    *,
    root: ET.Element,
    source_index: dict[str, Path],
    parsers: dict[str, object],
    source_root: Path,
) -> TaintInventoryCore:
    all_comment_codes: list[str] = []
    counts: Counter[str] = Counter()
    candidate_map_raw: dict[str, list[dict[str, int | str]]] = {}
    duplicate_key_skipped = 0
    flaw_records_processed = 0
    ctx_cache: dict[str, FileContext | None] = {}

    for file_elem in root.iter('file'):
        file_name = file_elem.attrib.get('path', '')
        ctx = _get_or_load_file_context(
            file_name=file_name,
            source_index=source_index,
            parsers=parsers,
            cache=ctx_cache,
        )

        for child in list(file_elem):
            tag = child.tag
            if tag not in TARGET_ALL_TAGS:
                continue

            line_no = int(child.attrib.get('line', '0') or 0)

            if tag in TARGET_COMMENT_TAGS:
                key = child.attrib.get('code')
                if key is None:
                    continue
                all_comment_codes.append(key)
                counts[key] += 1
            else:
                flaw_records_processed += 1
                key = (
                    'WARNING_FLAW_CODE_NOT_FOUND' if ctx is None else _derive_flaw_key(ctx, line_no)
                )

            if key in candidate_map_raw:
                duplicate_key_skipped += 1
                continue

            candidate_map_raw[key] = _build_record_candidate_entry(
                ctx=ctx, line_no=line_no, key=key
            )

    raw_function_names: set[str] = {
        str(call.get('name', '')).strip()
        for calls in candidate_map_raw.values()
        for call in calls
        if str(call.get('name', '')).strip()
    }
    macro_defs = _collect_macro_definitions(source_root)
    resolution_map = _build_resolution_map(raw_function_names, macro_defs)
    candidate_map = _apply_resolution_to_candidate_map(candidate_map_raw, resolution_map)
    function_name_counts = _count_function_names(candidate_map)

    return TaintInventoryCore(
        all_comment_codes=all_comment_codes,
        counts=counts,
        candidate_map=candidate_map,
        function_name_counts=function_name_counts,
        duplicate_key_skipped=duplicate_key_skipped,
        flaw_records_processed=flaw_records_processed,
        macro_defs=macro_defs,
        resolution_map=resolution_map,
    )


def _build_flow_aware_taint_inventory_core(
    *,
    root: ET.Element,
    source_index: dict[str, Path],
    parsers: dict[str, object],
    source_root: Path,
) -> TaintInventoryCore:
    all_comment_codes: list[str] = []
    counts: Counter[str] = Counter()
    source_candidate_map_raw: dict[str, list[dict[str, int | str]]] = {}
    sink_candidate_map_raw: dict[str, list[dict[str, int | str]]] = {}
    duplicate_key_skipped = 0
    flaw_records_processed = 0
    ctx_cache: dict[str, FileContext | None] = {}

    for testcase in root.findall('testcase'):
        for flow in testcase.findall('flow'):
            for child in flow:
                if child.tag not in {'fix', 'flaw'}:
                    continue

                role = child.attrib.get('role')
                if role not in {'source', 'sink'}:
                    continue

                file_name = child.attrib.get('file', '')
                ctx = _get_or_load_file_context(
                    file_name=file_name,
                    source_index=source_index,
                    parsers=parsers,
                    cache=ctx_cache,
                )
                line_no = int(child.attrib.get('line', '0') or 0)
                explicit_code = child.attrib.get('code') or None
                key = (
                    explicit_code
                    if explicit_code is not None
                    else (
                        'WARNING_FLAW_CODE_NOT_FOUND'
                        if ctx is None
                        else _derive_line_text_key(ctx, line_no)
                    )
                )

                all_comment_codes.append(key)
                counts[key] += 1
                if child.tag == 'flaw':
                    flaw_records_processed += 1

                candidate_map_raw = (
                    source_candidate_map_raw if role == 'source' else sink_candidate_map_raw
                )
                if key in candidate_map_raw:
                    duplicate_key_skipped += 1
                    continue

                candidate_map_raw[key] = _build_record_candidate_entry(
                    ctx=ctx,
                    line_no=line_no,
                    key=key,
                )

    raw_function_names: set[str] = {
        str(call.get('name', '')).strip()
        for candidate_map_raw in (source_candidate_map_raw, sink_candidate_map_raw)
        for calls in candidate_map_raw.values()
        for call in calls
        if str(call.get('name', '')).strip()
    }
    macro_defs = _collect_macro_definitions(source_root)
    resolution_map = _build_resolution_map(raw_function_names, macro_defs)
    source_candidate_map = _apply_resolution_to_candidate_map(
        source_candidate_map_raw,
        resolution_map,
    )
    sink_candidate_map = _apply_resolution_to_candidate_map(
        sink_candidate_map_raw,
        resolution_map,
    )
    source_function_name_counts = _count_function_names(source_candidate_map)
    sink_function_name_counts = _count_function_names(sink_candidate_map)
    candidate_map = {
        **{f'source::{key}': value for key, value in source_candidate_map.items()},
        **{f'sink::{key}': value for key, value in sink_candidate_map.items()},
    }

    return TaintInventoryCore(
        all_comment_codes=all_comment_codes,
        counts=counts,
        candidate_map=candidate_map,
        function_name_counts=source_function_name_counts + sink_function_name_counts,
        duplicate_key_skipped=duplicate_key_skipped,
        flaw_records_processed=flaw_records_processed,
        macro_defs=macro_defs,
        resolution_map=resolution_map,
        mode='flow_aware',
        source_function_name_counts=source_function_name_counts,
        sink_function_name_counts=sink_function_name_counts,
    )


def build_taint_inventory_core(*, input_xml: Path, source_root: Path) -> TaintInventoryCore:
    if not input_xml.exists():
        raise FileNotFoundError(f'Input XML not found: {input_xml}')
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    parsers = load_tree_sitter_parsers()
    source_index = build_manifest_source_index(
        manifest_xml=input_xml,
        source_root=source_root,
        suffixes=SOURCE_EXTS,
    )
    root = ET.parse(input_xml).getroot()
    if _manifest_has_flow_roles(root):
        return _build_flow_aware_taint_inventory_core(
            root=root,
            source_index=source_index,
            parsers=parsers,
            source_root=source_root,
        )

    return _build_legacy_taint_inventory_core(
        root=root,
        source_index=source_index,
        parsers=parsers,
        source_root=source_root,
    )


def extract_unique_code_fields(
    *,
    input_xml: Path,
    source_root: Path,
    output_dir: Path,
    pulse_taint_config_output: Path | None = None,
) -> dict[str, object]:
    if not input_xml.exists():
        raise FileNotFoundError(f'Input XML not found: {input_xml}')
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    flow_aware_backfill = _backfill_flow_aware_code_xml(
        input_xml=input_xml,
        source_root=source_root,
        output_dir=output_dir,
    )
    selected_input_xml = flow_aware_backfill.output_xml if flow_aware_backfill else input_xml
    core = build_taint_inventory_core(input_xml=selected_input_xml, source_root=source_root)

    output_dir.mkdir(parents=True, exist_ok=True)
    _write_macro_resolution_csv(output_dir, core.resolution_map)

    pulse_output_path = pulse_taint_config_output or (output_dir / DEFAULT_PULSE_TAINT_CONFIG_NAME)
    pulse_stats = _write_pulse_taint_config(
        pulse_output_path,
        core.source_function_name_counts or core.function_name_counts,
        core.sink_function_name_counts,
    )

    artifacts = {
        'pulse_taint_config': str(pulse_output_path),
        'function_name_macro_resolution_csv': str(
            output_dir / 'function_name_macro_resolution.csv'
        ),
        'summary_json': str(output_dir / 'summary.json'),
    }
    if flow_aware_backfill is not None:
        artifacts['source_sink_classified_with_code_xml'] = str(flow_aware_backfill.output_xml)
    stats = {
        'total_code_entries': len(core.all_comment_codes),
        'candidate_map_keys': len(core.candidate_map),
        'keys_with_calls': sum(1 for value in core.candidate_map.values() if value),
        'unique_function_names': len(core.function_name_counts),
        'duplicate_key_skipped': core.duplicate_key_skipped,
        'flaw_records_processed': core.flaw_records_processed,
        **pulse_stats,
    }
    extra = None
    if core.mode == 'flow_aware':
        stats['unique_source_function_names'] = len(core.source_function_name_counts or Counter())
        stats['unique_sink_function_names'] = len(core.sink_function_name_counts or Counter())
    if flow_aware_backfill is not None:
        stats['code_backfill_attempted'] = flow_aware_backfill.attempted
        stats['code_backfill_succeeded'] = flow_aware_backfill.succeeded
        stats['code_backfill_failed'] = flow_aware_backfill.failed
        extra = {'code_backfill_failed_examples': flow_aware_backfill.failed_examples}
    write_stage_summary(
        output_dir / 'summary.json',
        artifacts=artifacts,
        stats=stats,
        extra=extra,
        echo=False,
    )
    return {'artifacts': artifacts, 'stats': stats}
