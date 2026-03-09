#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

TARGET_COMMENT_TAGS = ("comment_flaw", "comment_fix")
TARGET_ALL_TAGS = (*TARGET_COMMENT_TAGS, "flaw")
SOURCE_EXTS = {".c", ".cpp", ".h"}
PARSER_LANG = {".c": "c", ".cpp": "cpp"}
DEFAULT_PULSE_TAINT_CONFIG_NAME = "pulse-taint-config.from_juliet.json"
RAND_ALIAS_MAP = {"RAND32": "rand", "RAND64": "rand"}

DEFINE_FUNC_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\s*\((.*?)\)\s*(.*)$")
DEFINE_OBJ_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b(.*)$")
PP_IF_RE = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b")
PP_ENDIF_RE = re.compile(r"^\s*#\s*endif\b")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


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


def load_parsers() -> dict[str, object]:
    try:
        from tree_sitter import Parser
        from tree_sitter_languages import get_language
    except Exception:
        return {}

    parsers: dict[str, object] = {}
    for language_name in ("c", "cpp"):
        parser = Parser()
        lang = get_language(language_name)
        if hasattr(parser, "set_language"):
            parser.set_language(lang)
        else:
            parser.language = lang
        parsers[language_name] = parser
    return parsers


def build_source_index(source_root: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for p in source_root.rglob("*"):
        if p.is_file() and p.suffix.lower() in SOURCE_EXTS and p.name not in index:
            index[p.name] = p
    return index


def _node_first_line_text(node, source_bytes: bytes) -> str:
    text = source_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")
    return (text.splitlines()[0] if text else "").strip()


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


def _choose_node(line_nodes: dict[int, list[object]], source_bytes: bytes, line_no: int, target_text: str | None) -> object | None:
    candidates = line_nodes.get(line_no, [])
    if not candidates:
        return None

    if target_text is not None:
        matched = [n for n in candidates if _node_first_line_text(n, source_bytes) == target_text]
        if matched:
            return min(matched, key=lambda n: (n.end_byte - n.start_byte))

    return min(candidates, key=lambda n: (n.end_byte - n.start_byte))


def _extract_calls(node, source_bytes: bytes, target_line: int) -> list[dict[str, int | str]]:
    calls: list[dict[str, int | str]] = []
    seen: set[tuple[str, int]] = set()
    stack = [node]
    while stack:
        n = stack.pop()
        if n.type == "call_expression" and (n.start_point[0] + 1) == target_line:
            fn = n.child_by_field_name("function")
            args = n.child_by_field_name("arguments")
            name = (
                source_bytes[fn.start_byte : fn.end_byte].decode("utf-8", errors="ignore").strip()
                if fn is not None
                else ""
            )
            lname = name.lower()
            if (
                "g2b" in lname
                or "b2b" in lname
                or "bad" in lname
                or lname.startswith("global")
                or lname.startswith("helper")
            ):
                stack.extend(reversed(n.children))
                continue
            argc = len(args.named_children) if args is not None else 0
            sig = (name, argc)
            if sig not in seen:
                seen.add(sig)
                calls.append({"name": name, "argc": argc})
        stack.extend(reversed(n.children))
    return calls


def _load_file_context(src: Path, parsers: dict[str, object]) -> FileContext:
    content = src.read_text(encoding="utf-8", errors="ignore")
    source_bytes = content.encode("utf-8", errors="ignore")
    source_lines = content.splitlines()
    line_nodes: dict[int, list[object]] = {}

    language_name = PARSER_LANG.get(src.suffix.lower())
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
    return ""


def _derive_flaw_key(ctx: FileContext, line_no: int) -> str:
    node = _choose_node(ctx.line_nodes, ctx.source_bytes, line_no, target_text=None)
    if node is not None:
        text = _node_first_line_text(node, ctx.source_bytes)
        if text:
            return text
    line_text = _fallback_line_text(ctx, line_no)
    return line_text if line_text else "WARNING_FLAW_CODE_NOT_FOUND"


def _collect_macro_definitions(source_root: Path) -> dict[str, list[MacroDefinition]]:
    macro_defs: dict[str, list[MacroDefinition]] = {}
    order = 0
    for p in source_root.rglob("*"):
        if not p.is_file() or p.suffix.lower() not in SOURCE_EXTS:
            continue
        try:
            lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        depth = 0
        for i, line in enumerate(lines, 1):
            if PP_IF_RE.match(line):
                depth += 1

            m_func = DEFINE_FUNC_RE.match(line)
            if m_func:
                name = m_func.group(1)
                body = (m_func.group(3) or "").strip()
                order += 1
                macro_defs.setdefault(name, []).append(
                    MacroDefinition(name, "function_like", body, str(p), i, depth > 0, order)
                )
            else:
                m_obj = DEFINE_OBJ_RE.match(line)
                if m_obj:
                    name = m_obj.group(1)
                    body = (m_obj.group(2) or "").strip()
                    order += 1
                    macro_defs.setdefault(name, []).append(
                        MacroDefinition(name, "object_like", body, str(p), i, depth > 0, order)
                    )

            if PP_ENDIF_RE.match(line):
                depth = max(0, depth - 1)
    return macro_defs


def _write_global_macro_dump(output_dir: Path, macro_defs: dict[str, list[MacroDefinition]]) -> dict[str, int]:
    json_path = output_dir / "global_macro_definitions_by_name.json"
    jsonl_path = output_dir / "global_macro_definitions_by_name.jsonl"

    by_name: dict[str, list[str]] = {}
    for name in sorted(macro_defs):
        bodies = sorted({(d.body or "").strip() for d in macro_defs[name] if (d.body or "").strip()})
        by_name[name] = bodies

    json_path.write_text(json.dumps(by_name, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    with jsonl_path.open("w", encoding="utf-8") as f:
        for name, bodies in by_name.items():
            f.write(json.dumps({"name": name, "bodies": bodies}, ensure_ascii=False) + "\n")

    rows = sum(len(v) for v in by_name.values())
    return {
        "global_macro_definition_rows": rows,
        "global_macro_unique_names": len(macro_defs),
    }


def _extract_replacement_identifier(body: str) -> str | None:
    m = IDENT_RE.search(body)
    return m.group(0) if m else None


def _resolve_name(raw_name: str, macro_defs: dict[str, list[MacroDefinition]]) -> ResolutionResult:
    if raw_name in RAND_ALIAS_MAP:
        return ResolutionResult([RAND_ALIAS_MAP[raw_name]], "rand_alias", 1, "function_like", "unknown")

    defs = macro_defs.get(raw_name, [])
    if not defs:
        return ResolutionResult([raw_name], "no_macro_match", 0, "", "")

    resolved_set: set[str] = set()
    for d in defs:
        ident = _extract_replacement_identifier(d.body)
        if ident:
            resolved_set.add(ident)

    if not resolved_set:
        return ResolutionResult([raw_name], "unresolved_no_identifier", len(defs), "", "")

    resolved_names = sorted(resolved_set)
    status = "resolved_multi" if len(resolved_names) > 1 else "resolved_single"
    selected_kind = "mixed" if len({d.kind for d in defs}) > 1 else defs[0].kind
    selected_conditional = "mixed" if len({d.conditional for d in defs}) > 1 else str(defs[0].conditional).lower()
    return ResolutionResult(resolved_names, status, len(defs), selected_kind, selected_conditional)


def _build_resolution_map(raw_names: set[str], macro_defs: dict[str, list[MacroDefinition]]) -> dict[str, ResolutionResult]:
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
            raw_name = str(call.get("name", "")).strip()
            argc = int(call.get("argc", 0))
            rr = resolution_map.get(raw_name, ResolutionResult([raw_name], "no_macro_match", 0, "", ""))
            for resolved_name in rr.resolved_names:
                sig = (resolved_name, argc)
                if sig in seen:
                    continue
                seen.add(sig)
                entry: dict[str, int | str] = {"name": resolved_name, "argc": argc}
                if raw_name and raw_name != resolved_name:
                    entry["original_name"] = raw_name
                new_calls.append(entry)
        resolved_map[code_key] = new_calls
    return resolved_map


def _count_function_names(candidate_map: dict[str, list[dict[str, int | str]]]) -> Counter[str]:
    name_counts: Counter[str] = Counter()
    for calls in candidate_map.values():
        for call in calls:
            name = str(call.get("name", "")).strip()
            if name:
                name_counts[name] += 1
    return name_counts


def _write_macro_resolution_csv(output_dir: Path, resolution_map: dict[str, ResolutionResult]) -> dict[str, int]:
    path = output_dir / "function_name_macro_resolution.csv"
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "original_name",
                "resolved_names",
                "resolution_status",
                "candidate_count",
                "selected_kind",
                "selected_conditional",
            ]
        )
        for raw_name in sorted(resolution_map):
            rr = resolution_map[raw_name]
            writer.writerow(
                [
                    raw_name,
                    "|".join(rr.resolved_names),
                    rr.status,
                    rr.candidate_count,
                    rr.selected_kind,
                    rr.selected_conditional,
                ]
            )

    statuses = Counter(rr.status for rr in resolution_map.values())
    return {
        "macro_names_detected": sum(1 for rr in resolution_map.values() if rr.status != "no_macro_match"),
        "macro_resolved_count": statuses["resolved_single"] + statuses["resolved_multi"] + statuses["rand_alias"],
        "macro_ambiguous_count": statuses["resolved_multi"],
        "macro_unresolved_count": statuses["unresolved_no_identifier"],
        "rand_alias_applied_count": statuses["rand_alias"],
    }


def _build_pulse_taint_config(function_names: list[str]) -> dict[str, list[dict[str, str]]]:
    all_names = sorted(function_names)
    return {
        "pulse-taint-sources": [
            record
            for name in all_names
            for record in (
                {"procedure": name, "taint_target": "ReturnValue"},
                {"procedure": name, "taint_target": "AllArguments"},
            )
        ],
        "pulse-taint-sinks": [{"procedure": name, "taint_target": "AllArguments"} for name in all_names],
    }


def _write_pulse_taint_config(output_path: Path, function_name_counts: Counter[str]) -> dict[str, int]:
    function_names = sorted(function_name_counts)
    config = _build_pulse_taint_config(function_names)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return {
        "pulse_source_procedures": len(config["pulse-taint-sources"]) // 2,
        "pulse_sink_procedures": len(config["pulse-taint-sinks"]),
    }


def write_outputs(
    output_dir: Path,
    all_comment_codes: list[str],
    counts: Counter[str],
    candidate_map: dict[str, list[dict[str, int | str]]],
    duplicate_key_skipped: int,
    flaw_records_processed: int,
    extra_stats: dict[str, int],
) -> Counter[str]:
    output_dir.mkdir(parents=True, exist_ok=True)

    unique_codes = sorted(counts)
    (output_dir / "code_unique.txt").write_text("\n".join(unique_codes) + ("\n" if unique_codes else ""), encoding="utf-8")

    with (output_dir / "code_frequency.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["count", "code"])
        for code, cnt in sorted(counts.items(), key=lambda x: (-x[1], x[0])):
            writer.writerow([cnt, code])

    (output_dir / "source_sink_candidate_map.json").write_text(
        json.dumps(candidate_map, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    function_name_counts = _count_function_names(candidate_map)
    with (output_dir / "function_name_frequency.csv").open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["count", "function_name"])
        for name, cnt in sorted(function_name_counts.items(), key=lambda x: (-x[1], x[0])):
            writer.writerow([cnt, name])

    (output_dir / "function_name_unique.txt").write_text(
        "\n".join(sorted(function_name_counts)) + ("\n" if function_name_counts else ""), encoding="utf-8"
    )

    summary = {
        "total_code_entries": len(all_comment_codes),
        "unique_code_entries": len(counts),
        "max_frequency": max(counts.values()) if counts else 0,
        "candidate_map_keys": len(candidate_map),
        "keys_with_calls": sum(1 for v in candidate_map.values() if v),
        "unique_function_names": len(function_name_counts),
        "total_function_name_occurrences": sum(function_name_counts.values()),
        "duplicate_key_skipped": duplicate_key_skipped,
        "flaw_records_processed": flaw_records_processed,
        **extra_stats,
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return function_name_counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract code values/frequency and build source-sink candidate call map.")
    parser.add_argument(
        "--input-xml",
        type=Path,
        default=Path("experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml"),
    )
    parser.add_argument("--source-root", type=Path, default=Path("juliet-test-suite-v1.3/C"))
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("experiments/epic001a_code_field_inventory/outputs"),
    )
    parser.add_argument(
        "--pulse-taint-config-output",
        type=Path,
        default=None,
        help=f"Optional output path (default: <output-dir>/{DEFAULT_PULSE_TAINT_CONFIG_NAME}).",
    )
    args = parser.parse_args()

    if not args.input_xml.exists():
        raise FileNotFoundError(f"Input XML not found: {args.input_xml}")
    if not args.source_root.exists():
        raise FileNotFoundError(f"Source root not found: {args.source_root}")

    parsers = load_parsers()
    source_index = build_source_index(args.source_root)
    root = ET.parse(args.input_xml).getroot()

    all_comment_codes: list[str] = []
    counts: Counter[str] = Counter()
    candidate_map_raw: dict[str, list[dict[str, int | str]]] = {}
    duplicate_key_skipped = 0
    flaw_records_processed = 0

    for file_elem in root.iter("file"):
        file_name = file_elem.attrib.get("path", "")
        src = source_index.get(file_name)
        ctx = _load_file_context(src, parsers) if src is not None else None

        for child in list(file_elem):
            tag = child.tag
            if tag not in TARGET_ALL_TAGS:
                continue

            line_no = int(child.attrib.get("line", "0") or 0)

            if tag in TARGET_COMMENT_TAGS:
                key = child.attrib.get("code")
                if key is None:
                    continue
                all_comment_codes.append(key)
                counts[key] += 1
            else:
                flaw_records_processed += 1
                key = "WARNING_FLAW_CODE_NOT_FOUND" if ctx is None else _derive_flaw_key(ctx, line_no)

            if key in candidate_map_raw:
                duplicate_key_skipped += 1
                continue

            if ctx is None:
                candidate_map_raw[key] = []
                continue

            chosen = _choose_node(ctx.line_nodes, ctx.source_bytes, line_no, target_text=key)
            if chosen is None:
                candidate_map_raw[key] = []
                continue

            candidate_map_raw[key] = _extract_calls(chosen, ctx.source_bytes, line_no)

    raw_function_names: set[str] = {
        str(call.get("name", "")).strip()
        for calls in candidate_map_raw.values()
        for call in calls
        if str(call.get("name", "")).strip()
    }
    macro_defs = _collect_macro_definitions(args.source_root)
    resolution_map = _build_resolution_map(raw_function_names, macro_defs)
    candidate_map = _apply_resolution_to_candidate_map(candidate_map_raw, resolution_map)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    macro_dump_stats = _write_global_macro_dump(args.output_dir, macro_defs)
    macro_stats = _write_macro_resolution_csv(args.output_dir, resolution_map)
    extra_stats = {**macro_dump_stats, **macro_stats}

    function_name_counts = write_outputs(
        args.output_dir,
        all_comment_codes,
        counts,
        candidate_map,
        duplicate_key_skipped,
        flaw_records_processed,
        extra_stats,
    )

    pulse_output_path = args.pulse_taint_config_output or (args.output_dir / DEFAULT_PULSE_TAINT_CONFIG_NAME)
    pulse_stats = _write_pulse_taint_config(pulse_output_path, function_name_counts)

    print(
        json.dumps(
            {
                "input_xml": str(args.input_xml),
                "source_root": str(args.source_root),
                "output_dir": str(args.output_dir),
                "total_code_entries": len(all_comment_codes),
                "unique_code_entries": len(counts),
                "max_frequency": max(counts.values()) if counts else 0,
                "candidate_map_keys": len(candidate_map),
                "keys_with_calls": sum(1 for v in candidate_map.values() if v),
                "unique_function_names": len(function_name_counts),
                "total_function_name_occurrences": sum(function_name_counts.values()),
                "duplicate_key_skipped": duplicate_key_skipped,
                "flaw_records_processed": flaw_records_processed,
                "pulse_taint_config_output": str(pulse_output_path),
                **extra_stats,
                **pulse_stats,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
