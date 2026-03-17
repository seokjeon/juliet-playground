from __future__ import annotations

    import sys
    from pathlib import Path

    REPO_ROOT = Path(__file__).resolve().parents[3]
    TOOLS_ROOT = REPO_ROOT / 'tools'
    if str(TOOLS_ROOT) not in sys.path:
        sys.path.insert(0, str(TOOLS_ROOT))

    from shared.csvio import write_csv_rows
    from shared.jsonio import write_json, write_jsonl, write_stage_summary
    from stage import stage02a_taint as _stage02a_taint


    def _write_global_macro_dump(
        output_dir: Path, macro_defs: dict[str, list[_stage02a_taint.MacroDefinition]]
    ) -> dict[str, int]:
        json_path = output_dir / 'global_macro_definitions_by_name.json'
        jsonl_path = output_dir / 'global_macro_definitions_by_name.jsonl'

        by_name: dict[str, list[str]] = {}
        for name in sorted(macro_defs):
            bodies = sorted(
                {
                    (definition.body or '').strip()
                    for definition in macro_defs[name]
                    if (definition.body or '').strip()
                }
            )
            by_name[name] = bodies

        write_json(json_path, by_name)
        write_jsonl(
            jsonl_path,
            ({'name': name, 'bodies': bodies} for name, bodies in by_name.items()),
        )

        rows = sum(len(values) for values in by_name.values())
        return {
            'global_macro_definition_rows': rows,
            'global_macro_unique_names': len(macro_defs),
        }


    def extract_unique_code_fields(
        *,
        input_xml: Path,
        source_root: Path,
        output_dir: Path,
        pulse_taint_config_output: Path | None = None,
    ) -> dict[str, object]:
        core = _stage02a_taint.build_taint_inventory_core(
            input_xml=input_xml,
            source_root=source_root,
        )
        output_dir.mkdir(parents=True, exist_ok=True)

        unique_codes = sorted(core.counts)
        (output_dir / 'code_unique.txt').write_text(
            '
'.join(unique_codes) + ('
' if unique_codes else ''),
            encoding='utf-8',
        )
        write_csv_rows(
            output_dir / 'code_frequency.csv',
            ['count', 'code'],
            (
                [count, code]
                for code, count in sorted(core.counts.items(), key=lambda item: (-item[1], item[0]))
            ),
        )
        write_json(output_dir / 'source_sink_candidate_map.json', core.candidate_map)
        write_csv_rows(
            output_dir / 'function_name_frequency.csv',
            ['count', 'function_name'],
            (
                [count, name]
                for name, count in sorted(
                    core.function_name_counts.items(), key=lambda item: (-item[1], item[0])
                )
            ),
        )
        (output_dir / 'function_name_unique.txt').write_text(
            '
'.join(sorted(core.function_name_counts))
            + ('
' if core.function_name_counts else ''),
            encoding='utf-8',
        )

        macro_dump_stats = _write_global_macro_dump(output_dir, core.macro_defs)
        macro_stats = _stage02a_taint._write_macro_resolution_csv(output_dir, core.resolution_map)

        pulse_output_path = pulse_taint_config_output or (
            output_dir / _stage02a_taint.DEFAULT_PULSE_TAINT_CONFIG_NAME
        )
        pulse_stats = _stage02a_taint._write_pulse_taint_config(
            pulse_output_path,
            core.function_name_counts,
        )

        artifacts = {
            'pulse_taint_config': str(pulse_output_path),
            'source_sink_candidate_map': str(output_dir / 'source_sink_candidate_map.json'),
            'function_name_macro_resolution_csv': str(output_dir / 'function_name_macro_resolution.csv'),
            'summary_json': str(output_dir / 'summary.json'),
        }
        stats = {
            'total_code_entries': len(core.all_comment_codes),
            'candidate_map_keys': len(core.candidate_map),
            'keys_with_calls': sum(1 for value in core.candidate_map.values() if value),
            'unique_function_names': len(core.function_name_counts),
            'duplicate_key_skipped': core.duplicate_key_skipped,
            'flaw_records_processed': core.flaw_records_processed,
            **macro_dump_stats,
            **macro_stats,
            **pulse_stats,
        }
        write_stage_summary(output_dir / 'summary.json', artifacts=artifacts, stats=stats, echo=False)
        return {'artifacts': artifacts, 'stats': stats}
