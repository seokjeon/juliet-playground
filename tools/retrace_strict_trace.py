#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from shared.fs import prepare_output_dir
from shared.jsonio import load_json, write_stage_summary
from shared.paths import RESULT_DIR
from stage import stage02a_taint as _stage02a_taint
from stage import stage02b_epic002 as _stage02b_epic002
from stage import stage02b_flow as _stage02b_flow
from stage import stage04_trace_flow as _stage04_trace_flow


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Regenerate Stage 02b/04 strict trace outputs from an existing pipeline run.'
    )
    parser.add_argument(
        'source_run',
        type=str,
        help='Source run id (for example run-2026.03.17-15:11:12) or full run directory path.',
    )
    parser.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
        help='Pipeline root used when source_run is a run id.',
    )
    parser.add_argument(
        '--output-name',
        type=str,
        default=None,
        help='Sibling output directory name. Defaults to retrace-<source-run-name>.',
    )
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='Replace an existing non-empty retrace output directory.',
    )
    parser.add_argument(
        '--keep-single-child-flows',
        dest='prune_single_child_flows',
        action='store_false',
        help='Keep flow tags that have exactly one child after Stage 02b dedup.',
    )
    parser.add_argument(
        '--source-root',
        type=Path,
        default=None,
        help='Source root used to regenerate the Stage 02a-enriched XML for Stage 04.',
    )
    parser.set_defaults(prune_single_child_flows=True)
    return parser.parse_args()


def _looks_like_path(value: str) -> bool:
    candidate = Path(value)
    return candidate.is_absolute() or len(candidate.parts) > 1 or value.startswith('.')


def resolve_source_run_dir(source_run: str, pipeline_root: Path) -> Path:
    if _looks_like_path(source_run):
        candidate = Path(source_run).resolve()
    else:
        candidate = (pipeline_root.resolve() / source_run).resolve()

    if not candidate.exists():
        raise FileNotFoundError(f'Source run directory not found: {candidate}')
    if not candidate.is_dir():
        raise NotADirectoryError(f'Source run path is not a directory: {candidate}')
    return candidate


def validate_output_name(output_name: str) -> str:
    candidate = Path(output_name)
    if not output_name or len(candidate.parts) != 1 or output_name in {'.', '..'}:
        raise ValueError('--output-name must be a single directory name, not a path.')
    if output_name.startswith('run-'):
        raise ValueError('--output-name must not start with "run-".')
    return output_name


def build_output_dir(source_run_dir: Path, output_name: str | None) -> Path:
    if output_name is None:
        output_name = f'retrace-{source_run_dir.name}'
    output_name = validate_output_name(output_name)
    return (source_run_dir.parent / output_name).resolve()


def resolve_source_manifest(source_run_dir: Path) -> Path:
    manifest_path = source_run_dir / '01_manifest' / 'manifest_with_comments.xml'
    if not manifest_path.exists():
        raise FileNotFoundError(f'Source manifest_with_comments.xml not found: {manifest_path}')
    return manifest_path.resolve()


def resolve_infer_summary(source_run_dir: Path) -> Path:
    summary_path = source_run_dir / '03_infer_summary.json'
    if not summary_path.exists():
        raise FileNotFoundError(f'Source 03_infer_summary.json not found: {summary_path}')
    return summary_path.resolve()


def resolve_signature_non_empty_dir(summary_json: Path) -> Path:
    payload = load_json(summary_json)
    artifacts = payload.get('artifacts') or {}
    if not isinstance(artifacts, dict):
        raise ValueError(f'Expected "artifacts" object in {summary_json}')

    signature_non_empty_dir = str(artifacts.get('signature_non_empty_dir') or '').strip()
    if signature_non_empty_dir:
        resolved = Path(signature_non_empty_dir).resolve()
    else:
        signature_output_dir = str(artifacts.get('signature_output_dir') or '').strip()
        if not signature_output_dir:
            raise ValueError(
                'Could not resolve signature_non_empty_dir from '
                f'{summary_json}: missing artifacts.signature_non_empty_dir and '
                'artifacts.signature_output_dir'
            )
        resolved = (Path(signature_output_dir).resolve() / 'non_empty').resolve()

    if not resolved.exists():
        raise FileNotFoundError(f'Resolved signature_non_empty_dir not found: {resolved}')
    if not resolved.is_dir():
        raise NotADirectoryError(f'Resolved signature_non_empty_dir is not a directory: {resolved}')
    return resolved


def build_retrace_paths(output_dir: Path) -> dict[str, Any]:
    resolved_output_dir = output_dir.resolve()
    return {
        'output_dir': resolved_output_dir,
        'taint_dir': resolved_output_dir / '02a_taint',
        'stage02b': _stage02b_flow.build_stage02b_output_paths(resolved_output_dir / '02b_flow'),
        'stage02b_epic002': _stage02b_epic002.build_stage02b_epic002_output_paths(
            resolved_output_dir / '02b_flow' / 'epic002'
        ),
        'generated_taint_config': resolved_output_dir / '02a_taint' / 'pulse-taint-config.json',
        'source_sink_classified_with_code_xml': (
            resolved_output_dir / '02a_taint' / _stage02a_taint.FLOW_AWARE_ENRICHED_XML_NAME
        ),
        'trace_dir': resolved_output_dir / '04_trace_flow',
        'summary_json': resolved_output_dir / 'retrace_summary.json',
    }


def run_retrace_strict_trace(
    *,
    source_run: str,
    pipeline_root: Path,
    output_name: str | None = None,
    overwrite: bool = False,
    prune_single_child_flows: bool = True,
    source_root: Path | None = None,
) -> dict[str, Any]:
    source_run_dir = resolve_source_run_dir(source_run, pipeline_root)
    manifest_with_comments_xml = resolve_source_manifest(source_run_dir)
    infer_summary_json = resolve_infer_summary(source_run_dir)
    signature_non_empty_dir = resolve_signature_non_empty_dir(infer_summary_json)
    resolved_source_root = source_root.resolve() if source_root is not None else None
    if resolved_source_root is not None and not resolved_source_root.exists():
        raise FileNotFoundError(f'Source root not found: {resolved_source_root}')

    paths = build_retrace_paths(build_output_dir(source_run_dir, output_name))
    if paths['output_dir'] == source_run_dir:
        raise ValueError('Retrace output directory must differ from the source run directory.')

    prepare_output_dir(paths['output_dir'], overwrite)

    stage02b_result = _stage02b_flow.run_stage02b_flow(
        input_xml=manifest_with_comments_xml,
        output_dir=paths['stage02b']['output_dir'],
        prune_single_child_flows=prune_single_child_flows,
    )
    stage02b_epic002_result: dict[str, Any] | None = None
    stage02a_result: dict[str, Any] | None = None
    stage04_flow_xml = paths['stage02b']['manifest_with_testcase_flows_xml']
    if resolved_source_root is not None:
        stage02b_epic002_result = _stage02b_epic002.run_stage02b_epic002(
            input_xml=paths['stage02b']['manifest_with_testcase_flows_xml'],
            output_dir=paths['stage02b_epic002']['output_dir'],
        )
        stage02a_result = _stage02a_taint.extract_unique_code_fields(
            input_xml=paths['stage02b_epic002']['source_sink_classified_xml'],
            source_root=resolved_source_root,
            output_dir=paths['taint_dir'],
            pulse_taint_config_output=paths['generated_taint_config'],
        )
        if paths['source_sink_classified_with_code_xml'].exists():
            stage04_flow_xml = paths['source_sink_classified_with_code_xml']
    stage04_result = _stage04_trace_flow.filter_traces_by_flow(
        flow_xml=stage04_flow_xml,
        signatures_dir=signature_non_empty_dir,
        output_dir=paths['trace_dir'],
    )

    artifacts = {
        'output_dir': str(paths['output_dir']),
        'manifest_with_testcase_flows_xml': str(
            paths['stage02b']['manifest_with_testcase_flows_xml']
        ),
        'stage02b_summary_json': str(paths['stage02b']['summary_json']),
        'trace_flow_match_strict_jsonl': str(paths['trace_dir'] / 'trace_flow_match_strict.jsonl'),
        'stage04_summary_json': str(paths['trace_dir'] / 'summary.json'),
    }
    if stage02b_epic002_result is not None:
        artifacts['source_sink_classified_xml'] = str(
            paths['stage02b_epic002']['source_sink_classified_xml']
        )
        artifacts['stage02b_epic002_summary_json'] = str(paths['stage02b_epic002']['summary_json'])
    if stage02a_result is not None and paths['source_sink_classified_with_code_xml'].exists():
        artifacts['source_sink_classified_with_code_xml'] = str(
            paths['source_sink_classified_with_code_xml']
        )
        artifacts['stage02a_summary_json'] = str(paths['taint_dir'] / 'summary.json')
    stats = {
        'stage02b': dict(stage02b_result.get('stats') or {}),
        'stage04': dict(stage04_result.get('stats') or {}),
    }
    if stage02b_epic002_result is not None:
        stats['stage02b_epic002'] = dict(stage02b_epic002_result.get('stats') or {})
    if stage02a_result is not None:
        stats['stage02a'] = dict(stage02a_result.get('stats') or {})
    extra = {
        'source_run_dir': str(source_run_dir),
        'source_manifest_with_comments_xml': str(manifest_with_comments_xml),
        'source_infer_summary_json': str(infer_summary_json),
        'reused_signature_non_empty_dir': str(signature_non_empty_dir),
        'stage04_flow_xml': str(stage04_flow_xml),
    }
    if resolved_source_root is not None:
        extra['source_root'] = str(resolved_source_root)
    write_stage_summary(
        paths['summary_json'],
        artifacts=artifacts,
        stats=stats,
        extra=extra,
        echo=False,
    )
    return {'artifacts': artifacts, 'stats': stats, **extra}


def main() -> int:
    args = parse_args()
    try:
        run_retrace_strict_trace(
            source_run=args.source_run,
            pipeline_root=args.pipeline_root,
            output_name=args.output_name,
            overwrite=args.overwrite,
            prune_single_child_flows=args.prune_single_child_flows,
            source_root=args.source_root,
        )
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
