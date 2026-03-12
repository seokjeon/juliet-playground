#!/usr/bin/env python3
from __future__ import annotations

import argparse
import datetime
import importlib.util
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from paths import PROJECT_HOME, RESULT_DIR


def now_ts_compact() -> str:
    return datetime.datetime.now().strftime('%Y%m%d_%H%M%S')


def now_iso_utc() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            'Re-run pipeline Step 07 (dataset export) for an existing run using the already '
            'generated Step 05/06 artifacts. By default it re-runs both Step 07 and Step 07b.'
        )
    )
    parser.add_argument(
        '--run-dir',
        type=Path,
        default=None,
        help='Pipeline run directory. If omitted, use the latest run under --pipeline-root.',
    )
    parser.add_argument(
        '--pipeline-root',
        type=Path,
        default=Path(RESULT_DIR) / 'pipeline-runs',
        help='Root directory containing run-* pipeline outputs.',
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=None,
        help=(
            'Target directory for Step 07 outputs; default is <run-dir>/07_dataset_export_<ts> '
            'for the normal 07+07b rerun, or <run-dir>/07_dataset_export for --only-07b.'
        ),
    )
    parser.add_argument(
        '--dedup-mode',
        choices=['none', 'row'],
        default='row',
        help='Normalized-slice dedup mode to use for Step 07 export.',
    )
    parser.add_argument(
        '--overwrite',
        action='store_true',
        help='Replace an existing --output-dir.',
    )
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        '--only-07',
        action='store_true',
        help='Run only Step 07.',
    )
    mode_group.add_argument(
        '--only-07b',
        action='store_true',
        help='Run only Step 07b against an existing Step 07 output directory.',
    )
    parser.add_argument(
        '--old-prefix',
        type=str,
        default=None,
        help='Optional old path prefix to pass through when re-running Step 07b.',
    )
    parser.add_argument(
        '--new-prefix',
        type=str,
        default=None,
        help='Optional new path prefix to pass through when re-running Step 07b.',
    )
    return parser.parse_args()


def find_latest_pipeline_run_dir(pipeline_root: Path) -> Path:
    if not pipeline_root.exists():
        raise FileNotFoundError(f'Pipeline root not found: {pipeline_root}')
    candidates = [p for p in pipeline_root.iterdir() if p.is_dir() and p.name.startswith('run-')]
    latest = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if latest is None:
        raise FileNotFoundError(f'No run-* directories found under: {pipeline_root}')
    return latest.resolve()


def resolve_run_dir(args: argparse.Namespace) -> Path:
    if args.run_dir is not None:
        return args.run_dir.resolve()
    return find_latest_pipeline_run_dir(args.pipeline_root.resolve())


def validate_args(args: argparse.Namespace) -> None:
    if bool(args.old_prefix) != bool(args.new_prefix):
        raise ValueError('--old-prefix and --new-prefix must be provided together.')


def remove_target(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    else:
        path.unlink()


def prepare_target(path: Path, overwrite: bool) -> None:
    if path.exists():
        if not overwrite:
            raise FileExistsError(
                f'Target already exists: {path}. Re-run with --overwrite to replace it.'
            )
        remove_target(path)


def load_json(path: Path) -> dict[str, Any]:
    with path.open('r', encoding='utf-8') as f:
        payload = json.load(f)
    if not isinstance(payload, dict):
        raise ValueError(f'Expected JSON object: {path}')
    return payload


def choose_run_config(run_dir: Path) -> dict[str, Any]:
    run_summary_path = run_dir / 'run_summary.json'
    if not run_summary_path.exists():
        raise FileNotFoundError(f'run_summary.json not found: {run_summary_path}')
    run_summary = load_json(run_summary_path)
    outputs = run_summary.get('outputs') or {}
    if not isinstance(outputs, dict):
        outputs = {}

    pairs_jsonl = Path(
        str(outputs.get('pairs_jsonl') or (run_dir / '05_pair_trace_ds' / 'pairs.jsonl'))
    )
    paired_signatures_dir = Path(
        str(
            outputs.get('paired_signatures_dir')
            or (run_dir / '05_pair_trace_ds' / 'paired_signatures')
        )
    )
    slice_dir = Path(str(outputs.get('slice_dir') or (run_dir / '06_slices' / 'slice')))

    split_seed = int(run_summary.get('pair_split_seed', 1234))
    train_ratio = float(run_summary.get('pair_train_ratio', 0.8))

    config = {
        'run_summary_path': run_summary_path,
        'pairs_jsonl': pairs_jsonl,
        'paired_signatures_dir': paired_signatures_dir,
        'slice_dir': slice_dir,
        'split_seed': split_seed,
        'train_ratio': train_ratio,
    }
    return config


def validate_inputs(run_dir: Path, config: dict[str, Any]) -> None:
    if not run_dir.exists():
        raise FileNotFoundError(f'Run dir not found: {run_dir}')
    if not run_dir.is_dir():
        raise NotADirectoryError(f'Run dir is not a directory: {run_dir}')

    for key in ('pairs_jsonl', 'paired_signatures_dir', 'slice_dir'):
        path = config[key]
        if not isinstance(path, Path):
            raise ValueError(f'Invalid path for {key}: {path}')
        if not path.exists():
            raise FileNotFoundError(f'Required input not found for {key}: {path}')


def infer_suffix_from_output_dir(output_dir: Path) -> str:
    prefix = '07_dataset_export_'
    if output_dir.name.startswith(prefix):
        suffix = output_dir.name[len(prefix) :].strip()
        if suffix:
            return suffix
    return now_ts_compact()


def resolve_output_dir(*, run_dir: Path, args: argparse.Namespace, run_suffix: str) -> Path:
    if args.output_dir is not None:
        return args.output_dir.resolve()
    if args.only_07b:
        return run_dir / '07_dataset_export'
    return run_dir / f'07_dataset_export_{run_suffix}'


def validate_step07_output_dir(output_dir: Path) -> None:
    if not output_dir.exists():
        raise FileNotFoundError(f'Step 07 output dir not found: {output_dir}')
    if not output_dir.is_dir():
        raise NotADirectoryError(f'Step 07 output path is not a directory: {output_dir}')
    summary_json = output_dir / 'summary.json'
    split_manifest_json = output_dir / 'split_manifest.json'
    if not summary_json.exists():
        raise FileNotFoundError(f'Step 07 summary.json not found: {summary_json}')
    if not split_manifest_json.exists():
        raise FileNotFoundError(f'Step 07 split_manifest.json not found: {split_manifest_json}')


def load_module(module_path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f'Failed to load module spec from: {module_path}')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def rerun_step07(
    *, run_dir: Path, output_dir: Path, dedup_mode: str, overwrite: bool
) -> dict[str, Any]:
    config = choose_run_config(run_dir)
    validate_inputs(run_dir, config)

    prepare_target(output_dir, overwrite=overwrite)

    sys.path.insert(0, str(Path(PROJECT_HOME) / 'tools'))
    pipeline_module = load_module(
        Path(PROJECT_HOME) / 'tools' / 'run-epic001-pipeline.py', 'run_epic001_pipeline'
    )

    print(f'[Step07] run_dir={run_dir}')
    print(f'[Step07] output_dir={output_dir}')
    print(
        f'[Step07] split_seed={config["split_seed"]} '
        f'train_ratio={config["train_ratio"]} dedup_mode={dedup_mode}'
    )

    result = pipeline_module.export_dataset_from_pipeline(
        pairs_jsonl=config['pairs_jsonl'],
        paired_signatures_dir=config['paired_signatures_dir'],
        slice_dir=config['slice_dir'],
        output_dir=output_dir,
        split_seed=config['split_seed'],
        train_ratio=config['train_ratio'],
        dedup_mode=dedup_mode,
    )
    if not isinstance(result, dict):
        raise ValueError('Step 07 export returned a non-dict result.')
    return result


def rerun_step07b(
    *,
    run_dir: Path,
    dataset_export_dir: Path,
    run_suffix: str,
    dedup_mode: str,
    overwrite: bool,
    old_prefix: str | None,
    new_prefix: str | None,
) -> dict[str, Any]:
    pair_dir = run_dir / '05_pair_trace_ds'
    slice_root_dir = run_dir / '06_slices'
    signature_output_dir = pair_dir / f'train_patched_counterparts_signatures_{run_suffix}'
    slice_output_dir = slice_root_dir / f'train_patched_counterparts_{run_suffix}'
    output_pairs_jsonl = pair_dir / f'train_patched_counterparts_pairs_{run_suffix}.jsonl'
    selection_summary_json = (
        pair_dir / f'train_patched_counterparts_selection_summary_{run_suffix}.json'
    )

    cmd = [
        sys.executable,
        str(Path(PROJECT_HOME) / 'tools' / 'export_train_patched_counterparts.py'),
        '--run-dir',
        str(run_dir),
        '--dataset-export-dir',
        str(dataset_export_dir),
        '--signature-output-dir',
        str(signature_output_dir),
        '--slice-output-dir',
        str(slice_output_dir),
        '--output-pairs-jsonl',
        str(output_pairs_jsonl),
        '--selection-summary-json',
        str(selection_summary_json),
        '--dedup-mode',
        dedup_mode,
    ]
    if overwrite:
        cmd.append('--overwrite')
    if old_prefix and new_prefix:
        cmd.extend(['--old-prefix', old_prefix, '--new-prefix', new_prefix])

    print(f'[Step07b] command={" ".join(cmd)}')
    proc = subprocess.run(cmd, cwd=str(Path(PROJECT_HOME)))
    if proc.returncode != 0:
        raise RuntimeError(f'Step 07b failed with return code {proc.returncode}')

    summary_json = dataset_export_dir / 'train_patched_counterparts_summary.json'
    result = {
        'command': cmd,
        'returncode': proc.returncode,
        'signature_output_dir': str(signature_output_dir),
        'slice_output_dir': str(slice_output_dir),
        'output_pairs_jsonl': str(output_pairs_jsonl),
        'selection_summary_json': str(selection_summary_json),
        'summary_json': str(summary_json),
    }
    return result


def write_rerun_metadata(
    *,
    run_dir: Path,
    output_dir: Path,
    started_at: str,
    args: argparse.Namespace,
    run_step07: bool,
    run_step07b: bool,
    step07_result: dict[str, Any] | None,
    step07b_result: dict[str, Any] | None,
) -> Path:
    payload = {
        'started_at': started_at,
        'ended_at': now_iso_utc(),
        'run_dir': str(run_dir),
        'output_dir': str(output_dir),
        'dedup_mode': args.dedup_mode,
        'ran_step07': run_step07,
        'ran_step07b': run_step07b,
        'overwrite': bool(args.overwrite),
        'step07_result': step07_result,
        'step07b_result': step07b_result,
    }
    metadata_path = output_dir / 'rerun_step07_metadata.json'
    metadata_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    return metadata_path


def main() -> int:
    args = parse_args()
    validate_args(args)
    run_dir = resolve_run_dir(args)
    run_suffix = now_ts_compact()
    output_dir = resolve_output_dir(run_dir=run_dir, args=args, run_suffix=run_suffix)
    run_step07 = not args.only_07b
    run_step07b = not args.only_07
    step07b_suffix = infer_suffix_from_output_dir(output_dir)

    started_at = now_iso_utc()
    step07_result: dict[str, Any] | None = None
    if run_step07:
        step07_result = rerun_step07(
            run_dir=run_dir,
            output_dir=output_dir,
            dedup_mode=args.dedup_mode,
            overwrite=args.overwrite,
        )
    else:
        validate_step07_output_dir(output_dir)

    step07b_result: dict[str, Any] | None = None
    if run_step07b:
        step07b_result = rerun_step07b(
            run_dir=run_dir,
            dataset_export_dir=output_dir,
            run_suffix=step07b_suffix,
            dedup_mode=args.dedup_mode,
            overwrite=args.overwrite,
            old_prefix=args.old_prefix,
            new_prefix=args.new_prefix,
        )

    metadata_path = write_rerun_metadata(
        run_dir=run_dir,
        output_dir=output_dir,
        started_at=started_at,
        args=args,
        run_step07=run_step07,
        run_step07b=run_step07b,
        step07_result=step07_result,
        step07b_result=step07b_result,
    )

    result = {
        'run_dir': str(run_dir),
        'output_dir': str(output_dir),
        'dedup_mode': args.dedup_mode,
        'ran_step07': run_step07,
        'ran_step07b': run_step07b,
        'metadata_json': str(metadata_path),
        'step07_summary_json': str(output_dir / 'summary.json'),
        'step07_split_manifest_json': str(output_dir / 'split_manifest.json'),
        'step07b_summary_json': str(output_dir / 'train_patched_counterparts_summary.json')
        if run_step07b
        else None,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
