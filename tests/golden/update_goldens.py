#!/usr/bin/env python3
from __future__ import annotations

import argparse
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import xml.etree.ElementTree as ET
from contextlib import redirect_stdout
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from tests.golden.helpers import (  # noqa: E402
    DEFAULT_SOURCE_RUN,
    FIXTURE_ROOT,
    PATCHED_SOURCE_TESTCASE_KEYS,
    SELECTED_TESTCASE_KEYS,
    STRICT_ONLY_TESTCASE_KEYS,
    derive_testcase_key_from_file_name,
    deterministic_tokenizer_context,
    link_repo_source_tree,
    load_module_from_path,
    run_module_main,
    sanitize_tree_in_place,
)

SYNC_TARGETS = {
    '01': ['seed/manifest_subset.xml', 'expected/01_manifest'],
    '02a': ['seed/manifest_subset.xml', 'expected/02a_taint'],
    '02c': ['seed/manifest_subset.xml', 'expected/02c_flow'],
    '04': ['expected/03_signatures_non_empty', 'expected/04_trace_flow'],
    '05': ['expected/05_pair_trace_ds'],
    '06': ['expected/06_slices'],
    '07': ['expected/07_dataset_export'],
    '07b': [
        'expected/05_pair_trace_ds/train_patched_counterparts_pairs.jsonl',
        'expected/05_pair_trace_ds/train_patched_counterparts_selection_summary.json',
        'expected/05_pair_trace_ds/train_patched_counterparts_signatures',
        'expected/06_slices/train_patched_counterparts',
        'expected/07b_dataset_export',
    ],
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Regenerate committed golden fixtures from a source run.'
    )
    parser.add_argument(
        '--from-run',
        type=Path,
        default=DEFAULT_SOURCE_RUN,
        help='Pipeline run directory used as the source of curated fixture inputs.',
    )
    parser.add_argument(
        '--stage',
        choices=['all', '01', '02a', '02c', '04', '05', '06', '07', '07b'],
        default='all',
        help='Regenerate only the selected stage outputs (dependencies are still rebuilt in temp).',
    )
    return parser.parse_args()


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def load_pair_ids(path: Path) -> list[str]:
    pair_ids: list[str] = []
    for line in path.read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        pair_ids.append(str(obj['pair_id']))
    return pair_ids


def build_selection_manifest(
    source_run: Path, *, expected_primary_pair_ids: list[str], expected_patched_pair_ids: list[str]
) -> dict[str, object]:
    return {
        'baseline_run': str(source_run.resolve().relative_to(REPO_ROOT)),
        'baseline_cwe': 'CWE121',
        'selected_testcase_keys': SELECTED_TESTCASE_KEYS,
        'strict_only_testcase_keys': STRICT_ONLY_TESTCASE_KEYS,
        'expected_primary_pair_ids': expected_primary_pair_ids,
        'expected_patched_pair_ids': expected_patched_pair_ids,
        'patched_source_testcase_keys': PATCHED_SOURCE_TESTCASE_KEYS,
        'notes': {
            'coverage': [
                'stage04 strict flow coverage includes b2b/b2g1/b2g2/g2b/g2b1/g2b2',
                'stage05-07 include both .c and .cpp primary pairs',
                'stage07b patched export covers g2b/g2b1/g2b2',
            ]
        },
    }


def write_manifest_subset(input_manifest: Path, output_manifest: Path) -> None:
    tree = ET.parse(input_manifest)
    root = tree.getroot()
    subset_root = copy.deepcopy(root)

    for testcase in list(subset_root.findall('testcase')):
        keep = False
        for file_elem in testcase.findall('file'):
            testcase_key = derive_testcase_key_from_file_name(file_elem.attrib.get('path', ''))
            if testcase_key in SELECTED_TESTCASE_KEYS:
                keep = True
                break
        if not keep:
            subset_root.remove(testcase)

    output_manifest.parent.mkdir(parents=True, exist_ok=True)
    subset_tree = ET.ElementTree(subset_root)
    try:
        ET.indent(subset_tree, space='  ')
    except AttributeError:
        pass
    subset_tree.write(output_manifest, encoding='utf-8', xml_declaration=True)


def copy_signature_subset(source_run: Path, destination: Path) -> None:
    run_summary = json.loads((source_run / 'run_summary.json').read_text(encoding='utf-8'))
    signature_non_empty_dir = Path(run_summary['outputs']['stage03']['signature_non_empty_dir'])
    ensure_clean_dir(destination)
    for testcase_key in SELECTED_TESTCASE_KEYS:
        src = signature_non_empty_dir / testcase_key
        if not src.exists():
            raise FileNotFoundError(f'Signature dir not found for testcase: {src}')
        shutil.copytree(src, destination / testcase_key)


def _capture_stdout_json(fn) -> dict[str, object]:
    stdout = io.StringIO()
    with redirect_stdout(stdout):
        result = fn()
    if int(result or 0) != 0:
        raise RuntimeError(f'Stage command failed with exit code: {result}')
    output = stdout.getvalue().strip().splitlines()
    if not output:
        return {}
    return json.loads(output[-1])


def run_stage01(source_root: Path, temp_root: Path, manifest_subset: Path) -> None:
    module = load_module_from_path(
        'golden_stage01_scan_manifest',
        REPO_ROOT / 'experiments/epic001_manifest_comment_scan/scripts/scan_manifest_comments.py',
    )
    output_xml = temp_root / 'expected/01_manifest/manifest_with_comments.xml'
    summary_json = temp_root / 'expected/01_manifest/summary.stdout.json'
    payload = _capture_stdout_json(
        lambda: run_module_main(
            module,
            [
                '--manifest',
                str(manifest_subset),
                '--source-root',
                str(source_root),
                '--output-xml',
                str(output_xml),
            ],
        )
    )
    summary_json.parent.mkdir(parents=True, exist_ok=True)
    summary_json.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )


def run_stage02a(source_root: Path, temp_root: Path) -> None:
    module = load_module_from_path(
        'golden_stage02a_inventory',
        REPO_ROOT / 'tools/stage/stage02a_taint.py',
    )
    output_dir = temp_root / 'expected/02a_taint'
    ensure_clean_dir(output_dir)
    module.extract_unique_code_fields(
        input_xml=temp_root / 'expected/01_manifest/manifest_with_comments.xml',
        source_root=source_root,
        output_dir=output_dir,
        pulse_taint_config_output=output_dir / 'pulse-taint-config.json',
    )
    summary_path = output_dir / 'summary.json'
    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    summary['artifacts'] = {
        'pulse_taint_config': 'expected/02a_taint/pulse-taint-config.json',
        'function_name_macro_resolution_csv': 'expected/02a_taint/function_name_macro_resolution.csv',
        'summary_json': 'expected/02a_taint/summary.json',
    }
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )


def run_stage02c(temp_root: Path) -> None:
    module = load_module_from_path(
        'golden_stage02c_flow_partition',
        REPO_ROOT
        / 'experiments/epic001c_testcase_flow_partition/scripts/add_flow_tags_to_testcase.py',
    )
    output_dir = temp_root / 'expected/02c_flow'
    ensure_clean_dir(output_dir)
    result = run_module_main(
        module,
        [
            '--input-xml',
            str(temp_root / 'expected/01_manifest/manifest_with_comments.xml'),
            '--output-xml',
            str(output_dir / 'manifest_with_testcase_flows.xml'),
            '--summary-json',
            str(output_dir / 'summary.json'),
        ],
    )
    if result != 0:
        raise RuntimeError(f'Stage 02c failed: {result}')


def run_stage04(temp_root: Path) -> None:
    module = load_module_from_path(
        'golden_stage04_trace_flow',
        REPO_ROOT / 'experiments/epic001d_trace_flow_filter/scripts/filter_traces_by_flow.py',
    )
    output_dir = temp_root / 'expected/04_trace_flow'
    ensure_clean_dir(output_dir)
    result = run_module_main(
        module,
        [
            '--flow-xml',
            str(temp_root / 'expected/02c_flow/manifest_with_testcase_flows.xml'),
            '--signatures-dir',
            str(temp_root / 'expected/03_signatures_non_empty'),
            '--output-dir',
            str(output_dir),
        ],
    )
    if result != 0:
        raise RuntimeError(f'Stage 04 failed: {result}')


def run_stage05(temp_root: Path) -> None:
    module = load_module_from_path(
        'golden_stage05_pair_trace',
        REPO_ROOT / 'tools/stage/stage05_pair_trace.py',
    )
    output_dir = temp_root / 'expected/05_pair_trace_ds'
    ensure_clean_dir(output_dir)
    module.build_paired_trace_dataset(
        trace_jsonl=temp_root / 'expected/04_trace_flow/trace_flow_match_strict.jsonl',
        output_dir=output_dir,
        run_dir=temp_root / 'expected',
    )


def run_stage06(temp_root: Path) -> None:
    module = load_module_from_path(
        'golden_stage06_slices',
        REPO_ROOT / 'tools/stage/stage06_slices.py',
    )
    output_dir = temp_root / 'expected/06_slices'
    ensure_clean_dir(output_dir)
    module.generate_slices(
        signature_db_dir=temp_root / 'expected/05_pair_trace_ds/paired_signatures',
        output_dir=output_dir,
        run_dir=temp_root / 'expected',
    )


def run_stage07(temp_root: Path) -> None:
    pipeline_module = load_module_from_path(
        'golden_stage07_pipeline',
        REPO_ROOT / 'tools/run_pipeline.py',
    )
    output_dir = temp_root / 'expected/07_dataset_export'
    ensure_clean_dir(output_dir)
    old_cwd = Path.cwd()
    try:
        os.chdir(temp_root)
        with deterministic_tokenizer_context():
            pipeline_module.export_dataset_from_pipeline(
                pairs_jsonl=temp_root / 'expected/05_pair_trace_ds/pairs.jsonl',
                paired_signatures_dir=temp_root / 'expected/05_pair_trace_ds/paired_signatures',
                slice_dir=temp_root / 'expected/06_slices/slice',
                output_dir=output_dir,
                split_seed=1234,
                train_ratio=0.8,
                dedup_mode='row',
            )
    finally:
        os.chdir(old_cwd)


def run_stage07b(temp_root: Path) -> None:
    module = load_module_from_path(
        'golden_stage07b_export',
        REPO_ROOT / 'tools/stage/stage07b_patched_export.py',
    )

    pair_dir = temp_root / 'expected/05_pair_trace_ds'
    dataset_export_dir = temp_root / 'expected/07_dataset_export'
    stage07b_export_dir = temp_root / 'expected/07b_dataset_export'
    ensure_clean_dir(stage07b_export_dir)
    selected_train_pair_ids: list[str] = []
    for line in (pair_dir / 'pairs.jsonl').read_text(encoding='utf-8').splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj['testcase_key'] in PATCHED_SOURCE_TESTCASE_KEYS:
            selected_train_pair_ids.append(obj['pair_id'])
    split_manifest = {
        'counts': {
            'pairs_total': len(selected_train_pair_ids),
            'train_val': len(selected_train_pair_ids),
            'test': 0,
        },
        'pair_ids': {
            'train_val': selected_train_pair_ids,
            'test': [],
        },
    }
    (dataset_export_dir / 'split_manifest.json').write_text(
        json.dumps(split_manifest, ensure_ascii=False, indent=2) + '\n',
        encoding='utf-8',
    )
    with deterministic_tokenizer_context():
        result = module.export_patched_dataset(
            module.PatchedDatasetExportParams(
                run_dir=temp_root / 'expected',
                dedup_mode='row',
            )
        )
    for path in [
        result.dataset.csv_path,
        result.dataset.dedup_dropped_csv,
        result.dataset.normalized_slices_dir,
        result.dataset.token_counts_csv,
        result.dataset.token_distribution_png,
        result.dataset.split_manifest_json,
        result.dataset.summary_json,
    ]:
        destination = stage07b_export_dir / path.name
        sync_path(path, destination)


def sync_path(src: Path, dst: Path) -> None:
    if src.is_dir():
        if dst.exists():
            shutil.rmtree(dst)
        shutil.copytree(src, dst)
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def sync_fixture_tree(temp_root: Path, stage: str) -> None:
    FIXTURE_ROOT.mkdir(parents=True, exist_ok=True)
    if stage == 'all':
        if FIXTURE_ROOT.exists():
            shutil.rmtree(FIXTURE_ROOT)
        shutil.copytree(
            temp_root,
            FIXTURE_ROOT,
            ignore=shutil.ignore_patterns('juliet-test-suite-v1.3'),
            symlinks=True,
        )
        return

    (FIXTURE_ROOT / 'seed').mkdir(parents=True, exist_ok=True)
    sync_path(
        temp_root / 'seed/selection_manifest.json', FIXTURE_ROOT / 'seed/selection_manifest.json'
    )
    if stage in {'01', '02a', '02c'}:
        sync_path(temp_root / 'seed/manifest_subset.xml', FIXTURE_ROOT / 'seed/manifest_subset.xml')

    for relative in SYNC_TARGETS[stage]:
        sync_path(temp_root / relative, FIXTURE_ROOT / relative)


def main() -> int:
    args = parse_args()
    source_run = args.from_run.resolve()
    if not source_run.exists():
        raise FileNotFoundError(f'Source run not found: {source_run}')

    run_summary = json.loads((source_run / 'run_summary.json').read_text(encoding='utf-8'))
    input_manifest = Path(run_summary['inputs']['manifest'])
    source_root = Path(run_summary['inputs']['source_root'])

    if not input_manifest.exists():
        raise FileNotFoundError(f'Input manifest not found: {input_manifest}')
    if not source_root.exists():
        raise FileNotFoundError(f'Source root not found: {source_root}')

    with tempfile.TemporaryDirectory(prefix='golden-cwe121-') as tmpdir:
        temp_root = Path(tmpdir)
        (temp_root / 'seed').mkdir(parents=True, exist_ok=True)
        (temp_root / 'expected').mkdir(parents=True, exist_ok=True)
        link_repo_source_tree(temp_root)

        manifest_subset = temp_root / 'seed/manifest_subset.xml'
        write_manifest_subset(input_manifest, manifest_subset)

        run_stage01(source_root, temp_root, manifest_subset)
        run_stage02a(source_root, temp_root)
        run_stage02c(temp_root)
        copy_signature_subset(source_run, temp_root / 'expected/03_signatures_non_empty')
        run_stage04(temp_root)
        sanitize_tree_in_place(
            temp_root / 'expected/04_trace_flow',
            root_aliases=[
                (temp_root, ''),
                (REPO_ROOT, ''),
            ],
        )
        run_stage05(temp_root)
        sanitize_tree_in_place(
            temp_root / 'expected/05_pair_trace_ds',
            root_aliases=[
                (temp_root, ''),
                (REPO_ROOT, ''),
            ],
        )
        run_stage06(temp_root)
        run_stage07(temp_root)
        run_stage07b(temp_root)

        selection_manifest = build_selection_manifest(
            source_run,
            expected_primary_pair_ids=load_pair_ids(
                temp_root / 'expected/05_pair_trace_ds/pairs.jsonl'
            ),
            expected_patched_pair_ids=load_pair_ids(
                temp_root / 'expected/05_pair_trace_ds/train_patched_counterparts_pairs.jsonl'
            ),
        )
        (temp_root / 'seed/selection_manifest.json').write_text(
            json.dumps(selection_manifest, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8',
        )

        sanitize_tree_in_place(
            temp_root,
            root_aliases=[
                (temp_root, ''),
                (REPO_ROOT, ''),
            ],
        )
        sync_fixture_tree(temp_root, args.stage)

    print(
        json.dumps(
            {
                'fixture_root': str(FIXTURE_ROOT),
                'source_run': str(source_run),
                'stage': args.stage,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
