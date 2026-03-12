#!/usr/bin/env python3

import csv
import datetime
import json
import os
import re
from pathlib import Path
from typing import Iterable, Optional

import typer
from paths import INFER_RESULTS_DIR, RESULT_DIR


def find_latest_infer_run_dir(infer_results_dir: Path) -> Path:
    candidates: Iterable[Path] = (
        p for p in infer_results_dir.iterdir() if p.is_dir() and p.name.startswith('infer-')
    )
    latest = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if latest is None:
        raise typer.BadParameter(f'No infer-* directory found under: {infer_results_dir}')
    return latest


def resolve_infer_run_name(input_dir: Path, infer_run_name: Optional[str] = None) -> str:
    if infer_run_name is not None:
        if not infer_run_name.startswith('infer-'):
            raise typer.BadParameter(f'infer_run_name must start with "infer-": {infer_run_name}')
        return infer_run_name

    name = input_dir.name
    if not name.startswith('infer-'):
        raise typer.BadParameter(f'Input directory must be infer-* directory: {input_dir}')
    return name


def get_group_key(case_name: str) -> str:
    match = re.match(r'^(CWE\d+)_', case_name, flags=re.IGNORECASE)
    if match is None:
        return 'UNKNOWN'
    return match.group(1).upper()


def write_signature_stats_csv(non_empty_dir: Path, stats_map) -> None:
    stats_dir = non_empty_dir / 'analysis'
    os.makedirs(stats_dir, exist_ok=True)
    csv_path = stats_dir / 'signature_counts.csv'
    columns = [
        'group_key',
        'report_alarms_total',
        'bug_trace_nonempty',
        'signatures_written',
        'bug_trace_empty_skipped',
    ]
    total = {key: 0 for key in columns[1:]}

    with open(csv_path, 'w') as fp:
        writer = csv.writer(fp)
        writer.writerow(columns)

        for group_key in sorted(stats_map.keys()):
            row = stats_map[group_key]
            writer.writerow(
                [
                    group_key,
                    row['report_alarms_total'],
                    row['bug_trace_nonempty'],
                    row['signatures_written'],
                    row['bug_trace_empty_skipped'],
                ]
            )
            for key in total:
                total[key] += row[key]

        writer.writerow(
            [
                'TOTAL',
                total['report_alarms_total'],
                total['bug_trace_nonempty'],
                total['signatures_written'],
                total['bug_trace_empty_skipped'],
            ]
        )


def generate_signatures(
    input_dir: Path,
    output_root: Path = Path(RESULT_DIR) / 'signatures',
    infer_run_name: Optional[str] = None,
    signature_timestamp: Optional[str] = None,
) -> Path:
    infer_run_name = resolve_infer_run_name(input_dir, infer_run_name)
    if signature_timestamp is None:
        signature_timestamp = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')

    output_dir = output_root / infer_run_name / f'signature-{signature_timestamp}'
    non_empty_dir = output_dir / 'non_empty'
    flow_matched_dir = output_dir / 'flow_matched'
    os.makedirs(non_empty_dir, exist_ok=True)
    os.makedirs(flow_matched_dir, exist_ok=True)
    stats_map = {}

    for d in sorted(
        name for name in os.listdir(input_dir) if os.path.isdir(os.path.join(input_dir, name))
    ):
        if d == 'analysis':
            continue
        print('Generating signatures from {}'.format(d))
        report = '{}/{}/infer-out/report.json'.format(input_dir, d)
        if not os.path.exists(report):
            continue

        with open(report, 'r') as fp:
            j = json.load(fp)

        group_key = get_group_key(d)
        if group_key not in stats_map:
            stats_map[group_key] = {
                'report_alarms_total': 0,
                'bug_trace_nonempty': 0,
                'signatures_written': 0,
                'bug_trace_empty_skipped': 0,
            }

        taint_alarms = [a for a in j if a.get('bug_type') == 'TAINT_ERROR']
        stats_map[group_key]['report_alarms_total'] += len(taint_alarms)
        cnt = 1

        for alarm in taint_alarms:
            if len(alarm['bug_trace']) == 0:
                stats_map[group_key]['bug_trace_empty_skipped'] += 1
                continue

            stats_map[group_key]['bug_trace_nonempty'] += 1
            testcase_dir = non_empty_dir / d
            os.makedirs(testcase_dir, exist_ok=True)
            output_json = testcase_dir / f'{cnt}.json'
            with open(output_json, 'w') as fp:
                json.dump(alarm, fp, indent=2)
            stats_map[group_key]['signatures_written'] += 1
            cnt += 1

    write_signature_stats_csv(non_empty_dir, stats_map)
    return output_dir


def main(
    input_dir: Path = typer.Option(None, '--input-dir', help='Input infer-* directory'),
    output_root: Path = typer.Option(
        Path(RESULT_DIR) / 'signatures',
        '--output-root',
        help='Root directory for signatures output',
    ),
):
    if input_dir is None:
        input_dir = find_latest_infer_run_dir(Path(INFER_RESULTS_DIR))

    output_dir = generate_signatures(input_dir=input_dir, output_root=output_root)
    print(f'Signatures generated at: {output_dir}')


if __name__ == '__main__':
    typer.run(main)
