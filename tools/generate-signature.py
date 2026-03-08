#!/usr/bin/env python3

import csv
import datetime
import json
import os
from pathlib import Path
import re
from typing import Iterable

import typer

from paths import RESULT_DIR


def find_latest_juliet_result_dir(artifacts_dir: Path) -> Path:
    candidates: Iterable[Path] = (
        p for p in artifacts_dir.iterdir()
        if p.is_dir() and p.name.startswith('juliet-result-')
    )
    latest = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if latest is None:
        raise typer.BadParameter(
            f'No juliet-result-* directory found under: {artifacts_dir}')
    return latest


def get_group_key(case_name: str) -> str:
    match = re.match(r'^(CWE\d+)_', case_name, flags=re.IGNORECASE)
    if match is None:
        return 'UNKNOWN'
    return match.group(1).upper()


def write_signature_stats_csv(output_dir: Path, stats_map) -> None:
    stats_dir = output_dir / 'analysis'
    os.makedirs(stats_dir, exist_ok=True)
    csv_path = stats_dir / 'signature_counts.csv'
    columns = ['group_key', 'report_alarms_total', 'bug_trace_nonempty',
               'signatures_written', 'bug_trace_empty_skipped']
    total = {key: 0 for key in columns[1:]}

    with open(csv_path, 'w') as fp:
        writer = csv.writer(fp)
        writer.writerow(columns)

        for group_key in sorted(stats_map.keys()):
            row = stats_map[group_key]
            writer.writerow([
                group_key, row['report_alarms_total'],
                row['bug_trace_nonempty'], row['signatures_written'],
                row['bug_trace_empty_skipped']
            ])
            for key in total:
                total[key] += row[key]

        writer.writerow([
            'TOTAL', total['report_alarms_total'], total['bug_trace_nonempty'],
            total['signatures_written'], total['bug_trace_empty_skipped']
        ])


def generate_signatures(input_dir: Path,
                        output_root: Path = Path(RESULT_DIR) / 'signatures'
                        ) -> Path:
    timestamp = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')
    output_dir = output_root / f'signatures-result-{timestamp}'
    os.makedirs(output_dir, exist_ok=True)
    stats_map = {}

    for d in sorted(
            name for name in os.listdir(input_dir)
            if os.path.isdir(os.path.join(input_dir, name))):
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
                'bug_trace_empty_skipped': 0
            }

        stats_map[group_key]['report_alarms_total'] += len(j)
        cnt = 1

        for alarm in j:
            if len(alarm['bug_trace']) == 0:
                stats_map[group_key]['bug_trace_empty_skipped'] += 1
                continue

            stats_map[group_key]['bug_trace_nonempty'] += 1
            os.makedirs('{}/{}'.format(output_dir, d), exist_ok=True)
            output_json = '{}/{}/{}.json'.format(output_dir, d, cnt)
            with open(output_json, 'w') as fp:
                json.dump(alarm, fp, indent=2)
            stats_map[group_key]['signatures_written'] += 1
            cnt += 1

    write_signature_stats_csv(output_dir, stats_map)
    return output_dir


def main(input_dir: Path = typer.Option(
            None, '--input-dir', help='Input juliet-result-* directory'),
         output_root: Path = typer.Option(
            Path(RESULT_DIR) / 'signatures',
            '--output-root',
            help='Root directory for signatures-result-* output')):
    if input_dir is None:
        input_dir = find_latest_juliet_result_dir(Path(RESULT_DIR))

    output_dir = generate_signatures(input_dir=input_dir,
                                     output_root=output_root)
    print(f'Signatures generated at: {output_dir}')


if __name__ == '__main__':
    typer.run(main)
