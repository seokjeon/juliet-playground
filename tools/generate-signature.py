#!/usr/bin/env python3

import datetime
import json
import os
from pathlib import Path
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


def main(input_dir: Path = typer.Option(
            None, '--input-dir', help='Input juliet-result-* directory'),
         output_root: Path = typer.Option(
            Path(RESULT_DIR) / 'signatures',
            '--output-root',
            help='Root directory for signatures-result-* output'),
         taint_error_only: bool = typer.Option(
            True,
            '--taint-error-only/--all-issues',
            help='Export only TAINT_ERROR alarms (default: on)')):
    if input_dir is None:
        input_dir = find_latest_juliet_result_dir(Path(RESULT_DIR))

    timestamp = datetime.datetime.now().strftime('%Y.%m.%d-%H:%M:%S')
    output_dir = output_root / f'signatures-result-{timestamp}'
    os.makedirs(output_dir, exist_ok=True)

    for d in sorted(
            name for name in os.listdir(input_dir)
            if os.path.isdir(os.path.join(input_dir, name))):
        print('Generating signatures from {}'.format(d))
        report = '{}/{}/infer-out/report.json'.format(input_dir, d)
        if not os.path.exists(report):
            continue

        with open(report, 'r') as fp:
            j = json.load(fp)

        cnt = 1

        for alarm in j:
            if taint_error_only and alarm.get('bug_type') != 'TAINT_ERROR':
                continue

            if len(alarm['bug_trace']) == 0:
                continue

            os.makedirs('{}/{}'.format(output_dir, d), exist_ok=True)
            output_json = '{}/{}/{}.json'.format(output_dir, d, cnt)
            with open(output_json, 'w') as fp:
                json.dump(alarm, fp, indent=2)
            cnt += 1

    print(f'Signatures generated at: {output_dir}')


if __name__ == '__main__':
    typer.run(main)
