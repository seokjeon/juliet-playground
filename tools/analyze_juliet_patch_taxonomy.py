#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path

from shared.juliet_patch_taxonomy import export_juliet_patch_taxonomy, format_top_taxonomy_rows


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description='Analyze Juliet C/C++ patched counterparts and export a patch taxonomy report.'
    )
    parser.add_argument(
        '--juliet-root',
        type=Path,
        default=Path('juliet-test-suite-v1.3/C/testcases'),
        help='Root directory containing Juliet C/C++ testcase files.',
    )
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('experiments/juliet_patch_taxonomy/latest'),
        help='Directory to write taxonomy artifacts into.',
    )
    parser.add_argument(
        '--sample-per-type',
        type=int,
        default=3,
        help='How many representative examples to keep per taxonomy type in Markdown output.',
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    juliet_root = args.juliet_root.resolve()
    if not juliet_root.exists() or not juliet_root.is_dir():
        raise FileNotFoundError(f'Juliet testcase root not found: {juliet_root}')
    if args.sample_per_type < 1:
        raise ValueError('--sample-per-type must be >= 1')

    summary = export_juliet_patch_taxonomy(
        juliet_root=juliet_root,
        output_dir=args.output_dir.resolve(),
        sample_per_type=args.sample_per_type,
    )
    summary_csv = Path(summary['artifacts']['taxonomy_summary_csv'])
    print(f'Wrote taxonomy artifacts to {args.output_dir.resolve()}')
    print(format_top_taxonomy_rows(summary_csv))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
