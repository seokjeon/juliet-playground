#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

from inventory_lib import extract_unique_code_fields


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Extract code values/frequency and build source-sink candidate call map.'
    )
    parser.add_argument(
        '--input-xml',
        type=Path,
        default=Path(
            'experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml'
        ),
    )
    parser.add_argument('--source-root', type=Path, default=Path('juliet-test-suite-v1.3/C'))
    parser.add_argument(
        '--output-dir',
        type=Path,
        default=Path('experiments/epic001a_code_field_inventory/outputs'),
    )
    parser.add_argument('--pulse-taint-config-output', type=Path, default=None)
    args = parser.parse_args()

    payload = extract_unique_code_fields(
        input_xml=args.input_xml,
        source_root=args.source_root,
        output_dir=args.output_dir,
        pulse_taint_config_output=args.pulse_taint_config_output,
    )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
