#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
TOOLS_ROOT = REPO_ROOT / 'tools'
if str(TOOLS_ROOT) not in sys.path:
    sys.path.insert(0, str(TOOLS_ROOT))

from stage import stage01_manifest as _stage01_manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Scan manifest files and append comment_flaw/comment_fix tags.'
    )
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--output-xml', type=Path, required=True)
    args = parser.parse_args()

    payload = _stage01_manifest.scan_manifest_comments(
        manifest=args.manifest,
        source_root=args.source_root,
        output_xml=args.output_xml,
    )
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
