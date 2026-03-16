#!/usr/bin/env python3
from __future__ import annotations

from stage import patched_export as _patched_counterparts

build_train_patched_counterparts = _patched_counterparts.build_train_patched_counterparts
export_dataset = _patched_counterparts.export_dataset
find_latest_pipeline_run_dir = _patched_counterparts.find_latest_pipeline_run_dir
infer_run_dir_from_pair_dir = _patched_counterparts.infer_run_dir_from_pair_dir
parse_args = _patched_counterparts.parse_args
prepare_target = _patched_counterparts.prepare_target
process_signature_db = _patched_counterparts.process_signature_db
resolve_paths = _patched_counterparts.resolve_paths
validate_args = _patched_counterparts.validate_args


def main() -> int:
    return _patched_counterparts.main()


if __name__ == '__main__':
    raise SystemExit(main())
