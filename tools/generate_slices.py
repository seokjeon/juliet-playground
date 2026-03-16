#!/usr/bin/env python3
from __future__ import annotations

from stage import slices as _slices

CPP_SUFFIXES = _slices.CPP_SUFFIXES
build_slice = _slices.build_slice
classify_suffix = _slices.classify_suffix
extract_std_bug_trace = _slices.extract_std_bug_trace
find_latest_pipeline_run_dir = _slices.find_latest_pipeline_run_dir
fix_path = _slices.fix_path
generate_slices = _slices.generate_slices
guess_output_suffix = _slices.guess_output_suffix
infer_run_dir_from_signature_db_dir = _slices.infer_run_dir_from_signature_db_dir
parse_args = _slices.parse_args
prepare_output_dir = _slices.prepare_output_dir
process_signature_db = _slices.process_signature_db
read_source_line = _slices.read_source_line
resolve_paths = _slices.resolve_paths
validate_args = _slices.validate_args


def main() -> int:
    return _slices.main()


if __name__ == '__main__':
    raise SystemExit(main())
