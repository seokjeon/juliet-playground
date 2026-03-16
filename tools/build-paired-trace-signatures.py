#!/usr/bin/env python3
from __future__ import annotations

from stage import pair_trace as _pair_trace

COUNTERPART_FLOW_TYPES = _pair_trace.COUNTERPART_FLOW_TYPES
StrictTraceRecord = _pair_trace.StrictTraceRecord
find_latest_pipeline_run_dir = _pair_trace.find_latest_pipeline_run_dir
infer_run_dir_from_trace_jsonl = _pair_trace.infer_run_dir_from_trace_jsonl
load_signature_payload = _pair_trace.load_signature_payload
load_strict_records = _pair_trace.load_strict_records
group_by_testcase = _pair_trace.group_by_testcase
make_pair_id = _pair_trace.make_pair_id
parse_args = _pair_trace.parse_args
prepare_output_dir = _pair_trace.prepare_output_dir
record_sort_key = _pair_trace.record_sort_key
resolve_paths = _pair_trace.resolve_paths
select_best_record = _pair_trace.select_best_record
signature_meta = _pair_trace.signature_meta
validate_args = _pair_trace.validate_args
build_paired_trace_dataset = _pair_trace.build_paired_trace_dataset


def main() -> int:
    return _pair_trace.main()


if __name__ == '__main__':
    raise SystemExit(main())
