#!/usr/bin/env python3
from __future__ import annotations

from stage import trace_flow as _trace_flow

FlowPoint = _trace_flow.FlowPoint
TARGET_TAGS = _trace_flow.TARGET_TAGS
build_trace_line_set = _trace_flow.build_trace_line_set
choose_best_flow = _trace_flow.choose_best_flow
derive_testcase_key_from_file_name = _trace_flow.derive_testcase_key_from_file_name
filter_traces_by_flow = _trace_flow.filter_traces_by_flow
load_flow_index = _trace_flow.load_flow_index
match_trace_to_flows = _trace_flow.match_trace_to_flows
resolve_signatures_dir = _trace_flow.resolve_signatures_dir


def main() -> int:
    return _trace_flow.main()


if __name__ == '__main__':
    raise SystemExit(main())
