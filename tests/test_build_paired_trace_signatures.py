from __future__ import annotations

import json
from pathlib import Path

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main


def test_stage05_cli_selects_longest_counterpart_and_records_leftover(tmp_path):
    module = load_module_from_path(
        'test_stage05_cli_module',
        REPO_ROOT / 'tools/run_pipeline.py',
    )

    signatures_dir = tmp_path / 'signatures'
    signatures_dir.mkdir()

    b2b_path = signatures_dir / 'b2b.json'
    selected_counterpart_path = signatures_dir / 'g2b.json'
    leftover_counterpart_path = signatures_dir / 'b2g.json'

    for path, payload in (
        (b2b_path, {'key': 'b2b', 'hash': 'hash-b2b', 'bug_trace': []}),
        (selected_counterpart_path, {'key': 'g2b', 'hash': 'hash-g2b', 'bug_trace': []}),
        (leftover_counterpart_path, {'key': 'b2g', 'hash': 'hash-b2g', 'bug_trace': []}),
    ):
        path.write_text(json.dumps(payload), encoding='utf-8')

    trace_jsonl = tmp_path / 'trace_flow_match_strict.jsonl'
    records = [
        {
            'testcase_key': 'CASE001',
            'trace_file': str(b2b_path),
            'best_flow_type': 'b2b',
            'bug_trace_length': 3,
            'procedure': 'bad',
        },
        {
            'testcase_key': 'CASE001',
            'trace_file': str(selected_counterpart_path),
            'best_flow_type': 'g2b',
            'bug_trace_length': 8,
            'procedure': 'goodG2B',
        },
        {
            'testcase_key': 'CASE001',
            'trace_file': str(leftover_counterpart_path),
            'best_flow_type': 'b2g',
            'bug_trace_length': 4,
            'procedure': 'goodB2G',
        },
    ]
    trace_jsonl.write_text(
        '\n'.join(json.dumps(record) for record in records) + '\n',
        encoding='utf-8',
    )

    output_dir = tmp_path / 'paired-output'

    assert (
        run_module_main(
            module,
            [
                'stage05',
                '--trace-jsonl',
                str(trace_jsonl),
                '--output-dir',
                str(output_dir),
            ],
        )
        == 0
    )

    pairs = [
        json.loads(line)
        for line in (output_dir / 'pairs.jsonl').read_text(encoding='utf-8').splitlines()
    ]
    assert len(pairs) == 1
    assert pairs[0]['counterpart_flow_type'] == 'g2b'

    leftovers = [
        json.loads(line)
        for line in (output_dir / 'leftover_counterparts.jsonl')
        .read_text(encoding='utf-8')
        .splitlines()
    ]
    assert leftovers == [
        {
            'testcase_key': 'CASE001',
            'related_pair_id': pairs[0]['pair_id'],
            'trace_file': str(leftover_counterpart_path),
            'best_flow_type': 'b2g',
            'bug_trace_length': 4,
            'procedure': 'goodB2G',
            'primary_file': None,
            'primary_line': None,
            'dropped_reason': 'not_selected_longest_bug_trace',
        }
    ]

    paired_case_dir = output_dir / 'paired_signatures' / 'CASE001'
    assert (paired_case_dir / 'b2b.json').exists()
    assert (paired_case_dir / 'g2b.json').exists()


def test_stage05_pair_id_is_stable_across_run_roots(tmp_path):
    module = load_module_from_path(
        'test_stage05_pair_id_stability',
        REPO_ROOT / 'tools/stage/stage05_pair_trace.py',
    )

    def build_dataset(root: Path) -> tuple[str, str]:
        signatures_dir = root / '03_signatures' / 'non_empty' / 'CASE001'
        signatures_dir.mkdir(parents=True, exist_ok=True)

        b2b_path = signatures_dir / '3.json'
        selected_counterpart_path = signatures_dir / '7.json'
        leftover_counterpart_path = signatures_dir / '9.json'
        for path, payload in (
            (b2b_path, {'key': 'case001|bad|TAINT_ERROR', 'hash': 'hash-b2b', 'bug_trace': []}),
            (
                selected_counterpart_path,
                {'key': 'case001|goodG2B|TAINT_ERROR', 'hash': 'hash-g2b', 'bug_trace': []},
            ),
            (
                leftover_counterpart_path,
                {'key': 'case001|goodB2G|TAINT_ERROR', 'hash': 'hash-b2g', 'bug_trace': []},
            ),
        ):
            path.write_text(json.dumps(payload), encoding='utf-8')

        trace_jsonl = root / '04_trace_flow' / 'trace_flow_match_strict.jsonl'
        trace_jsonl.parent.mkdir(parents=True, exist_ok=True)
        records = [
            {
                'testcase_key': 'CASE001',
                'trace_file': str(b2b_path),
                'best_flow_type': 'b2b',
                'bug_trace_length': 3,
                'procedure': 'bad',
            },
            {
                'testcase_key': 'CASE001',
                'trace_file': str(selected_counterpart_path),
                'best_flow_type': 'g2b',
                'bug_trace_length': 8,
                'procedure': 'goodG2B',
            },
            {
                'testcase_key': 'CASE001',
                'trace_file': str(leftover_counterpart_path),
                'best_flow_type': 'b2g',
                'bug_trace_length': 4,
                'procedure': 'goodB2G',
            },
        ]
        trace_jsonl.write_text(
            '\n'.join(json.dumps(record) for record in records) + '\n',
            encoding='utf-8',
        )

        output_dir = root / '05_pair_trace_ds'
        module.build_paired_trace_dataset(trace_jsonl=trace_jsonl, output_dir=output_dir)

        pairs = [
            json.loads(line)
            for line in (output_dir / 'pairs.jsonl').read_text(encoding='utf-8').splitlines()
            if line.strip()
        ]
        leftovers = [
            json.loads(line)
            for line in (output_dir / 'leftover_counterparts.jsonl')
            .read_text(encoding='utf-8')
            .splitlines()
            if line.strip()
        ]
        return pairs[0]['pair_id'], leftovers[0]['related_pair_id']

    first_pair_id, first_related_pair_id = build_dataset(tmp_path / 'run_a')
    second_pair_id, second_related_pair_id = build_dataset(tmp_path / 'run_b')

    assert first_pair_id == second_pair_id
    assert first_related_pair_id == second_related_pair_id


def test_stage05_record_sort_key_ignores_run_prefix():
    module = load_module_from_path(
        'test_stage05_record_sort_key_stability',
        REPO_ROOT / 'tools/stage/stage05_pair_trace.py',
    )

    left = module.StrictTraceRecord(
        testcase_key='CASE001',
        trace_file=Path('/tmp/run-a/signatures/CASE001/7.json'),
        best_flow_type='g2b',
        bug_trace_length=8,
        procedure='goodG2B',
        primary_file=None,
        primary_line=None,
        raw={},
    )
    right = module.StrictTraceRecord(
        testcase_key='CASE001',
        trace_file=Path('/tmp/run-b/signatures/CASE001/7.json'),
        best_flow_type='g2b',
        bug_trace_length=8,
        procedure='goodG2B',
        primary_file=None,
        primary_line=None,
        raw={},
    )

    assert module.record_sort_key(left) == module.record_sort_key(right)
