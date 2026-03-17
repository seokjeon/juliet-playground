from __future__ import annotations

import json

from tests.golden.helpers import REPO_ROOT, load_module_from_path, prepare_workspace
from tests.helpers import write_text


def test_stage02a_flow_aware_splits_source_and_sink_from_classified_xml(tmp_path):
    stage02a_module = load_module_from_path(
        'test_stage02a_flow_aware_module',
        REPO_ROOT / 'tools/stage/stage02a_taint.py',
    )
    epic002_module = load_module_from_path(
        'test_stage02a_flow_aware_epic002_module',
        REPO_ROOT / 'tools/stage/stage02b_epic002.py',
    )

    baseline_root, work_root = prepare_workspace(tmp_path)
    classified_xml = work_root / 'expected/02b_flow/epic002/source_sink_classified.xml'
    epic002_module.write_classification_outputs(
        manifest_xml=baseline_root / 'expected/02c_flow/manifest_with_testcase_flows.xml',
        output_xml=classified_xml,
        exceptions_xml=work_root / 'expected/02b_flow/epic002/source_sink_exceptions.xml',
        summary_json=work_root / 'expected/02b_flow/epic002/summary.json',
    )

    output_dir = work_root / 'expected/02a_taint_flow_aware'
    pulse_config_path = output_dir / 'pulse-taint-config.json'
    result = stage02a_module.extract_unique_code_fields(
        input_xml=classified_xml,
        source_root=REPO_ROOT / 'juliet-test-suite-v1.3/C',
        output_dir=output_dir,
        pulse_taint_config_output=pulse_config_path,
    )

    pulse_config = json.loads(pulse_config_path.read_text(encoding='utf-8'))
    source_procedures = {row['procedure'] for row in pulse_config['pulse-taint-sources']}
    sink_procedures = {row['procedure'] for row in pulse_config['pulse-taint-sinks']}

    expected_source = {'fgets', 'memset'}
    expected_sink = {
        '_snprintf',
        '_snwprintf',
        'fgets',
        'snprintf',
        'strcat',
        'strlen',
        'strncat',
        'swprintf',
    }

    assert source_procedures == expected_source
    assert sink_procedures == expected_sink

    summary = json.loads((output_dir / 'summary.json').read_text(encoding='utf-8'))
    assert summary['stats']['unique_source_function_names'] == len(expected_source)
    assert summary['stats']['unique_sink_function_names'] == len(expected_sink)
    assert summary['stats']['unique_function_names'] == len(expected_source | expected_sink)
    assert summary['stats']['pulse_source_procedures'] == len(expected_source)
    assert summary['stats']['pulse_sink_procedures'] == len(expected_sink)
    assert result['artifacts']['pulse_taint_config'] == str(pulse_config_path)


def test_stage02a_flow_aware_ignores_roleless_and_uses_line_fallback(tmp_path):
    module = load_module_from_path(
        'test_stage02a_flow_aware_manual_module',
        REPO_ROOT / 'tools/stage/stage02a_taint.py',
    )

    source_root = tmp_path / 'juliet' / 'C'
    testcase_dir = source_root / 'testcases' / 'CWE999_Test'
    source_file = testcase_dir / 'CWE999_Test__simple_01.c'
    write_text(
        source_file,
        '\n'.join(
            [
                '#include <stdio.h>',
                'void demo(void) {',
                '  source_call();',
                '  sink_call();',
                '  ignored_call();',
                '}',
                '',
            ]
        ),
    )

    input_xml = tmp_path / 'source_sink_classified.xml'
    write_text(
        input_xml,
        '\n'.join(
            [
                '<manifest>',
                '  <testcase>',
                '    <file path="CWE999_Test__simple_01.c" />',
                '    <flow type="b2b">',
                '      <flaw line="3" file="CWE999_Test__simple_01.c" role="source" />',
                '      <fix line="4" file="CWE999_Test__simple_01.c" code="sink_call();" role="sink" />',
                '      <fix line="5" file="CWE999_Test__simple_01.c" code="ignored_call();" />',
                '    </flow>',
                '  </testcase>',
                '</manifest>',
                '',
            ]
        ),
    )

    output_dir = tmp_path / '02a_taint'
    pulse_config_path = output_dir / 'pulse-taint-config.json'
    module.extract_unique_code_fields(
        input_xml=input_xml,
        source_root=source_root,
        output_dir=output_dir,
        pulse_taint_config_output=pulse_config_path,
    )

    pulse_config = json.loads(pulse_config_path.read_text(encoding='utf-8'))
    source_procedures = {row['procedure'] for row in pulse_config['pulse-taint-sources']}
    sink_procedures = {row['procedure'] for row in pulse_config['pulse-taint-sinks']}

    assert source_procedures == {'source_call'}
    assert sink_procedures == {'sink_call'}
    assert 'ignored_call' not in source_procedures | sink_procedures

    summary = json.loads((output_dir / 'summary.json').read_text(encoding='utf-8'))
    assert summary['stats']['total_code_entries'] == 2
    assert summary['stats']['candidate_map_keys'] == 2
    assert summary['stats']['keys_with_calls'] == 2
    assert summary['stats']['unique_source_function_names'] == 1
    assert summary['stats']['unique_sink_function_names'] == 1
