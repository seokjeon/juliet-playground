from __future__ import annotations

import json

from tests.golden.helpers import REPO_ROOT, load_module_from_path, prepare_workspace


def test_stage02a_code_inventory_contract(tmp_path):
    baseline_root, work_root = prepare_workspace(tmp_path)
    module = load_module_from_path(
        'test_stage02a_code_inventory_contract',
        REPO_ROOT / 'tools/stage/stage02a_taint.py',
    )

    output_dir = work_root / 'expected/02a_taint'
    pulse_config_path = output_dir / 'pulse-taint-config.json'
    result = module.extract_unique_code_fields(
        input_xml=baseline_root / 'expected/01_manifest/manifest_with_comments.xml',
        source_root=REPO_ROOT / 'juliet-test-suite-v1.3/C',
        output_dir=output_dir,
        pulse_taint_config_output=pulse_config_path,
    )

    macro_resolution_path = output_dir / 'function_name_macro_resolution.csv'
    summary_path = output_dir / 'summary.json'

    assert pulse_config_path.exists()
    assert macro_resolution_path.exists()
    assert summary_path.exists()
    assert macro_resolution_path.read_text(encoding='utf-8').strip()

    pulse_config = json.loads(pulse_config_path.read_text(encoding='utf-8'))
    assert set(pulse_config) == {'pulse-taint-sources', 'pulse-taint-sinks'}
    source_procedures = {row['procedure'] for row in pulse_config['pulse-taint-sources']}
    sink_procedures = {row['procedure'] for row in pulse_config['pulse-taint-sinks']}
    assert source_procedures == sink_procedures

    summary = json.loads(summary_path.read_text(encoding='utf-8'))
    assert set(summary) == {'artifacts', 'stats'}
    assert summary['artifacts']['pulse_taint_config'] == str(pulse_config_path)
    assert summary['artifacts']['function_name_macro_resolution_csv'] == str(macro_resolution_path)
    assert summary['artifacts']['summary_json'] == str(summary_path)
    assert summary['stats']['candidate_map_keys'] >= summary['stats']['keys_with_calls']
    assert summary['stats']['unique_function_names'] == len(source_procedures)
    assert result['artifacts']['pulse_taint_config'] == str(pulse_config_path)
