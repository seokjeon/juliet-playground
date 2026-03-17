from __future__ import annotations

import json
import xml.etree.ElementTree as ET

from tests.helpers import REPO_ROOT, load_module_from_path, write_text


def test_add_flow_tags_normalizes_tags_unifies_function_and_dedups_manifest_flaw(tmp_path):
    module = load_module_from_path(
        'test_stage02b_flow_partition_normalization',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    input_xml = tmp_path / 'manifest_with_comments.xml'
    output_xml = tmp_path / 'manifest_with_testcase_flows.xml'
    summary_json = tmp_path / 'summary.json'
    write_text(
        input_xml,
        """<?xml version='1.0' encoding='utf-8'?>
<container>
  <testcase>
    <file path="sample.c">
      <flaw line="10" name="CWE-X: synthetic flaw" />
      <comment_flaw line="10" function="bad" code="bad_stmt();" />
      <comment_fix line="20" function="goodG2B" code="fixed_stmt();" />
      <comment_flaw line="20" function="goodG2B" code="same_line_flaw_stmt();" />
    </file>
  </testcase>
</container>
""",
    )

    module.add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_xml,
        summary_json=summary_json,
        prune_single_child_flows=False,
    )

    root = ET.parse(output_xml).getroot()
    testcase = root.find('testcase')
    assert testcase is not None
    flows = {flow.attrib['type']: list(flow) for flow in testcase.findall('flow')}

    b2b_items = flows['b2b']
    assert len(b2b_items) == 1
    b2b_item = b2b_items[0]
    assert b2b_item.tag == 'flaw'
    assert b2b_item.attrib['origin'] == 'manifest_flaw'
    assert b2b_item.attrib['function'] == 'bad'
    assert b2b_item.attrib['name'] == 'CWE-X: synthetic flaw'
    assert 'inferred_function' not in b2b_item.attrib

    g2b_items = {
        (item.tag, item.attrib['origin'], item.attrib['function']) for item in flows['g2b']
    }
    assert g2b_items == {
        ('fix', 'comment_fix', 'goodG2B'),
        ('flaw', 'comment_flaw', 'goodG2B'),
    }

    summary = json.loads(summary_json.read_text(encoding='utf-8'))
    assert summary['tag_counts_in_flows'] == {'flaw': 2, 'fix': 1}
    assert summary['dedup_removed_comment_flaw_records'] == 1


def test_add_flow_tags_drops_same_line_mismatched_manifest_flaw_when_matching_flaw_exists(tmp_path):
    module = load_module_from_path(
        'test_stage02b_flow_partition_same_line_mismatch',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    input_xml = tmp_path / 'manifest_with_comments.xml'
    output_xml = tmp_path / 'manifest_with_testcase_flows.xml'
    write_text(
        input_xml,
        """<?xml version='1.0' encoding='utf-8'?>
<container>
  <testcase>
    <file path="CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01.c">
      <flaw line="10" name="CWE-121: Stack-based Buffer Overflow" />
      <flaw line="10" name="CWE-126: Buffer Over-read" />
      <comment_flaw
        line="10"
        function="CWE121_Stack_Based_Buffer_Overflow__char_type_overrun_memcpy_01_bad"
        code="bad_stmt();"
      />
    </file>
  </testcase>
</container>
""",
    )

    module.add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_xml,
        summary_json=None,
        prune_single_child_flows=False,
    )

    root = ET.parse(output_xml).getroot()
    testcase = root.find('testcase')
    assert testcase is not None
    flows = {flow.attrib['type']: list(flow) for flow in testcase.findall('flow')}

    b2b_items = flows['b2b']
    assert len(b2b_items) == 1
    assert b2b_items[0].attrib['origin'] == 'manifest_flaw'
    assert b2b_items[0].attrib['name'] == 'CWE-121: Stack-based Buffer Overflow'


def test_add_flow_tags_keeps_mismatch_only_manifest_flaw_when_no_matching_manifest_flaw_exists(
    tmp_path,
):
    module = load_module_from_path(
        'test_stage02b_flow_partition_mismatch_only',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    input_xml = tmp_path / 'manifest_with_comments.xml'
    output_xml = tmp_path / 'manifest_with_testcase_flows.xml'
    write_text(
        input_xml,
        """<?xml version='1.0' encoding='utf-8'?>
<container>
  <testcase>
    <file path="CWE121_Stack_Based_Buffer_Overflow__CWE135_01.c">
      <flaw line="10" name="CWE-135: Incorrect Calculation of Multi-Byte String Length" />
      <comment_flaw
        line="12"
        function="CWE121_Stack_Based_Buffer_Overflow__CWE135_01_bad"
        code="bad_stmt();"
      />
    </file>
  </testcase>
</container>
""",
    )

    module.add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_xml,
        summary_json=None,
        prune_single_child_flows=False,
    )

    root = ET.parse(output_xml).getroot()
    testcase = root.find('testcase')
    assert testcase is not None
    flows = {flow.attrib['type']: list(flow) for flow in testcase.findall('flow')}

    b2b_items = flows['b2b']
    assert {(item.attrib['origin'], item.attrib.get('name', '')) for item in b2b_items} == {
        ('manifest_flaw', 'CWE-135: Incorrect Calculation of Multi-Byte String Length'),
        ('comment_flaw', ''),
    }


def test_add_flow_tags_groups_numbered_vasink_variants_into_numbered_flows(tmp_path):
    module = load_module_from_path(
        'test_stage02b_flow_partition_vasink_numbering',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    input_xml = tmp_path / 'manifest_with_comments.xml'
    output_xml = tmp_path / 'manifest_with_testcase_flows.xml'
    write_text(
        input_xml,
        """<?xml version='1.0' encoding='utf-8'?>
<container>
  <testcase>
    <file path="sample.c">
      <comment_fix line="10" function="goodB2G1VaSinkG" code="fix_b2g1_vasinkg();" />
      <comment_fix line="20" function="goodB2G2VaSinkG" code="fix_b2g2_vasinkg();" />
      <comment_flaw line="30" function="goodG2B1VaSinkB" code="flaw_g2b1_vasinkb();" />
      <comment_flaw line="40" function="goodG2B2VaSinkB" code="flaw_g2b2_vasinkb();" />
      <comment_fix
        line="50"
        function="CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_22_goodB2G1_vasink"
        code="fix_b2g1_22b_vasink();"
      />
      <comment_fix
        line="60"
        function="CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_22_goodB2G2_vasink"
        code="fix_b2g2_22b_vasink();"
      />
    </file>
  </testcase>
</container>
""",
    )

    module.add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_xml,
        summary_json=None,
        prune_single_child_flows=False,
    )

    root = ET.parse(output_xml).getroot()
    testcase = root.find('testcase')
    assert testcase is not None
    flows = {
        flow.attrib['type']: {(item.tag, item.attrib['function']) for item in flow}
        for flow in testcase.findall('flow')
    }

    assert 'b2g' not in flows
    assert 'g2b' not in flows
    assert flows['b2g1'] == {
        ('fix', 'goodB2G1VaSinkG'),
        (
            'fix',
            'CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_22_goodB2G1_vasink',
        ),
    }
    assert flows['b2g2'] == {
        ('fix', 'goodB2G2VaSinkG'),
        (
            'fix',
            'CWE134_Uncontrolled_Format_String__char_connect_socket_vprintf_22_goodB2G2_vasink',
        ),
    }
    assert flows['g2b1'] == {('flaw', 'goodG2B1VaSinkB')}
    assert flows['g2b2'] == {('flaw', 'goodG2B2VaSinkB')}


def test_add_flow_tags_prunes_single_child_flow_by_default(tmp_path):
    module = load_module_from_path(
        'test_stage02b_flow_partition_single_child_default_prune',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    input_xml = tmp_path / 'manifest_with_comments.xml'
    output_xml = tmp_path / 'manifest_with_testcase_flows.xml'
    write_text(
        input_xml,
        """<?xml version='1.0' encoding='utf-8'?>
<container>
  <testcase>
    <file path="sample.c">
      <flaw line="10" name="CWE-X: synthetic flaw" />
      <comment_flaw line="10" function="bad" code="bad_stmt();" />
    </file>
  </testcase>
</container>
""",
    )

    module.add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_xml,
        summary_json=None,
    )

    root = ET.parse(output_xml).getroot()
    testcase = root.find('testcase')
    assert testcase is not None
    assert testcase.findall('flow') == []


def test_add_flow_tags_keeps_non_singleton_flow_when_single_child_pruning_is_enabled(tmp_path):
    module = load_module_from_path(
        'test_stage02b_flow_partition_non_singleton_survives_default_prune',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    input_xml = tmp_path / 'manifest_with_comments.xml'
    output_xml = tmp_path / 'manifest_with_testcase_flows.xml'
    write_text(
        input_xml,
        """<?xml version='1.0' encoding='utf-8'?>
<container>
  <testcase>
    <file path="sample.c">
      <comment_fix line="20" function="goodG2B" code="fixed_stmt();" />
      <comment_flaw line="20" function="goodG2B" code="same_line_flaw_stmt();" />
    </file>
  </testcase>
</container>
""",
    )

    module.add_flow_tags_to_testcase(
        input_xml=input_xml,
        output_xml=output_xml,
        summary_json=None,
    )

    root = ET.parse(output_xml).getroot()
    testcase = root.find('testcase')
    assert testcase is not None
    flows = {flow.attrib['type']: list(flow) for flow in testcase.findall('flow')}

    assert {
        (item.tag, item.attrib['origin'], item.attrib['function']) for item in flows['g2b']
    } == {
        ('fix', 'comment_fix', 'goodG2B'),
        ('flaw', 'comment_flaw', 'goodG2B'),
    }
