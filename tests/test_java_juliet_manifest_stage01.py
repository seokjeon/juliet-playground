from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from tests.helpers import REPO_ROOT, load_module_from_path, write_text

JAVA_TESTCASE = """\
package juliet.testcases.CWE78_OS_Command_Injection;

public class CWE78_OS_Command_Injection__Environment_01 {
    public void bad() throws Throwable {
        String data;

        /* POTENTIAL FLAW: Read data from an environment variable */
        data = System.getenv("ADD");

        /* POTENTIAL FLAW: command injection */
        Runtime.getRuntime().exec(data);
    }

    private void goodG2B() throws Throwable {
        String data;

        /* FIX: Use a hardcoded string */
        data = "foo";

        /* POTENTIAL FLAW: command injection */
        Runtime.getRuntime().exec(data);
    }
}
"""


def test_generate_juliet_manifest_groups_java_subfiles(tmp_path):
    module = load_module_from_path(
        'test_generate_java_manifest_module',
        REPO_ROOT / 'tools/generate_juliet_manifest.py',
    )
    source_root = tmp_path / 'java' / 'juliet' / 'testcases'
    cwe_dir = source_root / 'CWE78_OS_Command_Injection'
    write_text(cwe_dir / 'CWE78_OS_Command_Injection__Environment_22a.java', JAVA_TESTCASE)
    write_text(cwe_dir / 'CWE78_OS_Command_Injection__Environment_22b.java', JAVA_TESTCASE)
    write_text(cwe_dir / 'CWE79_XSS__Servlet_01.java', JAVA_TESTCASE)

    output_xml = tmp_path / 'manifest.xml'
    result = module.build_manifest(
        source_root=source_root,
        output_xml=output_xml,
        suffixes={'.java'},
        cwes={'78'},
    )

    assert result['matched_files'] == 2
    root = ET.parse(output_xml).getroot()
    testcases = root.findall('testcase')
    assert len(testcases) == 1
    assert [file_elem.attrib['path'] for file_elem in testcases[0].findall('file')] == [
        'CWE78_OS_Command_Injection__Environment_22a.java',
        'CWE78_OS_Command_Injection__Environment_22b.java',
    ]


def test_stage01_scans_java_flaw_and_fix_comments(tmp_path):
    module = load_module_from_path(
        'test_stage01_java_manifest_module',
        REPO_ROOT / 'tools/stage/stage01_manifest.py',
    )
    if 'java' not in module.load_tree_sitter_parsers():
        pytest.skip('tree-sitter Java parser is not available')

    source_root = tmp_path / 'java' / 'juliet' / 'testcases'
    cwe_dir = source_root / 'CWE78_OS_Command_Injection'
    file_name = 'CWE78_OS_Command_Injection__Environment_01.java'
    write_text(cwe_dir / file_name, JAVA_TESTCASE)
    manifest_xml = tmp_path / 'manifest.xml'
    write_text(
        manifest_xml,
        f"""\
<?xml version="1.0" encoding="utf-8"?>
<container>
  <testcase>
    <file path="{file_name}" />
  </testcase>
</container>
""",
    )

    output_xml = tmp_path / 'manifest_with_comments.xml'
    result = module.scan_manifest_comments(
        manifest=manifest_xml,
        source_root=source_root,
        output_xml=output_xml,
    )

    assert result['scanned_files'] == 1
    root = ET.parse(output_xml).getroot()
    comments = [
        (child.tag, child.attrib['code'], child.attrib['function'])
        for child in root.iter()
        if child.tag in {'comment_flaw', 'comment_fix'}
    ]
    assert comments == [
        (
            'comment_flaw',
            'data = System.getenv("ADD");',
            'CWE78_OS_Command_Injection__Environment_01::bad',
        ),
        (
            'comment_flaw',
            'Runtime.getRuntime().exec(data);',
            'CWE78_OS_Command_Injection__Environment_01::bad',
        ),
        (
            'comment_fix',
            'data = "foo";',
            'CWE78_OS_Command_Injection__Environment_01::goodG2B',
        ),
        (
            'comment_flaw',
            'Runtime.getRuntime().exec(data);',
            'CWE78_OS_Command_Injection__Environment_01::goodG2B',
        ),
    ]


def test_stage02b_epic002_classifies_java_lowercase_source_helpers():
    module = load_module_from_path(
        'test_stage02b_epic002_java_role_module',
        REPO_ROOT / 'tools/stage/stage02b_epic002.py',
    )

    assert (
        module.classify_function_role('CWE78_OS_Command_Injection__Environment_21::bad_source')
        == 'source'
    )
    assert (
        module.classify_function_role('CWE78_OS_Command_Injection__Environment_51b::badSink')
        == 'sink'
    )
