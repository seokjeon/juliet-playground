from __future__ import annotations

from pathlib import Path

from shared.jsonio import load_json
from shared.juliet_patch_taxonomy import (
    analyze_juliet_patch_taxonomy,
    export_juliet_patch_taxonomy,
)

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main, write_text

DIVIDE_BY_ZERO_CASE = """
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE369_Divide_by_Zero__int_zero_divide_01.c
*/
/*
 * BadSource: zero Fixed value of zero
 * GoodSource: Non-zero
 * Sinks: divide
 *    GoodSink: Check for zero before dividing
 *    BadSink : Divide a constant by data
 * Flow Variant: 01 Baseline
 */

#include "std_testcase.h"

void CWE369_Divide_by_Zero__int_zero_divide_01_bad()
{
    int data = 0;
    /* POTENTIAL FLAW: Possibly divide by zero */
    printIntLine(100 / data);
}

static void goodG2B()
{
    int data = -1;
    /* FIX: Use a value not equal to zero */
    data = 7;
    /* POTENTIAL FLAW: Possibly divide by zero */
    printIntLine(100 / data);
}

static void goodB2G()
{
    int data = 0;
    /* FIX: test for a zero denominator */
    if (data != 0)
    {
        printIntLine(100 / data);
    }
}
"""


FORMAT_STRING_CASE = """
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE134_Uncontrolled_Format_String__char_console_printf_82_goodB2G.cpp
*/
/*
 * BadSource: console Read data from the console
 * GoodSource: Fixed string
 * Sinks: printf
 *    GoodSink: Use a fixed string as the format control string
 *    BadSink : Use data as the format string
 * Flow Variant: 82 Data flow: data passed in a parameter to a virtual method called via a pointer
 */

#include "std_testcase.h"

class CWE134_Uncontrolled_Format_String__char_console_printf_82_goodB2G
{
public:
    void action(char * data);
};

void CWE134_Uncontrolled_Format_String__char_console_printf_82_goodB2G::action(char * data)
{
    /* FIX: Use a fixed format string */
    printf("%s\\n", data);
}
"""


POINTER_CASE = """
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_82_goodB2G.cpp
*/
/*
 * BadSource: Search for the character by incrementing the pointer variable
 * GoodSource: Search for the character without incrementing the pointer variable
 * Sinks: free
 *    GoodSink: Search for the character without incrementing the pointer variable
 *    BadSink : Free memory not at the start of the buffer
 * Flow Variant: 82 Data flow: data passed in a parameter to a virtual method called via a pointer
 */

#include "std_testcase.h"

class CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_82_goodB2G
{
public:
    void action(char * data);
};

void CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_82_goodB2G::action(char * data)
{
    /* FIX: Search for the character without incrementing the pointer variable */
    free(data);
}
"""


UNKNOWN_CASE = """
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE999_Example__mystery_case_01_goodB2G.c
*/
/*
 * BadSource: mystery source
 * GoodSource: mystery replacement
 * Sinks: custom
 *    GoodSink: Perform custom mitigation sequence
 *    BadSink : Perform unsafe custom sequence
 * Flow Variant: 01 Baseline
 */

#include "std_testcase.h"

static void goodB2G()
{
    /* FIX: Perform custom mitigation sequence */
    do_custom_safe_thing();
}
"""


RESOURCE_HANDLE_CASE = """
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE675_Duplicate_Operations_on_Resource__fopen_01.c
*/
/*
 * BadSource: Open a file using fopen()
 * GoodSource: Open a file using fopen()
 * Sinks: fclose
 *    GoodSink: Do nothing
 *    BadSink : Close the file using fclose()
 * Flow Variant: 01 Baseline
 */

#include "std_testcase.h"

static void goodG2B()
{
    /* FIX: Open, but do not close the file in the source */
    FILE * data = fopen("tmp.txt", "w+");
    (void)data;
}

static void goodB2G()
{
    /* FIX: Don't close the file in the sink */
}
"""


LIBRARY_PATH_CASE = """
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE114_Process_Control__w32_char_connect_socket_01.c
*/
/*
 * BadSource: Read data from a socket
 * GoodSource: Hard code the full pathname to the library
 * Sinks: LoadLibrary
 *    GoodSink: Specify the full pathname for the library
 *    BadSink : Load the library using the name specified in data
 * Flow Variant: 01 Baseline
 */

#include "std_testcase.h"

static void goodG2B()
{
    /* FIX: Specify the full pathname for the library */
    LoadLibraryA("C:\\\\Windows\\\\System32\\\\user32.dll");
}
"""


COMMAND_INJECTION_CASE = """
/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE78_OS_Command_Injection__char_console_system_01.c
*/
/*
 * BadSource: console Read input from the console
 * GoodSource: Fixed string
 * Sinks: system
 *    GoodSink: Fixed string
 *    BadSink : Execute command in data using system()
 * Flow Variant: 01 Baseline
 */

#include "std_testcase.h"

static void goodG2B()
{
    /* FIX: Append a fixed string to data (not user / external input) */
    system("ls");
}
"""


def seed_sample_juliet_root(tmp_path: Path) -> Path:
    root = tmp_path / 'juliet-test-suite-v1.3' / 'C' / 'testcases'
    write_text(
        root / 'CWE369_Divide_by_Zero' / 's01' / 'CWE369_Divide_by_Zero__int_zero_divide_01.c',
        DIVIDE_BY_ZERO_CASE,
    )
    write_text(
        root
        / 'CWE134_Uncontrolled_Format_String'
        / 's01'
        / 'CWE134_Uncontrolled_Format_String__char_console_printf_82_goodB2G.cpp',
        FORMAT_STRING_CASE,
    )
    write_text(
        root
        / 'CWE761_Free_Pointer_Not_at_Start_of_Buffer'
        / 's01'
        / 'CWE761_Free_Pointer_Not_at_Start_of_Buffer__char_file_82_goodB2G.cpp',
        POINTER_CASE,
    )
    write_text(
        root / 'CWE999_Example' / 's01' / 'CWE999_Example__mystery_case_01_goodB2G.c',
        UNKNOWN_CASE,
    )
    return root


def seed_refinement_cases(tmp_path: Path) -> Path:
    root = tmp_path / 'juliet-test-suite-v1.3' / 'C' / 'testcases'
    write_text(
        root
        / 'CWE675_Duplicate_Operations_on_Resource'
        / 's01'
        / 'CWE675_Duplicate_Operations_on_Resource__fopen_01.c',
        RESOURCE_HANDLE_CASE,
    )
    write_text(
        root
        / 'CWE114_Process_Control'
        / 's01'
        / 'CWE114_Process_Control__w32_char_connect_socket_01.c',
        LIBRARY_PATH_CASE,
    )
    write_text(
        root
        / 'CWE78_OS_Command_Injection'
        / 's01'
        / 'CWE78_OS_Command_Injection__char_console_system_01.c',
        COMMAND_INJECTION_CASE,
    )
    return root


def test_analyze_juliet_patch_taxonomy_extracts_direction_specific_records(tmp_path):
    juliet_root = seed_sample_juliet_root(tmp_path)

    records = analyze_juliet_patch_taxonomy(juliet_root)
    by_key = {
        (record.functional_variant_name, record.patch_direction): record for record in records
    }

    assert len(records) == 5

    divide_b2g = by_key[('int_zero_divide', 'goodB2G')]
    assert divide_b2g.primary_phrase_source == 'good_sink'
    assert divide_b2g.primary_phrase == 'Check for zero before dividing'
    assert divide_b2g.l1_code == 'input_state_validation'
    assert divide_b2g.l2_code == 'sink_check_for_zero_before_dividing'
    assert divide_b2g.fix_comment_count == 1
    assert divide_b2g.representative_code_snippets[0] == 'if (data != 0) {'

    divide_g2b = by_key[('int_zero_divide', 'goodG2B')]
    assert divide_g2b.primary_phrase_source == 'good_source'
    assert divide_g2b.primary_phrase == 'Non-zero'
    assert divide_g2b.l1_code == 'input_state_validation'
    assert divide_g2b.l2_code == 'source_non_zero'

    fmt_b2g = by_key[('char_console_printf', 'goodB2G')]
    assert fmt_b2g.l1_code == 'api_contract_and_call_safety'
    assert fmt_b2g.primary_phrase == 'Use a fixed string as the format control string'

    pointer_b2g = by_key[('char_file', 'goodB2G')]
    assert pointer_b2g.l1_code == 'pointer_position_and_reference'

    unknown_b2g = by_key[('mystery_case', 'goodB2G')]
    assert unknown_b2g.l1_code == 'other'


def test_export_juliet_patch_taxonomy_writes_expected_artifacts(tmp_path):
    juliet_root = seed_sample_juliet_root(tmp_path)
    output_dir = tmp_path / 'analysis'

    summary = export_juliet_patch_taxonomy(juliet_root=juliet_root, output_dir=output_dir)

    assert Path(summary['artifacts']['patch_records_jsonl']).exists()
    assert Path(summary['artifacts']['taxonomy_summary_csv']).exists()
    assert Path(summary['artifacts']['l1_summary_csv']).exists()
    assert Path(summary['artifacts']['flow_variant_matrix_csv']).exists()
    assert Path(summary['artifacts']['direction_summary_csv']).exists()
    assert Path(summary['artifacts']['cwe_l1_matrix_csv']).exists()
    assert Path(summary['artifacts']['taxonomy_definition_md']).exists()
    assert Path(summary['artifacts']['statistics_json']).exists()
    assert Path(summary['artifacts']['statistics_report_md']).exists()
    assert Path(summary['artifacts']['review_queue_csv']).exists()

    summary_json = load_json(output_dir / 'summary.json')
    assert summary_json['stats']['counts']['raw_patch_records'] == 5
    assert summary_json['stats']['counts']['deduped_patch_records'] == 5
    assert summary_json['stats']['counts']['taxonomy_l1_categories'] >= 4
    assert summary_json['stats']['l1_counts']['other'] == 1
    assert 'statistical_analysis' in summary_json['stats']

    statistics_json = load_json(output_dir / 'statistics.json')
    assert statistics_json['counts']['raw_patch_records'] == 5
    assert len(statistics_json['direction_summary']) == 2
    assert statistics_json['counts']['raw_to_dedup_ratio'] >= 1.0

    l1_summary_csv = (output_dir / 'l1_summary.csv').read_text(encoding='utf-8')
    assert 'deduped_share' in l1_summary_csv
    taxonomy_summary_csv = (output_dir / 'taxonomy_summary.csv').read_text(encoding='utf-8')
    assert 'deduped_share_overall' in taxonomy_summary_csv

    definition_text = (output_dir / 'taxonomy_definition.md').read_text(encoding='utf-8')
    assert 'Flow variants are kept as a separate analysis axis' in definition_text
    assert 'Other / review needed' in definition_text

    statistics_report = (output_dir / 'statistics_report.md').read_text(encoding='utf-8')
    assert 'Juliet Patch Taxonomy Statistical Analysis' in statistics_report

    review_csv = (output_dir / 'taxonomy_review_queue.csv').read_text(encoding='utf-8')
    assert 'mystery_case' in review_csv


def test_refined_taxonomy_classifies_resource_handles_and_library_paths(tmp_path):
    juliet_root = seed_refinement_cases(tmp_path)

    records = analyze_juliet_patch_taxonomy(juliet_root)
    by_key = {
        (record.functional_variant_name, record.patch_direction): record for record in records
    }

    assert by_key[('fopen', 'goodG2B')].l1_code == 'resource_handle_lifecycle'
    assert by_key[('fopen', 'goodB2G')].l1_code == 'resource_handle_lifecycle'
    assert (
        by_key[('w32_char_connect_socket', 'goodG2B')].l1_code
        == 'security_policy_and_configuration'
    )
    assert by_key[('char_console_system', 'goodG2B')].l2_label == 'Use fixed command string'


def test_analyze_juliet_patch_taxonomy_cli_runs_end_to_end(tmp_path):
    juliet_root = seed_sample_juliet_root(tmp_path)
    output_dir = tmp_path / 'cli-output'
    module = load_module_from_path(
        'test_analyze_juliet_patch_taxonomy_cli',
        REPO_ROOT / 'tools' / 'analyze_juliet_patch_taxonomy.py',
    )

    exit_code = run_module_main(
        module,
        [
            '--juliet-root',
            str(juliet_root),
            '--output-dir',
            str(output_dir),
            '--sample-per-type',
            '2',
        ],
    )

    assert exit_code == 0
    assert (output_dir / 'summary.json').exists()
    assert (output_dir / 'taxonomy_summary.csv').exists()
