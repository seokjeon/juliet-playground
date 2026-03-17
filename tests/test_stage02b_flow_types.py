from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path


def test_flow_type_from_function_groups_numbered_sources_and_sinks():
    module = load_module_from_path(
        'test_stage02b_flow_types_module',
        REPO_ROOT / 'tools/stage/stage02b_flow.py',
    )

    cases = [
        ('b2g', 'goodB2G1', 'b2g1'),
        ('b2g', 'goodB2G1Source', 'b2g1'),
        ('b2g', 'goodB2G1Sink', 'b2g1'),
        ('b2g', 'CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21_goodB2G1Source', 'b2g1'),
        ('b2g', 'CWE121_Stack_Based_Buffer_Overflow__CWE129_fgets_21_goodB2G1Sink', 'b2g1'),
        ('b2g', 'goodB2G2Source', 'b2g2'),
        ('b2g', 'goodB2G2Sink', 'b2g2'),
        ('g2b', 'goodG2B1Source', 'g2b1'),
        ('g2b', 'goodG2B1Sink', 'g2b1'),
        (
            'g2b',
            'CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_43_goodG2B2Source',
            'g2b2',
        ),
        ('g2b', 'CWE121_Stack_Based_Buffer_Overflow__src_char_declare_cat_43_goodG2B2Sink', 'g2b2'),
        ('b2g', 'goodB2G', 'b2g'),
        ('b2g', 'goodB2GSource', 'b2g'),
        ('b2g', 'goodB2GSink', 'b2g'),
        ('g2b', 'goodG2B', 'g2b'),
        ('g2b', 'goodG2BSource', 'g2b'),
        ('b2b', 'badSink', 'b2b'),
    ]

    for base_flow, function_name, expected in cases:
        assert module.flow_type_from_function(base_flow, function_name) == expected
