import os
import shutil

PROJECT_HOME = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
GLOBAL_RESULT_DIR = os.path.join('/data', 'pattern', 'result')

INFER_DIR = os.path.join(PROJECT_HOME, 'infer')
BUG_BENCH_DIR = os.path.join(PROJECT_HOME, 'bug-bench')
BENCHMARK_DIR = os.path.join(BUG_BENCH_DIR, 'benchmark')
RESULT_DIR = os.path.join(PROJECT_HOME, 'artifacts')
JULIET_TESTCASE_DIR = os.path.join(PROJECT_HOME, 'juliet-test-suite-v1.3', 'C',
                                   'testcases')
PULSE_TAINT_CONFIG = os.path.join(PROJECT_HOME, 'tools',
                                  'pulse-taint-config.from_juliet.json')

INFER_BIN = shutil.which('infer') or os.path.join(INFER_DIR, 'infer', 'bin',
                                                 'infer')
