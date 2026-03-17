from __future__ import annotations

from tests.helpers import REPO_ROOT, load_module_from_path, run_module_main


def test_retrace_cli_defaults_to_pruning_single_child_flows(monkeypatch):
    module = load_module_from_path(
        'test_retrace_strict_trace_default_single_child_prune_flag',
        REPO_ROOT / 'tools/retrace_strict_trace.py',
    )
    captured: dict[str, object] = {}

    def fake_run_retrace_strict_trace(**kwargs):
        captured.update(kwargs)
        return {'artifacts': {}, 'stats': {}}

    monkeypatch.setattr(module, 'run_retrace_strict_trace', fake_run_retrace_strict_trace)

    result = run_module_main(module, ['run-demo'])

    assert result == 0
    assert captured['prune_single_child_flows'] is True


def test_retrace_cli_keep_single_child_flows_disables_pruning(monkeypatch):
    module = load_module_from_path(
        'test_retrace_strict_trace_keep_single_child_flag',
        REPO_ROOT / 'tools/retrace_strict_trace.py',
    )
    captured: dict[str, object] = {}

    def fake_run_retrace_strict_trace(**kwargs):
        captured.update(kwargs)
        return {'artifacts': {}, 'stats': {}}

    monkeypatch.setattr(module, 'run_retrace_strict_trace', fake_run_retrace_strict_trace)

    result = run_module_main(module, ['run-demo', '--keep-single-child-flows'])

    assert result == 0
    assert captured['prune_single_child_flows'] is False
