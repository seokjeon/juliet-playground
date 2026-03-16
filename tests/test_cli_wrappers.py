from __future__ import annotations


def test_export_train_wrapper_delegates(load_tools_module, monkeypatch):
    module = load_tools_module('test_wrapper_export_train', 'export_train_patched_counterparts.py')

    monkeypatch.setattr(module._patched_counterparts, 'main', lambda: 11)

    assert module.main() == 11


def test_generate_signature_wrapper_delegates(load_tools_module, monkeypatch):
    module = load_tools_module('test_wrapper_generate_signature', 'generate-signature.py')

    monkeypatch.setattr(module._signature_stage, 'main', lambda **_kwargs: 13)

    assert module.main() == 13
