# Repository Guidelines

This repository runs Infer on the Juliet C/C++ test suite and maintains the pipeline from signatures to paired traces, slices, and dataset exports. Treat this file as a map: use it to find the right code, docs, and validation commands, then prefer the smallest change that solves the task.

## Start Here
- Read `README.md` for local setup and common commands.
- Treat the `README.md` Workspace Map as the canonical description of the repository layout.
- Use `docs/pipeline-runbook.md` for pipeline behavior, `docs/artifacts.md` for output layout, `docs/rerun.md` for rerun workflows, and `docs/stage-contracts.md` for the current code-based stage contracts.
- For stage-specific logic, use `experiments/*/README.md` mainly for stages 01/02a/02b/04; for stages 03/05/06/07/07b, prefer `docs/stage-contracts.md` and the matching `tools/stage/*.py`.

## Repository Map
- `tools/`: user-facing CLI scripts such as `run_pipeline.py` and `compare-artifacts.py`.
- `tools/stage/`: importable stage implementations for pipeline steps and rerun/export workflows.
- `tools/shared/`: helper modules shared across stages and CLI entrypoints. Keep CLI wrappers thin and put reusable helper behavior here.
- `tests/`: unit and regression tests. `tests/golden/` contains stage-level golden fixtures and fixture update tooling.
- `docs/`: operator-facing docs and current contracts. Prefer these over old experiment notes when both exist.
- `juliet-test-suite-v1.3/`: Juliet input corpus. Actual source analysis typically starts under `juliet-test-suite-v1.3/C/`.
- `external/`: external-project input workspace. Common pattern: `external/<project>/inputs/{raw_code,build_targets.csv,manual_line_truth.csv}`.
- `cases/`: case-managed external vulnerability workspace. Common pattern:
  `cases/<project>__<CVE>/<track>/{repo,WORKLOG.md,trace_output,runs/inputs,runs/run-###}` where
  `track` is typically `vulnerable` or `patched`.
- `experiments/`: experiment notes, helper scripts, and analysis outputs. Includes EPIC001-derived dirs plus `epic002/`, `epic003/`, selected `CVE-*` dirs, and `!never_read!archive/` for historical notes.
- `config/`: committed configuration. Use `config/pulse-taint-config.json` for the common default, `config/CVE-*/` for project/experiment-specific variants, and `config/legacy/` for older archived configs.
- `artifacts/`: generated outputs only. Juliet sources live under `juliet-test-suite-v1.3/C/`.
  - `artifacts/pipeline-runs/`: Juliet pipeline run outputs.
  - `artifacts/external-runs/`: external-project fast-path outputs from `tools/run_external_trace_pipeline.py`.
    Canonical data handoff files usually live under `07_dataset_export/Real_Vul_data.csv` and
    `07_dataset_export/trace_row_manifest.jsonl`.
    The CLI contract is `<output-root>/<run-id>/`, but in practice this repo often groups runs as
    `artifacts/external-runs/<CVE-or-project>/<run-id>/`; `artifacts/external-runs/archive/` is a
    repository convention for historical runs.
  - `artifacts/external-build-audits/`: generated build-audit outputs for external projects such as the htcondor minimal-build workflow.

Use `AGENTS.md` as a concise navigation aid. When `README.md` and `AGENTS.md` overlap, follow `README.md` for the workspace map and keep `AGENTS.md` synchronized at the summary level.

## Tool Layout Rules
- Put **CLI entrypoints / wrappers / standalone utilities** in `tools/`.
- Put **pipeline step implementations** in `tools/stage/`.
- Put **shared helpers used by multiple stages or CLIs** in `tools/shared/`.

Use these decision rules:
- If the code directly implements one stage's contract, output schema, or runner behavior, it belongs in `tools/stage/`.
- If the code is reused by 2+ stages/CLIs and does not define a stage contract by itself, it belongs in `tools/shared/`.
- If the code is mainly there so a user can run a command, it belongs in `tools/`.

Do not:
- put generic helpers such as path/fs/json/signature/trace utilities into `tools/stage/`
- put stage-specific orchestration or output-producing logic into `tools/shared/`
- add new hyphenated module filenames except for CLI entrypoints

When in doubt:
- stage-specific beats shared
- shared must justify itself via reuse
- wrappers in `tools/` should stay thin

## Minimal Change Rule
Keep code changes minimal.

Do not:
- refactor unrelated code
- reorganize repository structure
- modify or delete generated artifacts unless requested

Also:
- preserve existing CLI flags, artifact paths, and output schemas unless the task explicitly requires a change
- keep fixes focused and avoid unrelated cleanup in the same change
- if this policy later needs many exceptions or examples, keep the summary here and split detailed rules into a separate policy document

## Setup & Development
- `python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt`
- `source .venv/bin/activate && pre-commit install`

## Pre-commit Hook
- This repo uses `pre-commit`, but Git hooks are local to each clone.
- Before assuming the hook is active, check whether `.git/hooks/pre-commit` exists.
- If it is missing, inform the user that the hook has not been installed for this clone and offer to run `source .venv/bin/activate && pre-commit install`.
- Do not install the hook automatically without explicit user approval.
- Do not assume `git clone` makes the hook active for other users.

## Validation
### Required for most Python changes
- `source .venv/bin/activate && ruff check .`
- `source .venv/bin/activate && pytest -q`

### Targeted validation
- `source .venv/bin/activate && pytest tests/test_<feature>.py -q`
- `source .venv/bin/activate && pytest tests/golden -q` for stage-output or fixture-sensitive changes
- `source .venv/bin/activate && python tests/golden/update_goldens.py --stage <stage>` only when expected outputs intentionally change

### Expensive / optional
- `source .venv/bin/activate && python tools/run_pipeline.py full 78` only when end-to-end pipeline verification is necessary

## Coding Style
- Python 3.9, 4-space indentation, 100-character lines, single quotes; `ruff format` is the formatter.
- Prefer `pathlib.Path`, explicit arguments, and type hints in new code.
- Use `snake_case` for functions, variables, modules, and tests. Keep hyphenated filenames only for CLI entrypoints.

## Testing & PR Notes
- Add unit tests as `tests/test_<feature>.py`.
- Add stage regressions as `tests/golden/test_stageXX_<name>.py`.
- Follow the existing commit style: `feat(compare): ...`, `test(cli): ...`, `docs(readme): ...`, `refactor(cli): ...`.
- PRs should list affected pipeline stages, validation commands, and any fixture or artifact changes.
