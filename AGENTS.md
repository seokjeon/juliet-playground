# Repository Guidelines

## Project Structure & Module Organization
- `juliet-test-suite-v1.3/` is the upstream Juliet C/C++ corpus. Treat it as **read-only** unless explicitly requested.
- `experiments/epicNNN_*` stores isolated trial runs. Each experiment should contain:
  - `scripts/` (experiment-only logic)
  - `inputs/` (experiment config/list files)
  - `outputs/` (raw outputs from that run)
  - `README.md` (hypothesis, command, findings)
- `tools/` is for promoted, reusable scripts validated in experiments.
- `data/manifests/` defines dataset scope/subsets.
- `data/interim/` stores reusable intermediate artifacts.
- `data/final/` stores finalized training/eval datasets.
- `docs/labeling_rules.md` contains source/sink/patch labeling rules.
- `docs/decisions/` stores ADR-style design decisions.

## Build, Test, and Development Commands
Run from `juliet-test-suite-v1.3/C` when building Juliet binaries.

- `make -j"$(nproc)"`: build aggregated `Juliet1.3` target.
- `make individuals`: build per-testcase executables (`*.out`).
- `make -C testcases/CWE476_NULL_Pointer_Dereference individuals`: build one CWE family only.

## Coding Style & Naming Conventions
- Preserve upstream formatting in Juliet files; keep diffs minimal.
- Use 4-space indentation in Python/Markdown and tabs in Makefiles.
- Experiment directories must follow `epicNNN_short_name`.

## Testing Guidelines
- No separate unit-test framework is required for this repo yet.
- Validate scripts on a small manifest subset first.
- For shared tool changes, run at least one end-to-end check producing `data/interim` output.

## Commit & Pull Request Guidelines
- Use concise conventional prefixes (`docs:`, `feat:`, `chore:`, `refactor:`).
- One logical change per commit.
- PRs should include: scope, run commands, affected paths, and sample output paths.

## Trace Output Contract
Use JSONL and keep required keys: `file`, `cwe`, `kind`, `line`, `evidence`.
Allowed `kind` values: `source`, `sink`, `patch`.

## Issue Tracking Rules
- Use `.github/ISSUE_TEMPLATE` templates for `Epic / Story / Task`.
- Label semantics:
  - `epic`: large goal/value item
  - `story`: user-value item (must link to one parent Epic)
  - `task`: implementation item (must link to one parent Story)
- Conventions:
  - Assign only one of `epic|story|task` per issue.
  - Story completion is based on Acceptance Criteria (AC).
  - Task completion requires output path + verification method.
