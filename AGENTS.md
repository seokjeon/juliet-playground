# Repository Guidelines

## Project Structure & Module Organization
- Root contains licensing and minimal project metadata (`README.md`, `LICENSE`).
- Main content lives in `juliet-test-suite-v1.3/C/`.
  - `testcases/`: CWE-specific vulnerable/safe samples (e.g., `CWE476_NULL_Pointer_Dereference/`).
  - `testcasesupport/`: shared runtime helpers (`main_linux.cpp`, `io.c`, headers).
  - `doc/`: official Juliet user guide and changelog PDFs.
  - Top-level `Makefile` builds the aggregated Linux target (`Juliet1.3`).

## Build, Test, and Development Commands
Run from `juliet-test-suite-v1.3/C` unless noted.

- `make -j"$(nproc)"`  
  Builds `Juliet1.3` from all partial testcase objects.
- `make individuals`  
  Builds per-testcase executables (`*.out`) across CWE folders.
- `make -C testcases/CWE476_NULL_Pointer_Dereference individuals`  
  Builds one CWE family only (faster local validation).
- `make clean` (inside a CWE folder)  
  Removes local build artifacts (`*.o`, `*.out`, `CWE*` binary).

## Coding Style & Naming Conventions
- This repo tracks upstream Juliet generated sources; prefer **minimal diffs**.
- Preserve existing style in touched files (C/C++ braces and spacing are template-driven).
- Keep indentation consistent with surrounding code (usually 4 spaces in C/C++, tabs in Makefiles).
- Follow existing naming patterns:
  - Directories: `CWE<id>_<Name>`
  - Files/functions: `CWE<id>_...__<variant>_<flow>` with `good`/`bad` suffixes.

## Testing Guidelines
- No separate unit-test framework is configured; build success is the primary check.
- For changes, compile at least the affected CWE directory and preferably run `make individuals` there.
- If editing shared support files, run a full top-level `make` to catch cross-suite breakage.

## Commit & Pull Request Guidelines
- Follow existing commit style: short, imperative, prefix when helpful (e.g., `chore:`, `build:`).
- Keep each commit focused (e.g., one CWE family or one tooling change).
- PRs should include:
  - What changed and why
  - Exact build commands run
  - Scope (affected paths/CWEs)
  - Logs or screenshots only when troubleshooting unusual failures
