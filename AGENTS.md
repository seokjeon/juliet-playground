# Repository Guidelines

## Project Structure
- `juliet-test-suite-v1.3/`: upstream Juliet corpus (read-only unless explicitly requested)
- `experiments/epicNNN_*`: experiment unit (`scripts/`, `inputs/`, `outputs/`, `README.md`)
- `tools/`: reusable scripts promoted from experiments
- `data/artifacts/`: intermediate artifacts/logs/verification outputs
- `data/final/`: finalized outputs (`manifest.xml`, `source.lst`, `sink.lst`)
- `docs/decisions/`: ADRs (source of truth for process/rules)

## Build Commands
Run from `juliet-test-suite-v1.3/C`:
- `make -j"$(nproc)"`
- `make individuals`
- `make -C testcases/CWE476_NULL_Pointer_Dereference individuals`

## Coding Style
- Preserve upstream formatting in Juliet files
- Python/Markdown: 4 spaces
- Makefiles: tabs
- Experiment directory naming: `epicNNN_short_name`

## Output Format Rule
- Output format is flexible by cycle (`JSONL/CSV/TSV/기타`)
- For trace extraction, JSONL is recommended with keys:
  `file`, `cwe`, `kind`, `line`, `evidence`

## Issue/PR Operating Rules (Summary)
- Use `.github/ISSUE_TEMPLATE` (`Epic / Story / Task`)
- One label only: `epic` or `story` or `task`
- Story completion = AC satisfied
- Task completion = output path + verification method
- Theme is managed in GitHub Project
- Epic is one experiment cycle; create Verify/Release Story first, then create Epic with both links
- Failure report path (if failed):
  `experiments/epicNNN_*/outputs/failure_report.md`
- Release note should include baseline commit SHA

## Canonical References (ADR)
- Work item hierarchy: `docs/decisions/0002-work-item-hierarchy-epic-story-task.md`
- Lifecycle and cycle operation: `docs/decisions/0003-development-lifecycle-and-cycle-scoping.md`
