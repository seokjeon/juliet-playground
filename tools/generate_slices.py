#!/usr/bin/env python3
"""
Signature-style JSON 디렉터리로부터 bug_trace를 읽어 슬라이스 파일을 생성한다.

기본 동작:
- --signature-db-dir 미지정 시 최신 pipeline run의
  05_pair_trace_ds/paired_signatures 를 사용
- --output-dir 미지정 시 같은 run 아래 06_slices/ 를 사용
- 생성된 슬라이스는 <output-dir>/slice/ 아래 저장
- bug_trace 가 list[dict] 이면 그대로 사용
- bug_trace 가 jagged list[list[dict]] 이면 가장 긴 서브트레이스를 사용
- 출력 확장자는 trace/source path 기준으로 .c 또는 .cpp 로 유지
"""

from __future__ import annotations

import argparse
import json
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

from paths import RESULT_DIR

CPP_SUFFIXES = {".cpp", ".cc", ".cxx", ".c++"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate source slices from paired signature JSON files.")
    parser.add_argument(
        "--signature-db-dir",
        type=Path,
        default=None,
        help=(
            "Input directory containing testcase subdirectories with JSON files. "
            "If omitted, use the latest pipeline run's 05_pair_trace_ds/paired_signatures."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Output stage directory. If omitted and the input dir is inside a pipeline run, "
            "defaults to <run_dir>/06_slices."
        ),
    )
    parser.add_argument(
        "--pipeline-root",
        type=Path,
        default=Path(RESULT_DIR) / "pipeline-runs",
        help="Root directory containing run-* pipeline outputs.",
    )
    parser.add_argument(
        "--old-prefix",
        type=str,
        default=None,
        help="Optional old path prefix to rewrite inside bug_trace filenames.",
    )
    parser.add_argument(
        "--new-prefix",
        type=str,
        default=None,
        help="Optional new path prefix used with --old-prefix.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output-dir if it already exists and is non-empty.",
    )
    return parser.parse_args()


def find_latest_pipeline_run_dir(pipeline_root: Path) -> Path:
    if not pipeline_root.exists():
        raise FileNotFoundError(f"Pipeline root not found: {pipeline_root}")
    candidates = [p for p in pipeline_root.iterdir() if p.is_dir() and p.name.startswith("run-")]
    latest = max(candidates, key=lambda p: p.stat().st_mtime, default=None)
    if latest is None:
        raise FileNotFoundError(f"No run-* directories found under: {pipeline_root}")
    return latest


def infer_run_dir_from_signature_db_dir(signature_db_dir: Path) -> Path | None:
    if signature_db_dir.name != "paired_signatures":
        return None
    if signature_db_dir.parent.name != "05_pair_trace_ds":
        return None
    return signature_db_dir.parent.parent


def resolve_paths(args: argparse.Namespace) -> tuple[Path, Path, Path, Path | None]:
    if args.signature_db_dir is None:
        run_dir = find_latest_pipeline_run_dir(args.pipeline_root.resolve())
        signature_db_dir = run_dir / "05_pair_trace_ds" / "paired_signatures"
    else:
        signature_db_dir = args.signature_db_dir.resolve()
        run_dir = infer_run_dir_from_signature_db_dir(signature_db_dir)

    if args.output_dir is None:
        if run_dir is None:
            raise ValueError(
                "--output-dir is required when --signature-db-dir is outside the standard pipeline layout."
            )
        output_dir = run_dir / "06_slices"
    else:
        output_dir = args.output_dir.resolve()

    slice_dir = output_dir / "slice"
    return signature_db_dir, output_dir, slice_dir, run_dir


def validate_args(args: argparse.Namespace, signature_db_dir: Path) -> None:
    if not signature_db_dir.exists():
        raise FileNotFoundError(f"Signature DB dir not found: {signature_db_dir}")
    if not signature_db_dir.is_dir():
        raise NotADirectoryError(f"Signature DB dir is not a directory: {signature_db_dir}")
    if bool(args.old_prefix) != bool(args.new_prefix):
        raise ValueError("--old-prefix and --new-prefix must be provided together.")


def prepare_output_dir(output_dir: Path, overwrite: bool) -> None:
    if output_dir.exists():
        if not overwrite:
            existing = list(output_dir.iterdir())
            if existing:
                raise FileExistsError(
                    f"Output directory already exists and is not empty: {output_dir}. "
                    f"Re-run with --overwrite to replace its contents."
                )
        else:
            shutil.rmtree(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)


def fix_path(original_path: str, old_prefix: str | None, new_prefix: str | None) -> str:
    if old_prefix and new_prefix and original_path.startswith(old_prefix):
        return original_path.replace(old_prefix, new_prefix, 1)
    return original_path


def read_source_line(filepath: Path, line_number: int) -> str | None:
    try:
        with filepath.open("r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def extract_std_bug_trace(bug_trace: Any) -> list[dict[str, Any]]:
    if not isinstance(bug_trace, list) or not bug_trace:
        return []
    first = bug_trace[0]
    if isinstance(first, dict):
        return [node for node in bug_trace if isinstance(node, dict)]
    if isinstance(first, list):
        valid_lists = [sub for sub in bug_trace if isinstance(sub, list)]
        if not valid_lists:
            return []
        selected = max(valid_lists, key=len)
        return [node for node in selected if isinstance(node, dict)]
    return []


def classify_suffix(path_like: str | None) -> str | None:
    if not path_like:
        return None
    suffix = Path(path_like).suffix.lower()
    if suffix == ".c":
        return ".c"
    if suffix in CPP_SUFFIXES:
        return ".cpp"
    return None


def guess_output_suffix(data: dict[str, Any], std_bug_trace: list[dict[str, Any]]) -> str:
    candidates: list[str | None] = [data.get("file")]
    if data.get("primary_file"):
        candidates.append(data.get("primary_file"))
    for node in std_bug_trace:
        candidates.append(node.get("filename"))
    for candidate in candidates:
        suffix = classify_suffix(candidate)
        if suffix:
            return suffix
    return ".c"


def build_slice(std_bug_trace: list[dict[str, Any]], old_prefix: str | None,
                new_prefix: str | None) -> tuple[str | None, str | None]:
    slice_lines: list[str] = []
    seen: set[tuple[str, int]] = set()

    for node in std_bug_trace:
        filename = node.get("filename")
        line_number = int(node.get("line_number", 0) or 0)
        if not filename or line_number <= 0:
            return None, "invalid_trace_node"

        fixed_path = fix_path(str(filename), old_prefix, new_prefix)
        key = (fixed_path, line_number)
        if key in seen:
            continue
        seen.add(key)

        source_line = read_source_line(Path(fixed_path), line_number)
        if source_line is None:
            return None, "missing_source_line"
        slice_lines.append(source_line)

    return "".join(slice_lines), None


def process_signature_db(signature_db_dir: Path, slice_dir: Path, old_prefix: str | None,
                         new_prefix: str | None) -> dict[str, Any]:
    slice_dir.mkdir(parents=True, exist_ok=True)

    testcase_dirs = sorted(
        d for d in signature_db_dir.iterdir()
        if d.is_dir()
    )

    total_slices = 0
    errors = 0
    counters = Counter()
    suffix_counter = Counter()

    for testcase_dir in testcase_dirs:
        counters["testcase_dirs_total"] += 1
        json_files = sorted(p for p in testcase_dir.iterdir() if p.is_file() and p.suffix == ".json")
        for json_path in json_files:
            counters["json_files_total"] += 1
            try:
                data = json.loads(json_path.read_text(encoding="utf-8"))
                bug_trace = data.get("bug_trace", [])
                std_bug_trace = extract_std_bug_trace(bug_trace)
                if not std_bug_trace:
                    counters["skipped_empty_bug_trace"] += 1
                    continue

                slice_content, skip_reason = build_slice(std_bug_trace, old_prefix, new_prefix)
                if slice_content is None:
                    counters[f"skipped_{skip_reason}"] += 1
                    continue

                suffix = guess_output_suffix(data, std_bug_trace)
                suffix_counter[suffix] += 1
                output_filename = f"slice_{testcase_dir.name}_{json_path.stem}{suffix}"
                output_path = slice_dir / output_filename
                output_path.write_text(slice_content, encoding="utf-8")
                total_slices += 1
                counters["generated"] += 1
            except Exception as exc:
                print(f"[ERROR] {json_path}: {exc}")
                errors += 1
                counters["errors"] += 1

    return {
        "signature_db_dirs_total": len(testcase_dirs),
        "total_slices": total_slices,
        "errors": errors,
        "counts": dict(counters),
        "slice_extension_counts": dict(suffix_counter),
    }


def main() -> int:
    args = parse_args()
    signature_db_dir, output_dir, slice_dir, run_dir = resolve_paths(args)
    validate_args(args, signature_db_dir)
    prepare_output_dir(output_dir, args.overwrite)

    summary = process_signature_db(
        signature_db_dir=signature_db_dir,
        slice_dir=slice_dir,
        old_prefix=args.old_prefix,
        new_prefix=args.new_prefix,
    )

    summary_payload = {
        "signature_db_dir": str(signature_db_dir),
        "output_dir": str(output_dir),
        "slice_dir": str(slice_dir),
        "run_dir": str(run_dir) if run_dir else None,
        "old_prefix": args.old_prefix,
        "new_prefix": args.new_prefix,
        **summary,
    }
    summary_path = output_dir / "summary.json"
    summary_path.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary_payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
