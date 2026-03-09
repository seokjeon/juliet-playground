#!/usr/bin/env python3
"""
슬라이스 파일들을 CodeBERT 토크나이저로 토큰화하고,
scienceplots 스타일의 분포 그래프를 생성한다.

기본 동작:
- --slice-dir 미지정 시 최신 pipeline run의 06_slices/slice 사용
- --output-dir 미지정 시 같은 run 아래 07_tokenized/ 사용
- .c 와 .cpp 파일을 모두 처리
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import scienceplots  # noqa: F401
from transformers import RobertaTokenizer

from paths import RESULT_DIR

ALLOWED_SUFFIXES = {".c", ".cpp"}
MAX_LENGTH = 512
CONTENT_TOKEN_LIMIT = MAX_LENGTH - 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Tokenize generated slice files and plot token count distribution.")
    parser.add_argument(
        "--slice-dir",
        type=Path,
        default=None,
        help=(
            "Directory containing generated slice files. If omitted, use the latest "
            "pipeline run's 06_slices/slice."
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help=(
            "Output directory for CSV/plot/summary. If omitted and --slice-dir is inside "
            "a pipeline run, defaults to <run_dir>/07_tokenized."
        ),
    )
    parser.add_argument(
        "--pipeline-root",
        type=Path,
        default=Path(RESULT_DIR) / "pipeline-runs",
        help="Root directory containing run-* pipeline outputs.",
    )
    parser.add_argument(
        "--model-name",
        type=str,
        default="microsoft/codebert-base",
        help="Tokenizer model name passed to transformers.",
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


def infer_run_dir_from_slice_dir(slice_dir: Path) -> Path | None:
    if slice_dir.name != "slice":
        return None
    if slice_dir.parent.name != "06_slices":
        return None
    return slice_dir.parent.parent


def resolve_paths(args: argparse.Namespace) -> tuple[Path, Path, Path | None]:
    if args.slice_dir is None:
        run_dir = find_latest_pipeline_run_dir(args.pipeline_root.resolve())
        slice_dir = run_dir / "06_slices" / "slice"
    else:
        slice_dir = args.slice_dir.resolve()
        run_dir = infer_run_dir_from_slice_dir(slice_dir)

    if args.output_dir is None:
        if run_dir is None:
            raise ValueError(
                "--output-dir is required when --slice-dir is outside the standard pipeline layout."
            )
        output_dir = run_dir / "07_tokenized"
    else:
        output_dir = args.output_dir.resolve()

    return slice_dir, output_dir, run_dir


def validate_inputs(slice_dir: Path) -> None:
    if not slice_dir.exists():
        raise FileNotFoundError(f"Slice directory not found: {slice_dir}")
    if not slice_dir.is_dir():
        raise NotADirectoryError(f"Slice directory is not a directory: {slice_dir}")


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


def load_tokenizer(model_name: str) -> RobertaTokenizer:
    try:
        return RobertaTokenizer.from_pretrained(model_name, local_files_only=True)
    except Exception:
        print(
            f"Local tokenizer cache not found for {model_name}; trying remote download...",
            file=sys.stderr,
        )
        try:
            return RobertaTokenizer.from_pretrained(model_name)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to load tokenizer '{model_name}'. "
                f"Ensure the model is cached locally or network access is available."
            ) from exc


def count_code_tokens(tokenizer: RobertaTokenizer, code: str) -> int:
    return len(tokenizer.tokenize(str(code)))


def list_slice_files(slice_dir: Path) -> list[Path]:
    return sorted(
        p for p in slice_dir.iterdir()
        if p.is_file() and p.suffix.lower() in ALLOWED_SUFFIXES
    )


def process_slices(slice_dir: Path, tokenizer: RobertaTokenizer) -> tuple[list[dict[str, object]], dict[str, int]]:
    slice_files = list_slice_files(slice_dir)
    results: list[dict[str, object]] = []
    counters = Counter()

    for i, filepath in enumerate(slice_files, start=1):
        code = filepath.read_text(encoding="utf-8", errors="replace")
        code_token_count = count_code_tokens(tokenizer, code)
        exceeds_limit = code_token_count > CONTENT_TOKEN_LIMIT
        input_token_count = min(code_token_count, CONTENT_TOKEN_LIMIT) + 2

        if exceeds_limit:
            counters["over_limit_count"] += 1
        counters[f"ext_{filepath.suffix.lower()}"] += 1

        results.append(
            {
                "filename": filepath.name,
                "extension": filepath.suffix.lower(),
                "code_token_count": code_token_count,
                "input_token_count_with_special": input_token_count,
                "exceeds_510": exceeds_limit,
            }
        )

        if i % 500 == 0:
            print(f"  [{i}/{len(slice_files)}] processed...")

    counters["slice_files_total"] = len(slice_files)
    return results, dict(counters)


def save_csv(results: list[dict[str, object]], output_csv: Path) -> None:
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "filename",
            "extension",
            "code_token_count",
            "input_token_count_with_special",
            "exceeds_510",
        ])
        for row in results:
            writer.writerow([
                row["filename"],
                row["extension"],
                row["code_token_count"],
                row["input_token_count_with_special"],
                row["exceeds_510"],
            ])


def plot_distribution(results: list[dict[str, object]], output_plot: Path) -> None:
    plt.style.use(["science", "no-latex"])
    fig, ax = plt.subplots(figsize=(8, 5))

    if not results:
        ax.text(0.5, 0.5, "No slice files found", ha="center", va="center", transform=ax.transAxes)
        ax.set_axis_off()
    else:
        token_counts = [int(row["code_token_count"]) for row in results]
        ax.hist(token_counts, bins=min(50, max(10, len(set(token_counts)))), edgecolor="black", alpha=0.7)
        ax.set_xlabel("Token Count")
        ax.set_ylabel("Number of Slices")
        ax.set_title("Token Count Distribution of Generated Slices")

        avg = sum(token_counts) / len(token_counts)
        sorted_counts = sorted(token_counts)
        median = sorted_counts[len(sorted_counts) // 2]
        stats_text = f"Total: {len(token_counts)}\nMean: {avg:.1f}\nMedian: {median}"
        ax.text(
            0.95,
            0.95,
            stats_text,
            transform=ax.transAxes,
            fontsize=9,
            verticalalignment="top",
            horizontalalignment="right",
            bbox=dict(boxstyle="round", facecolor="wheat", alpha=0.5),
        )

    fig.tight_layout()
    fig.savefig(output_plot, dpi=200)
    plt.close(fig)


def main() -> int:
    args = parse_args()
    slice_dir, output_dir, run_dir = resolve_paths(args)
    validate_inputs(slice_dir)
    prepare_output_dir(output_dir, args.overwrite)

    output_csv = output_dir / "slice_token_counts.csv"
    output_plot = output_dir / "slice_token_distribution.png"
    output_summary = output_dir / "summary.json"

    print("Loading tokenizer...")
    tokenizer = load_tokenizer(args.model_name)
    print(f"Reading slices from: {slice_dir}\n")

    results, counters = process_slices(slice_dir, tokenizer)
    save_csv(results, output_csv)
    plot_distribution(results, output_plot)

    summary_payload = {
        "slice_dir": str(slice_dir),
        "output_dir": str(output_dir),
        "run_dir": str(run_dir) if run_dir else None,
        "model_name": args.model_name,
        "max_length": MAX_LENGTH,
        "content_token_limit": CONTENT_TOKEN_LIMIT,
        "counts": counters,
        "csv": str(output_csv),
        "plot": str(output_plot),
    }
    output_summary.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary_payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
