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

import json
from collections import Counter
from pathlib import Path
from typing import Any

from shared.fs import prepare_output_dir
from shared.paths import RESULT_DIR
from shared.pipeline_runs import find_latest_pipeline_run_dir
from shared.traces import extract_std_bug_trace

CPP_SUFFIXES = {'.cpp', '.cc', '.cxx', '.c++'}


def infer_run_dir_from_signature_db_dir(signature_db_dir: Path) -> Path | None:
    if signature_db_dir.name != 'paired_signatures':
        return None
    if signature_db_dir.parent.name != '05_pair_trace_ds':
        return None
    return signature_db_dir.parent.parent


def resolve_paths(
    *,
    signature_db_dir: Path | None = None,
    output_dir: Path | None = None,
    pipeline_root: Path = Path(RESULT_DIR) / 'pipeline-runs',
    run_dir: Path | None = None,
) -> tuple[Path, Path, Path, Path | None]:
    resolved_run_dir = run_dir.resolve() if run_dir is not None else None

    if signature_db_dir is None:
        if resolved_run_dir is None:
            resolved_run_dir = find_latest_pipeline_run_dir(pipeline_root.resolve())
        resolved_signature_db_dir = resolved_run_dir / '05_pair_trace_ds' / 'paired_signatures'
    else:
        resolved_signature_db_dir = signature_db_dir.resolve()
        if resolved_run_dir is None:
            resolved_run_dir = infer_run_dir_from_signature_db_dir(resolved_signature_db_dir)

    if output_dir is None:
        if resolved_run_dir is None:
            raise ValueError(
                '--output-dir is required when --signature-db-dir is outside the standard pipeline layout.'
            )
        resolved_output_dir = resolved_run_dir / '06_slices'
    else:
        resolved_output_dir = output_dir.resolve()

    slice_dir = resolved_output_dir / 'slice'
    return resolved_signature_db_dir, resolved_output_dir, slice_dir, resolved_run_dir


def validate_args(
    signature_db_dir: Path,
    *,
    old_prefix: str | None = None,
    new_prefix: str | None = None,
) -> None:
    if not signature_db_dir.exists():
        raise FileNotFoundError(f'Signature DB dir not found: {signature_db_dir}')
    if not signature_db_dir.is_dir():
        raise NotADirectoryError(f'Signature DB dir is not a directory: {signature_db_dir}')
    if bool(old_prefix) != bool(new_prefix):
        raise ValueError('--old-prefix and --new-prefix must be provided together.')


def fix_path(original_path: str, old_prefix: str | None, new_prefix: str | None) -> str:
    if old_prefix and new_prefix and original_path.startswith(old_prefix):
        return original_path.replace(old_prefix, new_prefix, 1)
    return original_path


def read_source_line(filepath: Path, line_number: int) -> str | None:
    try:
        with filepath.open('r', encoding='utf-8', errors='replace') as f:
            lines = f.readlines()
        if 1 <= line_number <= len(lines):
            return lines[line_number - 1]
        return None
    except FileNotFoundError:
        return None
    except Exception:
        return None


def classify_suffix(path_like: str | None) -> str | None:
    if not path_like:
        return None
    suffix = Path(path_like).suffix.lower()
    if suffix == '.c':
        return '.c'
    if suffix in CPP_SUFFIXES:
        return '.cpp'
    return None


def guess_output_suffix(data: dict[str, Any], std_bug_trace: list[dict[str, Any]]) -> str:
    candidates: list[str | None] = [data.get('file')]
    if data.get('primary_file'):
        candidates.append(data.get('primary_file'))
    for node in std_bug_trace:
        candidates.append(node.get('filename'))
    for candidate in candidates:
        suffix = classify_suffix(candidate)
        if suffix:
            return suffix
    return '.c'


def build_slice(
    std_bug_trace: list[dict[str, Any]], old_prefix: str | None, new_prefix: str | None
) -> tuple[str | None, str | None]:
    slice_lines: list[str] = []
    seen: set[tuple[str, int]] = set()

    for node in std_bug_trace:
        filename = node.get('filename')
        line_number = int(node.get('line_number', 0) or 0)
        if not filename or line_number <= 0:
            return None, 'invalid_trace_node'

        fixed_path = fix_path(str(filename), old_prefix, new_prefix)
        key = (fixed_path, line_number)
        if key in seen:
            continue
        seen.add(key)

        source_line = read_source_line(Path(fixed_path), line_number)
        if source_line is None:
            return None, 'missing_source_line'
        slice_lines.append(source_line)

    return ''.join(slice_lines), None


def process_signature_db(
    signature_db_dir: Path, slice_dir: Path, old_prefix: str | None, new_prefix: str | None
) -> dict[str, Any]:
    slice_dir.mkdir(parents=True, exist_ok=True)

    testcase_dirs = sorted(d for d in signature_db_dir.iterdir() if d.is_dir())

    total_slices = 0
    errors = 0
    counters = Counter()
    suffix_counter = Counter()

    for testcase_dir in testcase_dirs:
        counters['testcase_dirs_total'] += 1
        json_files = sorted(
            p for p in testcase_dir.iterdir() if p.is_file() and p.suffix == '.json'
        )
        for json_path in json_files:
            counters['json_files_total'] += 1
            try:
                data = json.loads(json_path.read_text(encoding='utf-8'))
                bug_trace = data.get('bug_trace', [])
                std_bug_trace = extract_std_bug_trace(bug_trace)
                if not std_bug_trace:
                    counters['skipped_empty_bug_trace'] += 1
                    continue

                slice_content, skip_reason = build_slice(std_bug_trace, old_prefix, new_prefix)
                if slice_content is None:
                    counters[f'skipped_{skip_reason}'] += 1
                    continue

                suffix = guess_output_suffix(data, std_bug_trace)
                suffix_counter[suffix] += 1
                output_filename = f'slice_{testcase_dir.name}_{json_path.stem}{suffix}'
                output_path = slice_dir / output_filename
                output_path.write_text(slice_content, encoding='utf-8')
                total_slices += 1
                counters['generated'] += 1
            except Exception as exc:
                print(f'[ERROR] {json_path}: {exc}')
                errors += 1
                counters['errors'] += 1

    return {
        'signature_db_dirs_total': len(testcase_dirs),
        'total_slices': total_slices,
        'errors': errors,
        'counts': dict(counters),
        'slice_extension_counts': dict(suffix_counter),
    }


def generate_slices(
    *,
    signature_db_dir: Path,
    output_dir: Path,
    old_prefix: str | None = None,
    new_prefix: str | None = None,
    overwrite: bool = False,
    run_dir: Path | None = None,
    summary_metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    validate_args(signature_db_dir, old_prefix=old_prefix, new_prefix=new_prefix)
    prepare_output_dir(output_dir, overwrite)
    slice_dir = output_dir / 'slice'

    summary = process_signature_db(
        signature_db_dir=signature_db_dir,
        slice_dir=slice_dir,
        old_prefix=old_prefix,
        new_prefix=new_prefix,
    )

    summary_payload = {
        'signature_db_dir': str(signature_db_dir),
        'output_dir': str(output_dir),
        'slice_dir': str(slice_dir),
        'run_dir': str(run_dir) if run_dir else None,
        'old_prefix': old_prefix,
        'new_prefix': new_prefix,
        **summary,
    }
    if summary_metadata:
        for key, value in summary_metadata.items():
            if key not in summary_payload:
                summary_payload[key] = value
    summary_path = output_dir / 'summary.json'
    summary_path.write_text(
        json.dumps(summary_payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8'
    )
    print(json.dumps(summary_payload, ensure_ascii=False))
    return summary_payload
