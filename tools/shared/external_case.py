from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from pathlib import Path

TRACK_NAMES = frozenset({'vulnerable', 'patched'})
REMOTE_URL_RE = re.compile(r'^\s*url\s*=\s*(?P<url>\S+)\s*$')


@dataclass(frozen=True)
class CaseRunPaths:
    case_dir: Path
    case_id: str
    track: str
    run_id: str
    track_dir: Path
    repo_dir: Path
    worklog_path: Path
    trace_output_dir: Path
    selected_runs_dir: Path
    runs_dir: Path
    inputs_dir: Path
    run_dir: Path
    build_targets_csv: Path
    manual_line_truth_csv: Path
    pulse_taint_config: Path
    outputs_dir: Path


@dataclass(frozen=True)
class CaseRunInputPaths:
    build_targets_csv: Path
    manual_line_truth_csv: Path
    pulse_taint_config: Path


def resolve_case_run_paths(
    case_dir: Path,
    *,
    track: str,
    run_id: str,
) -> CaseRunPaths:
    normalized_case_dir = case_dir.resolve()
    if not normalized_case_dir.exists():
        raise ValueError(f'Case directory not found: {normalized_case_dir}')
    if track not in TRACK_NAMES:
        raise ValueError(f'Unsupported track: {track}')

    track_dir = normalized_case_dir / track
    runs_dir = track_dir / 'runs'
    run_dir = runs_dir / run_id

    return CaseRunPaths(
        case_dir=normalized_case_dir,
        case_id=normalized_case_dir.name,
        track=track,
        run_id=run_id,
        track_dir=track_dir,
        repo_dir=track_dir / 'repo',
        worklog_path=track_dir / 'WORKLOG.md',
        trace_output_dir=track_dir / 'trace_output',
        selected_runs_dir=track_dir / 'trace_output' / 'selected_runs',
        runs_dir=runs_dir,
        inputs_dir=runs_dir / 'inputs',
        run_dir=run_dir,
        build_targets_csv=run_dir / 'build_targets.csv',
        manual_line_truth_csv=run_dir / 'manual_line_truth.csv',
        pulse_taint_config=run_dir / 'pulse-taint-config.json',
        outputs_dir=run_dir / 'outputs',
    )


def validate_case_layout(paths: CaseRunPaths) -> None:
    required = {
        'track directory': paths.track_dir,
        'repo directory': paths.repo_dir,
        'runs directory': paths.runs_dir,
        'inputs directory': paths.inputs_dir,
    }
    for label, path in required.items():
        if not path.exists():
            raise ValueError(f'Missing {label}: {path}')


def prepare_case_run_inputs(
    paths: CaseRunPaths,
) -> CaseRunInputPaths:
    validate_case_layout(paths)
    paths.run_dir.mkdir(parents=True, exist_ok=True)

    return CaseRunInputPaths(
        build_targets_csv=_copy_case_input_path(
            label='build_targets.csv',
            source_path=paths.inputs_dir / 'build_targets.csv',
            destination_path=paths.build_targets_csv,
        ),
        manual_line_truth_csv=_copy_case_input_path(
            label='manual_line_truth.csv',
            source_path=paths.inputs_dir / 'manual_line_truth.csv',
            destination_path=paths.manual_line_truth_csv,
        ),
        pulse_taint_config=_copy_case_input_path(
            label='pulse-taint-config.json',
            source_path=paths.inputs_dir / 'pulse-taint-config.json',
            destination_path=paths.pulse_taint_config,
        ),
    )


def infer_project_name_from_repo(repo_dir: Path) -> str:
    source_root = repo_dir.resolve()
    if source_root.name == 'raw_code' and source_root.parent.name:
        return source_root.parent.name
    if source_root.name != 'repo':
        return source_root.name

    origin_url = _read_git_origin_url(source_root)
    if origin_url:
        project_name = _project_name_from_git_url(origin_url)
        if project_name:
            return project_name

    return source_root.parent.name or source_root.name


def _copy_case_input_path(
    *,
    label: str,
    source_path: Path,
    destination_path: Path,
) -> Path:
    resolved_source = source_path.resolve()
    _require_existing_input_path(label, resolved_source)
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    if destination_path.exists() or destination_path.is_symlink():
        if destination_path.is_dir():
            raise FileExistsError(f'Expected file for {label}: {destination_path}')
        destination_path.unlink()
    shutil.copy2(resolved_source, destination_path)
    return destination_path


def _require_existing_input_path(label: str, path: Path) -> None:
    if not path.exists():
        raise ValueError(f'Missing {label}: {path}')
    if path.is_dir():
        raise FileExistsError(f'Expected file for {label}: {path}')


def _read_git_origin_url(repo_dir: Path) -> str | None:
    git_config = repo_dir / '.git' / 'config'
    if not git_config.exists():
        return None

    in_origin = False
    for raw_line in git_config.read_text(encoding='utf-8').splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('['):
            in_origin = line == '[remote "origin"]'
            continue
        if not in_origin:
            continue

        match = REMOTE_URL_RE.match(raw_line)
        if match:
            return match.group('url')
    return None


def _project_name_from_git_url(raw_url: str) -> str:
    cleaned = raw_url.rstrip('/')
    if not cleaned:
        return ''

    tail = cleaned.rsplit(':', maxsplit=1)[-1] if '://' not in cleaned else cleaned
    name = tail.rsplit('/', maxsplit=1)[-1]
    if name.endswith('.git'):
        name = name[:-4]
    return name
