from __future__ import annotations

import csv
import math
import re
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from shared.csvio import write_csv_rows
from shared.jsonio import write_json, write_jsonl
from shared.juliet_keys import JULIET_GROUP_SOURCE_SUFFIXES, parse_juliet_case_identity

DIRECTIONS = ('goodB2G', 'goodG2B')
HEADER_FIELD_RE = re.compile(
    r'^\s*\*\s*(BadSource|GoodSource|GoodSink|BadSink)\s*:?\s*(.+?)\s*$',
    re.MULTILINE,
)
FLOW_VARIANT_COMMENT_RE = re.compile(r'^\s*\*\s*Flow Variant:\s*(\d+)\s*(.+?)\s*$', re.MULTILINE)
FIX_COMMENT_RE = re.compile(r'/\*\s*FIX:\s*(.*?)\s*\*/')
FLAW_COMMENT_RE = re.compile(r'/\*\s*POTENTIAL FLAW:\s*(.*?)\s*\*/')
DIRECTION_MARKER_RE = re.compile(r'\b(goodB2G|goodG2B)(\d+)?(?:Sink|Source)?\b')
NON_ALNUM_RE = re.compile(r'[^a-z0-9]+')
WHITESPACE_RE = re.compile(r'\s+')

CANONICAL_PHRASE_REPLACEMENTS = (
    ('a hardcoded non-zero number (two)', 'hardcoded non-zero value'),
    ('a value not equal to zero', 'non-zero value'),
    ('use a value not equal to zero', 'use non-zero value'),
    ('use a relatively small number greater than zero', 'use small positive value'),
    ('fixed value of zero', 'zero value'),
    ('check value of or near zero before dividing', 'check for zero before dividing'),
    ('check value of or near zero before modulo', 'check for zero before modulo'),
    ('do not initialize data', 'leave data uninitialized'),
    ('does not initialize data', 'leave data uninitialized'),
    ('do not attempt to connect if', 'guard before connect if'),
    ('listensocket', 'listen socket'),
    ('listen_socket', 'listen socket'),
    ('fscanf()', 'fscanf'),
    ('rand()', 'rand'),
    ('malloc()', 'malloc'),
    ('calloc()', 'calloc'),
    ('realloc()', 'realloc'),
    ('free()', 'free'),
    ('delete []', 'delete array'),
    ('new []', 'new array'),
)

L1_DEFINITIONS = {
    'input_state_validation': {
        'label': 'Input / state validation',
        'description': 'Validate scalar values or state before dangerous use.',
    },
    'bounds_and_size': {
        'label': 'Bounds / size / length control',
        'description': 'Constrain copy, index, buffer, string, or allocation size behavior.',
    },
    'pointer_position_and_reference': {
        'label': 'Pointer / reference correction',
        'description': 'Repair pointer position, nullability, or reference target selection.',
    },
    'buffer_allocation_strategy': {
        'label': 'Buffer / allocation strategy',
        'description': 'Choose a safer storage location, object type, or allocation shape.',
    },
    'memory_lifetime_and_ownership': {
        'label': 'Memory lifetime / ownership',
        'description': 'Match allocation and deallocation contracts or prevent ownership errors.',
    },
    'resource_handle_lifecycle': {
        'label': 'Resource / handle lifecycle',
        'description': 'Open, close, reuse, or avoid duplicating non-memory resources safely.',
    },
    'initialization_and_state_setup': {
        'label': 'Initialization / state setup',
        'description': 'Initialize data or state before use when that is the primary fix.',
    },
    'api_contract_and_call_safety': {
        'label': 'API contract / call safety',
        'description': 'Use safer APIs, format strings, or return-value handling contracts.',
    },
    'security_policy_and_configuration': {
        'label': 'Security policy / configuration',
        'description': 'Repair path, privilege, crypto, password, config, or access-control usage.',
    },
    'cleanup_and_information_exposure': {
        'label': 'Cleanup / information exposure',
        'description': 'Clear, close, scrub, or avoid residual sensitive information exposure.',
    },
    'concurrency_and_ordering': {
        'label': 'Concurrency / ordering',
        'description': 'Repair race, signal, locking, or time-of-check/time-of-use behavior.',
    },
    'other': {
        'label': 'Other / review needed',
        'description': 'Fallback bucket for phrases not yet covered cleanly by the seed taxonomy.',
    },
}

SECURITY_POLICY_KEYWORDS = (
    'password',
    'credential',
    'crypt',
    'crypto',
    'hash',
    'cipher',
    'prng',
    'seed',
    'random',
    'privilege',
    'permission',
    'access control',
    'authorize',
    'authentication',
    'path traversal',
    'relative path',
    'absolute path',
    'full path',
    'pathname',
    'file name',
    'filename',
    'directory',
    'load library',
    'loadlibrary',
    'library',
    'dll',
    'system or configuration setting',
    'environment variable',
    'cleartext',
    'plaintext',
    'dns',
    'host name',
    'tmp file',
    'temporary file',
    'temp file',
    'url',
    'command injection',
    'os command',
)
CONCURRENCY_KEYWORDS = (
    'race',
    'signal handler',
    'signal-safe',
    'thread',
    'lock',
    'unlock',
    'mutex',
    'semaphore',
    'time of check',
    'toctou',
    'deadlock',
)
CLEANUP_KEYWORDS = (
    'clear sensitive information',
    'sensitive information uncleared',
    'sensitive data',
    'clear the password',
    'scrub',
    'zero out',
    'clear its contents',
    'clear the list contents',
    'remove temporary file',
    'temporary file',
    'heap inspection',
    'release resource after use',
)
RESOURCE_HANDLE_KEYWORDS = (
    'open a file using',
    'close the file using',
    'close the file handle',
    'file handle',
    'file descriptor',
    'resource leak',
    'resource is not released',
    'reusing the file descriptor',
    'reusing it',
    'duplicate operation',
    'fopen',
    'open()',
    'close()',
    'createfile',
    'closehandle',
    'closesocket',
    'close socket',
    'open socket',
    'fdopen',
    'fclose',
)
MEMORY_LIFETIME_KEYWORDS = (
    'deallocate',
    'free data using',
    'delete data using',
    'double free',
    'release memory',
    'free()',
    'delete ',
    ' delete',
    'free pointer',
)
ALLOCATION_STRATEGY_KEYWORDS = (
    'alloca',
    'allocate memory on the heap',
    'allocate data using',
    'declared on the stack',
    'static on the stack',
    'declared static on the stack',
    'heap',
    'stack',
    'new array',
    'malloc',
    'calloc',
    'realloc',
)
POINTER_KEYWORDS = (
    'pointer to before',
    'start of buffer',
    'pointer to the allocated memory buffer',
    'null pointer',
    'dereference',
    'pointer',
    'reference',
)
BOUNDS_KEYWORDS = (
    'buffer',
    'string',
    'length',
    'size',
    'copy data',
    'copy',
    'concatenate',
    'index',
    'array',
    'truncate',
    'overflow',
    'underwrite',
    'underread',
    'overread',
    'null terminator',
    'small string',
    'large string',
    'allocate enough memory',
    'bounds',
)
API_CONTRACT_KEYWORDS = (
    'return value',
    'checked return',
    'incorrect check',
    'format string',
    'printf',
    'scanf',
    'snprintf',
    'memcpy',
    'memmove',
    'strcpy',
    'strncpy',
    'strcat',
    'strncat',
    'vprintf',
    'va_start',
    'dangerous function',
    'inherently dangerous function',
    'exception',
)
API_PRIORITY_KEYWORDS = (
    'format string',
    'return value',
    'checked return',
    'incorrect check',
    'dangerous function',
    'inherently dangerous function',
    'va_start',
)
INITIALIZATION_KEYWORDS = (
    'initialize',
    'initialized',
    'uninitialized',
    'leave data uninitialized',
    'set data to',
    'set data =',
    'initial value',
    'default value',
)
INPUT_VALIDATION_KEYWORDS = (
    'check for zero',
    'non-zero',
    'zero denominator',
    'zero before dividing',
    'zero before modulo',
    'positive',
    'negative',
    'greater than zero',
    'less than',
    'greater than',
    'within the bounds',
    'validate',
    'range',
)
SINK_FAMILY_PATTERNS = (
    ('memcpy', 'memcpy'),
    ('memmove', 'memmove'),
    ('strncpy', 'strncpy'),
    ('strcpy', 'strcpy'),
    ('strncat', 'strncat'),
    ('strcat', 'strcat'),
    ('snprintf', 'snprintf'),
    ('fprintf', 'fprintf'),
    ('printf', 'printf'),
    ('vfprintf', 'vfprintf'),
    ('vprintf', 'vprintf'),
    ('vsnprintf', 'vsnprintf'),
    ('wcsncpy', 'wcsncpy'),
    ('wcscpy', 'wcscpy'),
    ('wcsncat', 'wcsncat'),
    ('wcscat', 'wcscat'),
    ('loop', 'loop'),
    ('system', 'system'),
    ('popen', 'popen'),
)
SOURCE_KIND_PATTERNS = (
    ('placement_new', 'placement-new stack storage'),
    ('declared static on the stack', 'static stack storage'),
    ('static on the stack', 'static stack storage'),
    ('declare data buffer is declared on the stack', 'stack declaration'),
    ('declared on the stack', 'stack declaration'),
    ('alloca', 'alloca stack storage'),
)


@dataclass(frozen=True)
class CaseGroup:
    directory: str
    cwe_number: str
    cwe_name: str
    functional_variant_name: str
    flow_variant_id: str
    files: tuple[Path, ...]

    @property
    def case_group_id(self) -> str:
        return f'CWE{self.cwe_number}|{self.functional_variant_name}|flow{self.flow_variant_id}'


@dataclass(frozen=True)
class PatchRecord:
    case_group_id: str
    case_group_stem: str
    dedupe_key: str
    cwe_id: str
    cwe_name: str
    functional_variant_name: str
    flow_variant_id: str
    patch_direction: str
    patch_role: str
    bad_source: str
    good_source: str
    bad_sink: str
    good_sink: str
    primary_phrase_source: str
    primary_phrase: str
    l1_code: str
    l1_label: str
    l2_code: str
    l2_label: str
    direction_file_count: int
    fix_comment_count: int
    flaw_comment_count: int
    representative_files: tuple[str, ...]
    representative_fix_comments: tuple[str, ...]
    representative_flaw_comments: tuple[str, ...]
    representative_code_snippets: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass(frozen=True)
class AnalysisArtifacts:
    patch_records_jsonl: Path
    patch_records_csv: Path
    l1_summary_csv: Path
    taxonomy_summary_csv: Path
    flow_variant_matrix_csv: Path
    direction_summary_csv: Path
    cwe_l1_matrix_csv: Path
    taxonomy_definition_md: Path
    summary_json: Path
    statistics_json: Path
    statistics_report_md: Path
    review_queue_csv: Path


def slugify(text: str) -> str:
    normalized = NON_ALNUM_RE.sub('_', normalize_text(text)).strip('_')
    return normalized or 'unspecified'


def normalize_text(text: str) -> str:
    value = str(text or '').strip().lower()
    for old, new in CANONICAL_PHRASE_REPLACEMENTS:
        value = value.replace(old, new)
    value = WHITESPACE_RE.sub(' ', value)
    return value.strip()


def stable_phrase_label(text: str) -> str:
    normalized = normalize_text(text)
    if not normalized:
        return ''
    return normalized[0].upper() + normalized[1:]


def build_case_groups(juliet_root: Path) -> list[CaseGroup]:
    groups: dict[tuple[str, str, str, str, str], list[Path]] = defaultdict(list)
    for path in sorted(juliet_root.rglob('*')):
        if not path.is_file():
            continue
        identity = parse_juliet_case_identity(path, allowed_suffixes=JULIET_GROUP_SOURCE_SUFFIXES)
        if identity is None:
            continue
        groups[identity].append(path)

    case_groups: list[CaseGroup] = []
    for identity, files in sorted(groups.items()):
        case_groups.append(
            CaseGroup(
                directory=identity[0],
                cwe_number=identity[1],
                cwe_name=identity[2],
                functional_variant_name=identity[3],
                flow_variant_id=identity[4],
                files=tuple(sorted(files)),
            )
        )
    return case_groups


def extract_metadata(text: str) -> dict[str, str]:
    metadata = {'bad_source': '', 'good_source': '', 'good_sink': '', 'bad_sink': ''}
    for key, value in HEADER_FIELD_RE.findall(text):
        normalized_key = {
            'BadSource': 'bad_source',
            'GoodSource': 'good_source',
            'GoodSink': 'good_sink',
            'BadSink': 'bad_sink',
        }[key]
        if not metadata[normalized_key]:
            metadata[normalized_key] = value.strip()
    return metadata


def extract_flow_variant_comment(text: str) -> tuple[str, str]:
    match = FLOW_VARIANT_COMMENT_RE.search(text)
    if match is None:
        return '', ''
    return match.group(1).strip(), match.group(2).strip()


def detect_directions(group: CaseGroup, file_texts: dict[Path, str]) -> list[str]:
    found: list[str] = []
    for direction in DIRECTIONS:
        if any(f'_{direction}' in path.stem for path in group.files):
            found.append(direction)
            continue
        token = direction.lower()
        if any(token in text.lower() for text in file_texts.values()):
            found.append(direction)
    return found


def find_direction_markers(
    lines: list[str], file_direction_hint: str | None
) -> list[tuple[int, str]]:
    markers: list[tuple[int, str]] = []
    for index, line in enumerate(lines):
        if '(' not in line and '::' not in line and 'class ' not in line:
            continue
        match = DIRECTION_MARKER_RE.search(line)
        if match is None:
            continue
        markers.append((index, match.group(1)))
    if not markers and file_direction_hint is not None:
        markers.append((0, file_direction_hint))
    return markers


def assign_direction(
    line_index: int,
    *,
    markers: list[tuple[int, str]],
    file_direction_hint: str | None,
    file_text: str,
) -> str | None:
    previous_direction: str | None = None
    previous_index = -1
    next_index = None
    for marker_index, marker_direction in markers:
        if marker_index <= line_index and marker_index >= previous_index:
            previous_direction = marker_direction
            previous_index = marker_index
        elif marker_index > line_index:
            next_index = marker_index
            break
    if previous_direction is not None:
        if next_index is None or line_index < next_index:
            return previous_direction
    if file_direction_hint is not None:
        return file_direction_hint
    lower_text = file_text.lower()
    directions_present = [direction for direction in DIRECTIONS if direction.lower() in lower_text]
    if len(directions_present) == 1:
        return directions_present[0]
    return None


def extract_code_snippet(lines: list[str], comment_index: int) -> str:
    snippet_lines: list[str] = []
    for candidate in lines[comment_index + 1 : comment_index + 9]:
        stripped = candidate.strip()
        if not stripped:
            if snippet_lines:
                break
            continue
        if stripped.startswith('/*') or stripped.startswith('*'):
            if snippet_lines:
                break
            continue
        snippet_lines.append(stripped)
        if len(snippet_lines) >= 3:
            break
        if stripped.endswith(';') or stripped.endswith('{') or stripped.endswith('}'):
            break
    return ' '.join(snippet_lines)


def collect_direction_evidence(
    group: CaseGroup,
    direction: str,
    file_texts: dict[Path, str],
) -> dict[str, object]:
    fix_comments: list[str] = []
    flaw_comments: list[str] = []
    code_snippets: list[str] = []
    notes: list[str] = []
    representative_files: list[str] = []

    for path in group.files:
        text = file_texts[path]
        lower_text = text.lower()
        file_direction_hint = None
        if f'_{direction.lower()}' in path.stem.lower():
            file_direction_hint = direction
        elif any(
            f'_{other.lower()}' in path.stem.lower() for other in DIRECTIONS if other != direction
        ):
            continue
        elif direction.lower() not in lower_text and file_direction_hint is None:
            continue

        representative_files.append(str(path))
        lines = text.splitlines()
        markers = find_direction_markers(lines, file_direction_hint)
        for index, line in enumerate(lines):
            fix_match = FIX_COMMENT_RE.search(line)
            flaw_match = FLAW_COMMENT_RE.search(line)
            if fix_match is None and flaw_match is None:
                continue
            assigned = assign_direction(
                index,
                markers=markers,
                file_direction_hint=file_direction_hint,
                file_text=text,
            )
            if assigned != direction:
                continue
            if fix_match is not None:
                fix_comments.append(fix_match.group(1).strip())
            if flaw_match is not None:
                flaw_comments.append(flaw_match.group(1).strip())
            snippet = extract_code_snippet(lines, index)
            if snippet:
                code_snippets.append(snippet)

        if file_direction_hint is None and not markers:
            notes.append(f'heuristic_direction_assignment:{path.name}')

    return {
        'representative_files': tuple(dict.fromkeys(representative_files)),
        'fix_comments': tuple(dict.fromkeys(comment for comment in fix_comments if comment)),
        'flaw_comments': tuple(dict.fromkeys(comment for comment in flaw_comments if comment)),
        'code_snippets': tuple(dict.fromkeys(snippet for snippet in code_snippets if snippet)),
        'notes': tuple(dict.fromkeys(notes)),
    }


def pick_primary_phrase(
    *,
    direction: str,
    metadata: dict[str, str],
    fix_comments: tuple[str, ...],
    code_snippets: tuple[str, ...],
) -> tuple[str, str]:
    ordered_candidates: list[tuple[str, str]]
    if direction == 'goodB2G':
        ordered_candidates = [
            ('good_sink', metadata.get('good_sink', '')),
            ('fix_comment', fix_comments[0] if fix_comments else ''),
            ('good_source', metadata.get('good_source', '')),
            ('code_snippet', code_snippets[0] if code_snippets else ''),
        ]
    else:
        ordered_candidates = [
            ('good_source', metadata.get('good_source', '')),
            ('fix_comment', fix_comments[0] if fix_comments else ''),
            ('good_sink', metadata.get('good_sink', '')),
            ('code_snippet', code_snippets[0] if code_snippets else ''),
        ]
    for source, phrase in ordered_candidates:
        phrase = str(phrase or '').strip()
        if phrase:
            return source, stable_phrase_label(phrase)
    return 'none', ''


def classify_l1(*, primary_phrase: str, metadata: dict[str, str], evidence_text: str) -> str:
    combined = ' '.join(
        part
        for part in (
            normalize_text(primary_phrase),
            normalize_text(metadata.get('bad_source', '')),
            normalize_text(metadata.get('good_source', '')),
            normalize_text(metadata.get('bad_sink', '')),
            normalize_text(metadata.get('good_sink', '')),
            normalize_text(evidence_text),
        )
        if part
    )

    def contains_any(keywords: Iterable[str]) -> bool:
        return any(keyword in combined for keyword in keywords)

    if contains_any(CONCURRENCY_KEYWORDS):
        return 'concurrency_and_ordering'
    if contains_any(SECURITY_POLICY_KEYWORDS):
        return 'security_policy_and_configuration'
    if contains_any(RESOURCE_HANDLE_KEYWORDS):
        return 'resource_handle_lifecycle'
    if contains_any(CLEANUP_KEYWORDS):
        return 'cleanup_and_information_exposure'
    if contains_any(POINTER_KEYWORDS):
        return 'pointer_position_and_reference'
    if contains_any(MEMORY_LIFETIME_KEYWORDS):
        if 'pointer to before' not in combined and 'start of buffer' not in combined:
            return 'memory_lifetime_and_ownership'
    if contains_any(ALLOCATION_STRATEGY_KEYWORDS):
        if 'deallocate' not in combined or 'allocate memory on the heap' in combined:
            return 'buffer_allocation_strategy'
    if contains_any(API_PRIORITY_KEYWORDS):
        return 'api_contract_and_call_safety'
    if contains_any(BOUNDS_KEYWORDS):
        return 'bounds_and_size'
    if contains_any(API_CONTRACT_KEYWORDS):
        return 'api_contract_and_call_safety'
    if contains_any(INPUT_VALIDATION_KEYWORDS):
        return 'input_state_validation'
    if contains_any(INITIALIZATION_KEYWORDS):
        return 'initialization_and_state_setup'
    return 'other'


def detect_sink_family(*texts: str) -> str:
    combined = ' '.join(normalize_text(text) for text in texts if text).strip()
    for pattern, label in SINK_FAMILY_PATTERNS:
        if pattern in combined:
            return label
    return ''


def detect_source_kind(text: str) -> str:
    normalized = normalize_text(text)
    for pattern, label in SOURCE_KIND_PATTERNS:
        if pattern in normalized:
            return label
    return ''


def refine_l2_label(
    *,
    primary_phrase: str,
    metadata: dict[str, str],
    evidence_text: str,
) -> str:
    normalized_phrase = normalize_text(primary_phrase)
    combined = ' '.join(
        normalize_text(part)
        for part in (
            primary_phrase,
            metadata.get('bad_source', ''),
            metadata.get('good_source', ''),
            metadata.get('bad_sink', ''),
            metadata.get('good_sink', ''),
            evidence_text,
        )
        if part
    )
    sink_family = detect_sink_family(metadata.get('bad_sink', ''), metadata.get('good_sink', ''))

    if normalized_phrase == 'fixed string':
        if 'execute command' in combined or sink_family in {'system', 'popen'}:
            return 'Use fixed command string'
        if 'format string' in combined or 'format specifier' in combined:
            return 'Use fixed format string'
    if normalized_phrase == 'copy a fixed string into data':
        if 'format string' in combined or 'format specifier' in combined:
            return 'Copy non-format literal into data'
        return 'Copy fixed literal into data'
    if normalized_phrase == 'initialize data as a small string':
        if sink_family:
            return f'Use small string for {sink_family} sink'
        return 'Use small string input buffer'
    if normalized_phrase == 'set data pointer to the allocated memory buffer':
        if sink_family:
            return f'Reset pointer to buffer start for {sink_family} sink'
        return 'Reset pointer to buffer start'
    if normalized_phrase == 'allocate memory on the heap':
        source_kind = detect_source_kind(metadata.get('bad_source', ''))
        if source_kind:
            return f'Move allocation from {source_kind} to heap'
    return primary_phrase


def classify_l2(
    *,
    direction: str,
    primary_phrase_source: str,
    primary_phrase: str,
    metadata: dict[str, str],
    evidence_text: str,
) -> tuple[str, str]:
    if primary_phrase:
        refined_label = refine_l2_label(
            primary_phrase=primary_phrase,
            metadata=metadata,
            evidence_text=evidence_text,
        )
        prefix = 'sink' if direction == 'goodB2G' else 'source'
        code = f'{prefix}_{slugify(refined_label)}'
        return code, refined_label
    fallback = f'{direction}_{primary_phrase_source}_unspecified'
    return slugify(fallback), f'{direction} {primary_phrase_source} unspecified'


def build_patch_record(
    group: CaseGroup, direction: str, file_texts: dict[Path, str]
) -> PatchRecord:
    metadata = {'bad_source': '', 'good_source': '', 'good_sink': '', 'bad_sink': ''}
    for text in file_texts.values():
        for key, value in extract_metadata(text).items():
            if value and not metadata[key]:
                metadata[key] = value

    evidence = collect_direction_evidence(group, direction, file_texts)
    primary_phrase_source, primary_phrase = pick_primary_phrase(
        direction=direction,
        metadata=metadata,
        fix_comments=evidence['fix_comments'],
        code_snippets=evidence['code_snippets'],
    )
    evidence_text = ' '.join(
        list(evidence['fix_comments'])
        + list(evidence['flaw_comments'])
        + list(evidence['code_snippets'])
    )
    l1_code = classify_l1(
        primary_phrase=primary_phrase,
        metadata=metadata,
        evidence_text=evidence_text,
    )
    l2_code, l2_label = classify_l2(
        direction=direction,
        primary_phrase_source=primary_phrase_source,
        primary_phrase=primary_phrase,
        metadata=metadata,
        evidence_text=evidence_text,
    )
    cwe_id = f'CWE{group.cwe_number}'
    role = 'sink_guard' if direction == 'goodB2G' else 'source_prevention'
    dedupe_key = '|'.join(
        [
            cwe_id,
            group.functional_variant_name,
            direction,
            normalize_text(metadata.get('bad_source', '')),
            normalize_text(metadata.get('good_source', '')),
            normalize_text(metadata.get('bad_sink', '')),
            normalize_text(metadata.get('good_sink', '')),
            l1_code,
            l2_code,
        ]
    )
    return PatchRecord(
        case_group_id=group.case_group_id,
        case_group_stem=f'{cwe_id}_{group.functional_variant_name}_{group.flow_variant_id}',
        dedupe_key=dedupe_key,
        cwe_id=cwe_id,
        cwe_name=group.cwe_name,
        functional_variant_name=group.functional_variant_name,
        flow_variant_id=group.flow_variant_id,
        patch_direction=direction,
        patch_role=role,
        bad_source=metadata['bad_source'],
        good_source=metadata['good_source'],
        bad_sink=metadata['bad_sink'],
        good_sink=metadata['good_sink'],
        primary_phrase_source=primary_phrase_source,
        primary_phrase=primary_phrase,
        l1_code=l1_code,
        l1_label=L1_DEFINITIONS[l1_code]['label'],
        l2_code=l2_code,
        l2_label=l2_label,
        direction_file_count=len(evidence['representative_files']),
        fix_comment_count=len(evidence['fix_comments']),
        flaw_comment_count=len(evidence['flaw_comments']),
        representative_files=evidence['representative_files'][:6],
        representative_fix_comments=evidence['fix_comments'][:6],
        representative_flaw_comments=evidence['flaw_comments'][:6],
        representative_code_snippets=evidence['code_snippets'][:6],
        notes=evidence['notes'],
    )


def analyze_juliet_patch_taxonomy(juliet_root: Path) -> list[PatchRecord]:
    records: list[PatchRecord] = []
    for group in build_case_groups(juliet_root):
        file_texts = {
            path: path.read_text(encoding='utf-8', errors='ignore') for path in group.files
        }
        for direction in detect_directions(group, file_texts):
            records.append(build_patch_record(group, direction, file_texts))
    return records


PATCH_RECORD_FIELDS = [field.name for field in PatchRecord.__dataclass_fields__.values()]


def patch_record_row(record: PatchRecord) -> dict[str, str]:
    row = asdict(record)
    for key, value in list(row.items()):
        if isinstance(value, tuple):
            row[key] = ' || '.join(str(item) for item in value)
        else:
            row[key] = str(value)
    return row


SUMMARY_FIELDS = [
    'patch_direction',
    'l1_code',
    'l1_label',
    'l2_code',
    'l2_label',
    'deduped_patch_count',
    'raw_record_count',
    'deduped_share_overall',
    'raw_share_overall',
    'deduped_share_within_direction',
    'raw_share_within_direction',
    'cwe_count',
    'flow_variant_count',
    'example_case_groups',
]

L1_SUMMARY_FIELDS = [
    'scope',
    'l1_code',
    'l1_label',
    'deduped_patch_count',
    'raw_record_count',
    'deduped_share',
    'raw_share',
]


def build_taxonomy_summary_rows(records: list[PatchRecord]) -> list[dict[str, str]]:
    buckets: dict[tuple[str, str, str], list[PatchRecord]] = defaultdict(list)
    for record in records:
        buckets[(record.patch_direction, record.l1_code, record.l2_code)].append(record)

    total_raw = len(records)
    total_dedup = len({record.dedupe_key for record in records})
    raw_by_direction = Counter(record.patch_direction for record in records)
    dedup_by_direction = Counter(record.patch_direction for record in dedupe_records(records))

    rows: list[dict[str, str]] = []
    for (direction, l1_code, l2_code), members in sorted(
        buckets.items(),
        key=lambda item: (-len({record.dedupe_key for record in item[1]}), item[0]),
    ):
        dedupe_count = len({record.dedupe_key for record in members})
        example_case_groups = sorted({record.case_group_id for record in members})[:5]
        rows.append(
            {
                'patch_direction': direction,
                'l1_code': l1_code,
                'l1_label': members[0].l1_label,
                'l2_code': l2_code,
                'l2_label': members[0].l2_label,
                'deduped_patch_count': str(dedupe_count),
                'raw_record_count': str(len(members)),
                'deduped_share_overall': f'{(dedupe_count / total_dedup) if total_dedup else 0.0:.6f}',
                'raw_share_overall': f'{(len(members) / total_raw) if total_raw else 0.0:.6f}',
                'deduped_share_within_direction': (
                    f'{(dedupe_count / dedup_by_direction[direction]) if dedup_by_direction[direction] else 0.0:.6f}'
                ),
                'raw_share_within_direction': (
                    f'{(len(members) / raw_by_direction[direction]) if raw_by_direction[direction] else 0.0:.6f}'
                ),
                'cwe_count': str(len({record.cwe_id for record in members})),
                'flow_variant_count': str(len({record.flow_variant_id for record in members})),
                'example_case_groups': ' || '.join(example_case_groups),
            }
        )
    return rows


def build_l1_summary_rows(records: list[PatchRecord]) -> list[dict[str, str]]:
    deduped_records = dedupe_records(records)

    rows: list[dict[str, str]] = []
    for scope in ('overall', *DIRECTIONS):
        if scope == 'overall':
            raw_members = records
            dedup_members = deduped_records
        else:
            raw_members = [record for record in records if record.patch_direction == scope]
            dedup_members = [
                record for record in deduped_records if record.patch_direction == scope
            ]
        raw_total = len(raw_members)
        dedup_total = len(dedup_members)
        raw_counter = Counter(record.l1_code for record in raw_members)
        dedup_counter = Counter(record.l1_code for record in dedup_members)
        for l1_code, dedup_count in dedup_counter.most_common():
            rows.append(
                {
                    'scope': scope,
                    'l1_code': l1_code,
                    'l1_label': L1_DEFINITIONS[l1_code]['label'],
                    'deduped_patch_count': str(dedup_count),
                    'raw_record_count': str(raw_counter[l1_code]),
                    'deduped_share': (f'{(dedup_count / dedup_total) if dedup_total else 0.0:.6f}'),
                    'raw_share': f'{(raw_counter[l1_code] / raw_total) if raw_total else 0.0:.6f}',
                }
            )
    return rows


REVIEW_QUEUE_FIELDS = [
    'case_group_id',
    'patch_direction',
    'l1_code',
    'l2_code',
    'primary_phrase_source',
    'primary_phrase',
    'good_source',
    'good_sink',
    'representative_fix_comments',
    'representative_files',
]


def build_review_queue_rows(records: list[PatchRecord]) -> list[dict[str, str]]:
    candidates = [
        record
        for record in records
        if record.l1_code == 'other' or record.primary_phrase_source in {'none', 'code_snippet'}
    ]
    candidates.sort(
        key=lambda record: (
            record.l1_code != 'other',
            record.patch_direction,
            record.primary_phrase,
            record.case_group_id,
        )
    )
    rows: list[dict[str, str]] = []
    for record in candidates:
        row = patch_record_row(record)
        rows.append({field: row[field] for field in REVIEW_QUEUE_FIELDS})
    return rows


def build_flow_variant_matrix_rows(records: list[PatchRecord]) -> tuple[list[str], list[list[str]]]:
    variant_ids = sorted({record.flow_variant_id for record in records}, key=int)
    row_keys = sorted(
        {(record.patch_direction, record.l1_code, record.l2_code) for record in records}
    )
    header = [
        'patch_direction',
        'l1_code',
        'l1_label',
        'l2_code',
        'l2_label',
        'total_distinct_patches',
        *variant_ids,
    ]
    rows: list[list[str]] = []
    for direction, l1_code, l2_code in row_keys:
        members = [
            record
            for record in records
            if record.patch_direction == direction
            and record.l1_code == l1_code
            and record.l2_code == l2_code
        ]
        total_distinct = len({record.dedupe_key for record in members})
        per_variant: dict[str, int] = {}
        for variant_id in variant_ids:
            per_variant[variant_id] = len(
                {record.dedupe_key for record in members if record.flow_variant_id == variant_id}
            )
        rows.append(
            [
                direction,
                l1_code,
                members[0].l1_label,
                l2_code,
                members[0].l2_label,
                str(total_distinct),
                *[str(per_variant[variant_id]) for variant_id in variant_ids],
            ]
        )
    return header, rows


DIRECTION_SUMMARY_FIELDS = [
    'patch_direction',
    'raw_record_count',
    'deduped_patch_count',
    'raw_share',
    'deduped_share',
    'duplication_factor',
    'unique_l1_count',
    'unique_l2_count',
]


def dedupe_records(records: list[PatchRecord]) -> list[PatchRecord]:
    by_key: dict[str, PatchRecord] = {}
    for record in records:
        by_key.setdefault(record.dedupe_key, record)
    return list(by_key.values())


def build_direction_summary_rows(records: list[PatchRecord]) -> list[dict[str, str]]:
    raw_total = len(records)
    deduped_records = dedupe_records(records)
    dedup_total = len(deduped_records)
    rows: list[dict[str, str]] = []
    for direction in DIRECTIONS:
        raw_members = [record for record in records if record.patch_direction == direction]
        dedup_members = [
            record for record in deduped_records if record.patch_direction == direction
        ]
        raw_count = len(raw_members)
        dedup_count = len(dedup_members)
        rows.append(
            {
                'patch_direction': direction,
                'raw_record_count': str(raw_count),
                'deduped_patch_count': str(dedup_count),
                'raw_share': f'{(raw_count / raw_total) if raw_total else 0.0:.6f}',
                'deduped_share': f'{(dedup_count / dedup_total) if dedup_total else 0.0:.6f}',
                'duplication_factor': f'{(raw_count / dedup_count) if dedup_count else 0.0:.6f}',
                'unique_l1_count': str(len({record.l1_code for record in dedup_members})),
                'unique_l2_count': str(len({record.l2_code for record in dedup_members})),
            }
        )
    return rows


def build_cwe_l1_matrix_rows(records: list[PatchRecord]) -> tuple[list[str], list[list[str]]]:
    deduped_records = dedupe_records(records)
    cwe_ids = sorted({record.cwe_id for record in deduped_records}, key=lambda item: int(item[3:]))
    l1_labels = [
        definition['label']
        for code, definition in L1_DEFINITIONS.items()
        if any(record.l1_code == code for record in deduped_records)
    ]
    header = ['cwe_id', *l1_labels, 'total_distinct_patches']
    rows: list[list[str]] = []
    for cwe_id in cwe_ids:
        members = [record for record in deduped_records if record.cwe_id == cwe_id]
        counter = Counter(record.l1_label for record in members)
        rows.append(
            [cwe_id, *[str(counter.get(label, 0)) for label in l1_labels], str(len(members))]
        )
    return header, rows


def counter_entropy(counter: Counter[str]) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        probability = count / total
        entropy -= probability * math.log2(probability)
    return entropy


def build_statistics_payload(records: list[PatchRecord]) -> dict[str, object]:
    deduped_records = dedupe_records(records)
    raw_total = len(records)
    dedup_total = len(deduped_records)

    raw_l1 = Counter(record.l1_label for record in records)
    dedup_l1 = Counter(record.l1_label for record in deduped_records)
    raw_l2 = Counter((record.patch_direction, record.l2_label) for record in records)
    dedup_l2 = Counter((record.patch_direction, record.l2_label) for record in deduped_records)
    raw_flow = Counter(record.flow_variant_id for record in records)
    dedup_cwe = Counter(record.cwe_id for record in deduped_records)

    direction_rows = build_direction_summary_rows(records)
    return {
        'counts': {
            'raw_patch_records': raw_total,
            'deduped_patch_records': dedup_total,
            'raw_to_dedup_ratio': (raw_total / dedup_total) if dedup_total else 0.0,
            'taxonomy_l1_categories': len(dedup_l1),
            'taxonomy_l2_categories': len({record.l2_code for record in deduped_records}),
        },
        'direction_summary': direction_rows,
        'l1_distribution': [
            {'l1_label': label, 'raw_count': raw_l1[label], 'deduped_count': dedup_l1[label]}
            for label, _count in dedup_l1.most_common()
        ],
        'top_l2_distribution': [
            {
                'patch_direction': direction,
                'l2_label': label,
                'deduped_count': count,
                'raw_count': raw_l2[(direction, label)],
            }
            for (direction, label), count in dedup_l2.most_common(25)
        ],
        'top_cwes': [
            {'cwe_id': cwe_id, 'deduped_patch_count': count}
            for cwe_id, count in dedup_cwe.most_common(25)
        ],
        'top_flow_variants_raw': [
            {'flow_variant_id': variant_id, 'raw_record_count': count}
            for variant_id, count in raw_flow.most_common(15)
        ],
        'concentration': {
            'l1_entropy_bits': counter_entropy(dedup_l1),
            'l2_entropy_bits': counter_entropy(
                Counter(f'{direction}|{label}' for direction, label in dedup_l2.elements())
            ),
        },
    }


def build_statistics_report_md(stats_payload: dict[str, object]) -> str:
    counts = stats_payload['counts']
    direction_rows = stats_payload['direction_summary']
    l1_distribution = stats_payload['l1_distribution']
    top_l2_distribution = stats_payload['top_l2_distribution']
    top_cwes = stats_payload['top_cwes']
    top_flow_variants_raw = stats_payload['top_flow_variants_raw']
    concentration = stats_payload['concentration']

    lines = [
        '# Juliet Patch Taxonomy Statistical Analysis',
        '',
        '## Headline Metrics',
        '',
        f'- Raw patch records: **{counts["raw_patch_records"]}**',
        f'- Deduped patch records: **{counts["deduped_patch_records"]}**',
        f'- Raw/dedup ratio: **{counts["raw_to_dedup_ratio"]:.2f}x**',
        f'- L1 categories: **{counts["taxonomy_l1_categories"]}**',
        f'- L2 categories: **{counts["taxonomy_l2_categories"]}**',
        '',
        '## Direction Summary',
        '',
    ]
    for row in direction_rows:
        lines.append(
            f'- `{row["patch_direction"]}`: raw={row["raw_record_count"]}, '
            f'deduped={row["deduped_patch_count"]}, duplication={float(row["duplication_factor"]):.2f}x'
        )
    lines.extend(['', '## L1 Distribution (deduped)', ''])
    for item in l1_distribution[:12]:
        lines.append(
            f'- {item["l1_label"]}: deduped={item["deduped_count"]}, raw={item["raw_count"]}'
        )
    lines.extend(['', '## Top L2 Types (deduped)', ''])
    for item in top_l2_distribution[:20]:
        lines.append(
            f'- `{item["patch_direction"]}` / {item["l2_label"]}: '
            f'deduped={item["deduped_count"]}, raw={item["raw_count"]}'
        )
    lines.extend(['', '## Top CWEs (deduped)', ''])
    for item in top_cwes[:15]:
        lines.append(f'- {item["cwe_id"]}: {item["deduped_patch_count"]}')
    lines.extend(['', '## Top Flow Variants (raw)', ''])
    for item in top_flow_variants_raw[:10]:
        lines.append(f'- {item["flow_variant_id"]}: {item["raw_record_count"]}')
    lines.extend(
        [
            '',
            '## Diversity Signals',
            '',
            f'- L1 entropy: **{concentration["l1_entropy_bits"]:.3f} bits**',
            f'- L2 entropy: **{concentration["l2_entropy_bits"]:.3f} bits**',
            '',
        ]
    )
    return '\n'.join(lines).rstrip() + '\n'


def build_taxonomy_definition_md(
    *,
    records: list[PatchRecord],
    summary_rows: list[dict[str, str]],
    sample_per_type: int,
) -> str:
    l1_counts = Counter(record.l1_code for record in records)
    other_count = l1_counts.get('other', 0)
    total_records = len(records)
    lines = [
        '# Juliet Patch Taxonomy',
        '',
        '## Scope',
        '',
        '- Dataset: `juliet-test-suite-v1.3/C/testcases`',
        '- Record unit: one direction-specific patched counterpart per case-group and flow variant',
        '- Direction split: `goodB2G` (sink guard) vs `goodG2B` (source prevention)',
        '- Flow variants are kept as a separate analysis axis, not part of the taxonomy identity.',
        '',
        '## MECE Signals',
        '',
        f'- Raw patch records: **{total_records}**',
        f'- L1 categories used: **{len({record.l1_code for record in records})}**',
        f'- `other` fallback records: **{other_count}** ({(other_count / total_records * 100) if total_records else 0:.2f}%)',
        '- Review queue contains `other` or weak-primary-phrase records for the next refinement pass.',
        '',
        '## L1 Taxonomy',
        '',
    ]
    for l1_code, definition in L1_DEFINITIONS.items():
        if l1_code not in l1_counts:
            continue
        lines.append(f'### {definition["label"]} (`{l1_code}`)')
        lines.append('')
        lines.append(f'- Definition: {definition["description"]}')
        lines.append(f'- Raw records: {l1_counts[l1_code]}')
        l2_rows = [row for row in summary_rows if row['l1_code'] == l1_code]
        l2_rows.sort(key=lambda row: (-int(row['deduped_patch_count']), row['l2_code']))
        for row in l2_rows[: sample_per_type * 5]:
            lines.append(
                f'- `{row["patch_direction"]}` / `{row["l2_code"]}`: '
                f'{row["l2_label"]} '
                f'(deduped={row["deduped_patch_count"]}, raw={row["raw_record_count"]})'
            )
        lines.append('')

    lines.extend(['## Representative Examples', ''])
    keyed_records: dict[tuple[str, str, str], list[PatchRecord]] = defaultdict(list)
    for record in records:
        keyed_records[(record.patch_direction, record.l1_code, record.l2_code)].append(record)
    for row in summary_rows[: max(sample_per_type * 12, 1)]:
        key = (row['patch_direction'], row['l1_code'], row['l2_code'])
        examples = keyed_records[key][:sample_per_type]
        lines.append(f'### {row["patch_direction"]} / {row["l1_label"]} / {row["l2_label"]}')
        lines.append('')
        for record in examples:
            files = ', '.join(Path(item).name for item in record.representative_files[:2])
            snippet = (
                record.representative_code_snippets[0]
                if record.representative_code_snippets
                else ''
            )
            lines.append(f'- `{record.case_group_id}` ({files})')
            if snippet:
                lines.append(f'  - Snippet: `{snippet}`')
            if record.representative_fix_comments:
                lines.append(f'  - FIX: {record.representative_fix_comments[0]}')
        lines.append('')
    return '\n'.join(lines).rstrip() + '\n'


def write_dict_rows(path: Path, header: list[str], rows: list[dict[str, str]]) -> None:
    write_csv_rows(path, header, ([row.get(field, '') for field in header] for row in rows))


def default_artifacts(output_dir: Path) -> AnalysisArtifacts:
    return AnalysisArtifacts(
        patch_records_jsonl=output_dir / 'patch_records.jsonl',
        patch_records_csv=output_dir / 'patch_records.csv',
        l1_summary_csv=output_dir / 'l1_summary.csv',
        taxonomy_summary_csv=output_dir / 'taxonomy_summary.csv',
        flow_variant_matrix_csv=output_dir / 'flow_variant_matrix.csv',
        direction_summary_csv=output_dir / 'direction_summary.csv',
        cwe_l1_matrix_csv=output_dir / 'cwe_l1_matrix.csv',
        taxonomy_definition_md=output_dir / 'taxonomy_definition.md',
        summary_json=output_dir / 'summary.json',
        statistics_json=output_dir / 'statistics.json',
        statistics_report_md=output_dir / 'statistics_report.md',
        review_queue_csv=output_dir / 'taxonomy_review_queue.csv',
    )


def export_juliet_patch_taxonomy(
    *,
    juliet_root: Path,
    output_dir: Path,
    sample_per_type: int = 3,
) -> dict[str, object]:
    records = analyze_juliet_patch_taxonomy(juliet_root)
    artifacts = default_artifacts(output_dir)

    patch_rows = [patch_record_row(record) for record in records]
    write_jsonl(artifacts.patch_records_jsonl, patch_rows)
    write_dict_rows(artifacts.patch_records_csv, PATCH_RECORD_FIELDS, patch_rows)

    l1_summary_rows = build_l1_summary_rows(records)
    write_dict_rows(artifacts.l1_summary_csv, L1_SUMMARY_FIELDS, l1_summary_rows)

    summary_rows = build_taxonomy_summary_rows(records)
    write_dict_rows(artifacts.taxonomy_summary_csv, SUMMARY_FIELDS, summary_rows)

    matrix_header, matrix_rows = build_flow_variant_matrix_rows(records)
    write_csv_rows(artifacts.flow_variant_matrix_csv, matrix_header, matrix_rows)

    direction_summary_rows = build_direction_summary_rows(records)
    write_dict_rows(
        artifacts.direction_summary_csv, DIRECTION_SUMMARY_FIELDS, direction_summary_rows
    )

    cwe_header, cwe_rows = build_cwe_l1_matrix_rows(records)
    write_csv_rows(artifacts.cwe_l1_matrix_csv, cwe_header, cwe_rows)

    review_rows = build_review_queue_rows(records)
    write_dict_rows(artifacts.review_queue_csv, REVIEW_QUEUE_FIELDS, review_rows)

    taxonomy_md = build_taxonomy_definition_md(
        records=records,
        summary_rows=summary_rows,
        sample_per_type=sample_per_type,
    )
    artifacts.taxonomy_definition_md.parent.mkdir(parents=True, exist_ok=True)
    artifacts.taxonomy_definition_md.write_text(taxonomy_md, encoding='utf-8')

    statistics_payload = build_statistics_payload(records)
    write_json(artifacts.statistics_json, statistics_payload)
    artifacts.statistics_report_md.write_text(
        build_statistics_report_md(statistics_payload),
        encoding='utf-8',
    )

    unique_dedupe_keys = {record.dedupe_key for record in records}
    direction_counts = Counter(record.patch_direction for record in records)
    l1_counts = Counter(record.l1_code for record in records)
    review_rows_count = len(review_rows)
    summary_payload = {
        'artifacts': {
            field: str(getattr(artifacts, field)) for field in artifacts.__dataclass_fields__
        },
        'stats': {
            'counts': {
                'case_groups': len({record.case_group_id for record in records}),
                'raw_patch_records': len(records),
                'deduped_patch_records': len(unique_dedupe_keys),
                'taxonomy_l1_categories': len({record.l1_code for record in records}),
                'taxonomy_l2_categories': len({record.l2_code for record in records}),
                'review_queue_records': review_rows_count,
            },
            'directions': dict(sorted(direction_counts.items())),
            'l1_counts': dict(sorted(l1_counts.items())),
            'flow_variants': sorted({record.flow_variant_id for record in records}, key=int),
            'mece_signals': {
                'other_raw_records': l1_counts.get('other', 0),
                'other_ratio': (l1_counts.get('other', 0) / len(records) if records else 0.0),
                'review_queue_ratio': review_rows_count / len(records) if records else 0.0,
            },
            'statistical_analysis': {
                'statistics_json': str(artifacts.statistics_json),
                'statistics_report_md': str(artifacts.statistics_report_md),
                'direction_summary_csv': str(artifacts.direction_summary_csv),
                'cwe_l1_matrix_csv': str(artifacts.cwe_l1_matrix_csv),
            },
        },
    }
    write_json(artifacts.summary_json, summary_payload)
    return summary_payload


def format_top_taxonomy_rows(path: Path, limit: int = 12) -> str:
    with path.open('r', newline='', encoding='utf-8') as f:
        rows = list(csv.DictReader(f))
    preview = rows[:limit]
    lines = []
    for row in preview:
        lines.append(
            f'{row["patch_direction"]}: {row["l1_label"]} / {row["l2_label"]} '
            f'(deduped={row["deduped_patch_count"]}, raw={row["raw_record_count"]})'
        )
    return '\n'.join(lines)
