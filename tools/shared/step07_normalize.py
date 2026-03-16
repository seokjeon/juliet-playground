from __future__ import annotations

import hashlib


def lex_c_like(code: str) -> list[dict[str, str]]:
    tokens: list[dict[str, str]] = []
    i = 0
    n = len(code)

    while i < n:
        ch = code[i]

        if ch.isspace():
            j = i + 1
            while j < n and code[j].isspace():
                j += 1
            tokens.append({'kind': 'ws', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('//', i):
            j = i + 2
            while j < n and code[j] != '\n':
                j += 1
            tokens.append({'kind': 'comment', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('/*', i):
            j = i + 2
            while j < n - 1 and code[j : j + 2] != '*/':
                j += 1
            j = min(n, j + 2 if j < n - 1 else n)
            tokens.append({'kind': 'comment', 'text': code[i:j]})
            i = j
            continue

        if ch == '"':
            j = i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == '"':
                    j += 1
                    break
                j += 1
            tokens.append({'kind': 'string', 'text': code[i:j]})
            i = j
            continue

        if ch == "'":
            j = i + 1
            while j < n:
                if code[j] == '\\':
                    j += 2
                    continue
                if code[j] == "'":
                    j += 1
                    break
                j += 1
            tokens.append({'kind': 'char', 'text': code[i:j]})
            i = j
            continue

        if ch.isalpha() or ch == '_':
            j = i + 1
            while j < n and (code[j].isalnum() or code[j] == '_'):
                j += 1
            tokens.append({'kind': 'identifier', 'text': code[i:j]})
            i = j
            continue

        if code.startswith('->', i) or code.startswith('::', i):
            tokens.append({'kind': 'punct', 'text': code[i : i + 2]})
            i += 2
            continue

        tokens.append({'kind': 'punct', 'text': ch})
        i += 1

    return tokens


def previous_meaningful_token(tokens: list[dict[str, str]], index: int) -> dict[str, str] | None:
    for j in range(index - 1, -1, -1):
        token = tokens[j]
        if token['kind'] in {'ws', 'comment'}:
            continue
        return token
    return None


def next_meaningful_token(tokens: list[dict[str, str]], index: int) -> dict[str, str] | None:
    for j in range(index + 1, len(tokens)):
        token = tokens[j]
        if token['kind'] in {'ws', 'comment'}:
            continue
        return token
    return None


def normalize_slice_function_names(
    code: str, user_defined_function_names: set[str]
) -> tuple[str, dict[str, str], int]:
    if not user_defined_function_names:
        return code, {}, 0

    tokens = lex_c_like(code)
    placeholder_map: dict[str, str] = {}
    replacements = 0

    for idx, token in enumerate(tokens):
        if token['kind'] != 'identifier':
            continue
        name = token['text']
        if name not in user_defined_function_names:
            continue

        prev_token = previous_meaningful_token(tokens, idx)
        next_token = next_meaningful_token(tokens, idx)

        if next_token is None or next_token['text'] != '(':
            continue
        if prev_token is not None and prev_token['text'] in {'.', '->', '::'}:
            continue

        placeholder = placeholder_map.get(name)
        if placeholder is None:
            placeholder = f'FUNC_{len(placeholder_map) + 1}'
            placeholder_map[name] = placeholder
        if token['text'] != placeholder:
            token['text'] = placeholder
            replacements += 1

    return ''.join(token['text'] for token in tokens), placeholder_map, replacements


def compact_code_for_hash(code: str) -> str:
    return ''.join(str(code).split())


def normalized_code_md5(code: str) -> str:
    return hashlib.md5(compact_code_for_hash(code).encode('utf-8')).hexdigest()
