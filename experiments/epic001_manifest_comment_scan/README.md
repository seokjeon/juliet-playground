# epic001_manifest_comment_scan

`manifest.xml`의 각 `file` 항목을 실제 소스 파일에 매핑해 다음 주석 시작 라인을 탐지합니다.

- `/* ... FLAW` (단, `INCIDENTAL FLAW` 제외)
- `/* FIX`

탐지 결과는 각 `file` 하위에 아래 태그로 추가됩니다.

- `<comment_flaw line="N" code="..." function="..."/>`
- `<comment_fix line="N" code="..." function="..."/>`

## 태그 속성
- `line`: 주석과 매핑된 대상 코드 라인 번호
- `code`: 대상 코드 1줄(양끝 공백 제거)
- `function`: 해당 라인이 속한 함수명(tree-sitter 기반)

## 동작 규칙
- 인라인 주석(`코드 + /* FLAW|FIX */`)은 같은 줄 코드 노드를 사용하고 `code`에 `[INLINE] ` 접두사를 붙입니다.
- 일반 주석은 tree-sitter `comment` 노드의 `next_named_sibling`을 대상 코드로 사용합니다.
- 대상 코드를 찾지 못하면 `line`은 주석 라인, `code="WARNING_NOT_FOUND"`로 기록합니다.
- 함수 span에 매핑되지 않는 주석은 XML에 추가하지 않고 `dropped_comment_lines`로 집계합니다.

## 스캔 범위/제약
- 소스 인덱싱 확장자: `.c`, `.cpp`, `.h`
- 실제 주석 스캔/함수 파싱 대상: `.c`, `.cpp` (`.h`는 스킵)
- tree-sitter 파서 로드 실패 또는 파일 파싱 실패 시 해당 파일은 `parse_failed_files`로 집계하고 스킵합니다.
- 파일 매핑은 manifest의 `file@path`(파일명)를 기준으로 해당 testcase의 CWE 디렉터리 안에서만 찾습니다.
- `--source-root`는 `juliet-test-suite-v1.3/C` 또는 `juliet-test-suite-v1.3/C/testcases` 둘 다 사용할 수 있습니다.

## 구조
- `scripts/scan_manifest_comments.py`: 스캔/태깅 실행
- `scripts/report.py`: 요약 통계 출력
- `inputs/manifest.xml`: 입력 manifest
- `outputs/manifest_with_comments.xml`: 결과 XML

## 설치
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt # tree-sitter 의존성 설치
```

## 실행
```bash
python experiments/epic001_manifest_comment_scan/scripts/scan_manifest_comments.py \
  --manifest experiments/epic001_manifest_comment_scan/inputs/manifest.xml \
  --source-root juliet-test-suite-v1.3/C \
  --output-xml experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml
```

실행 후 콘솔에 1줄 JSON 요약이 출력됩니다.

요약 필드:
- `output_xml`, `total_files`, `scanned_files`, `missing_files`, `parse_failed_files`, `dropped_comment_lines`

## outputs 참고
현재 스크립트가 직접 생성하는 산출물은 `manifest_with_comments.xml`(+ 콘솔 JSON)입니다.
`manifest_comment_scan_report.jsonl`, `dropped_comments.jsonl`는 현 스크립트 기준 산출물이 아니며 `outputs/legacy/`에 분리 보관되어 있습니다.
