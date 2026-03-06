# juliet-playground

Juliet Test Suite v1.3(C/C++)를 기반으로, AI 학습용 **취약 trace / 패치 trace** 데이터를 구축하는 저장소입니다.

## 목표
- source / sink를 일관된 형태로 추출
- source / sink 줄번호(line number) 식별
- 패치(trace) 관점에서 good/bad 흐름 연결

## Repository Layout
- `juliet-test-suite-v1.3/`: 원본 데이터(가급적 read-only)
- `experiments/`: 실험 단위 작업 (`epicNNN_*`)
  - 실험 결과는 각 실험의 `outputs/`에 저장
- `tools/`: 실험에서 검증되어 재사용 가능한 공용 스크립트
- `data/artifacts/`: `tools/` 실행 부산물(로그/검증 출력/중간 산출물)
- `data/final/`: 최신 확정본 산출물(`manifest.xml`, `source.lst`, `sink.lst`)
- `docs/labeling_rules.md`: source/sink/patch 판정 규칙
- `docs/decisions/`: 설계 결정 기록(ADR 스타일)

## Output Format
출력 형식은 실험 목적에 따라 유연하게 선택합니다(JSONL/CSV/TSV/기타).

trace 추출에는 JSONL을 권장하며, JSONL 사용 시 권장 키는 아래와 같습니다.

권장 키:
- `file`: 원본 파일 경로
- `cwe`: CWE 식별자 (예: `CWE476`)
- `kind`: `source` | `sink` | `patch`
- `line`: 줄번호(1-based)
- `evidence`: 근거 텍스트(주석/코드 일부)

예시:
```json
{"file":"juliet-test-suite-v1.3/C/testcases/.../CWE476_xxx.c","cwe":"CWE476","kind":"source","line":42,"evidence":"POTENTIAL FLAW: Set data to NULL"}
{"file":"juliet-test-suite-v1.3/C/testcases/.../CWE476_xxx.c","cwe":"CWE476","kind":"sink","line":49,"evidence":"Attempt to use data, which may be NULL"}
{"file":"juliet-test-suite-v1.3/C/testcases/.../CWE476_xxx.c","cwe":"CWE476","kind":"patch","line":71,"evidence":"FIX: Check for NULL before attempting to print data"}
```

## Working Rules
1. 실험은 반드시 `experiments/epicNNN_*` 아래에서 수행
2. 재사용 가치가 생기면 `tools/`로 승격
3. 실험 결과는 `experiments/epicNNN_*/outputs/`에 저장
4. `tools/` 실행 부산물은 `data/artifacts/`에 저장
5. 최종 확정본은 `data/final/`에만 저장
6. 버전 관리는 GitHub Release로 수행하고, Release Note에 기준 커밋 SHA를 기록

## Issue Tracking Rules
- 이슈는 `.github/ISSUE_TEMPLATE`의 `Epic / Story / Task` 템플릿을 사용합니다.
- 라벨 운영:
  - `epic`: 큰 목표/가치 단위 이슈
  - `story`: 사용자 가치 단위 이슈 (반드시 상위 Epic 연결)
  - `task`: 실행/구현 단위 이슈 (반드시 상위 Story 연결)
- 권장 규칙:
  - 하나의 이슈에는 `epic|story|task` 중 **하나만** 부여
  - Story 완료 기준은 수용 기준(AC) 충족
  - Task 완료 기준은 산출물 경로 + 검증 방법 확인
