# juliet-playground

Juliet Test Suite v1.3(C/C++)를 기반으로, AI 학습용 **취약 trace / 패치 trace** 데이터를 구축하는 저장소입니다.

## 목표
- source / sink를 일관된 형태로 추출
- source / sink 줄번호(line number) 식별
- 패치(trace) 관점에서 good/bad 흐름 연결

## Repository Layout
- `juliet-test-suite-v1.3/`: 원본 데이터(가급적 read-only)
- `experiments/`: 실험 단위 작업 (`expNNN_*`)
- `tools/`: 실험에서 검증되어 재사용 가능한 공용 스크립트
- `data/manifests/`: 처리 대상 축소/선정 기준 (subset 정의)
- `data/interim/`: 정규화·중복제거·매칭 등 중간 산출물
- `data/final/`: 학습/평가에 사용하는 최종 데이터셋
- `docs/labeling_rules.md`: source/sink/patch 판정 규칙
- `docs/decisions/`: 설계 결정 기록(ADR 스타일)

## Output Format (JSONL)
모든 추출 결과는 JSONL 1레코드/1라인 형식을 권장합니다.

필수 키:
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
1. 실험은 반드시 `experiments/expNNN_*` 아래에서 수행
2. 재사용 가치가 생기면 `tools/`로 승격
3. 최종 산출물은 `data/final/`에만 확정 저장
