# epic001_good_bad_marker

## 목적
CWE-476에서 `FLAW/FIX` 마커 아래 라인을 이용해 good/bad 라인을 1차 추출하고,
`line_text`를 함께 저장해 유효 구문 여부를 검증한다.

## 가설
- `/* ... FLAW ... */` 바로 아래(공백/주석 스킵)의 첫 유효 구문 라인은 `bad`
- `/* FIX ... */` 바로 아래(공백/주석 스킵)의 첫 유효 구문 라인은 `good`

## 범위
- 대상: `juliet-test-suite-v1.3/C/testcases/CWE476_NULL_Pointer_Dereference/**/*.c`
- 제외: source/sink 분류, 패치 매핑, 타 CWE

## 라인 선택/검증 규칙
1. 마커 식별: 주석 내 `FLAW` 또는 `FIX` 문자열 포함 시 대상
2. 라인 선택: 마커 이후 라인에서 공백/주석만 건너뛴 첫 라인 채택
3. 유효 구문(휴리스틱): 실행문/선언문/제어문 시작 라인 허용
4. 제외 규칙: 중괄호 단독 라인 `{` / `}` 는 유효 구문에서 제외

## 출력 (manifest.xml 유사 구조)
- 메인 산출물: `outputs/good_bad_lines.xml`
- 검증 리포트: `outputs/verify_report.md`
- 특이 케이스 CSV: `outputs/special_cases.csv` (`is_valid_syntax=false`만)
- 샘플 리뷰: `outputs/sample_review.md` (수동 작성)
- 실패 리포트(필요 시): `outputs/failure_report.md`

### XML 구조
```xml
<container>
  <testcase>
    <file path="CWE476_..._01.c">
      <flaw line="34" name="CWE-476: NULL Pointer Dereference" line_text="..." evidence="..." is_valid_syntax="true" validation_reason="semicolon_statement"/>
      <fix  line="59" name="CWE-476: NULL Pointer Dereference" line_text="..." evidence="..." is_valid_syntax="true" validation_reason="control_statement"/>
    </file>
  </testcase>
</container>
```

## 재현 명령
```bash
python experiments/epic001_good_bad_marker/scripts/extract_good_bad_lines.py \
  --input juliet-test-suite-v1.3/C/testcases/CWE476_NULL_Pointer_Dereference \
  --manifest juliet-test-suite-v1.3/C/manifest.xml \
  --output experiments/epic001_good_bad_marker/outputs/good_bad_lines.xml
```

## 검증 명령
```bash
python experiments/epic001_good_bad_marker/scripts/verify_good_bad_lines.py \
  --xml experiments/epic001_good_bad_marker/outputs/good_bad_lines.xml \
  --input juliet-test-suite-v1.3/C/testcases/CWE476_NULL_Pointer_Dereference \
  --manifest juliet-test-suite-v1.3/C/manifest.xml \
  --report experiments/epic001_good_bad_marker/outputs/verify_report.md
```

## 특이 케이스 CSV 생성
```bash
python experiments/epic001_good_bad_marker/scripts/export_special_cases_csv.py \
  --xml experiments/epic001_good_bad_marker/outputs/good_bad_lines.xml \
  --out experiments/epic001_good_bad_marker/outputs/special_cases.csv
```

## 특이 케이스 검토 순서 (manual QA 전처리)
1. `validation_reason` 기준으로 묶어서 확인
2. 같은 reason 내에서 `file`, `line` 순으로 검토
3. 필요 시 `sample_review.md`에 판단 근거 기록

## 참고
- 추출 스크립트: `scripts/extract_good_bad_lines.py`
- 검증 스크립트: `scripts/verify_good_bad_lines.py`
- 특이 케이스 CSV 스크립트: `scripts/export_special_cases_csv.py`
