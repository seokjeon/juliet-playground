# Stage contracts

현재 파이프라인의 **실제 구현 단계**를 순서대로 정리한 문서입니다.

이 문서는 먼저 **지금 코드가 실제로 어떻게 동작하는지**를 정확히 적습니다.
단계 병합이나 개념 단계 재정리는 그 다음 문제로 보고, 여기서는 우선 현재 구현을
`tools/run_pipeline.py` 기준으로 기록합니다.

특히 이 문서는 **테스트 작성을 위한 계약 문서**를 목표로 합니다.
따라서 각 단계에서 다음을 구분하려고 합니다.

- downstream이 실제로 기대하는 **계약 항목**
- 테스트에서 꼭 확인해야 하는 **필수 필드 / 태그 / 파일**
- golden diff로 볼 수는 있지만 **핵심 계약으로 보기 어려운 항목**


> **2026-03 compact contract note**
> 
> 현재 코드 기준으로 `02a`, `02b`, `03`, `04`, `05`, `06`, `07`, `07b` 의 summary JSON 은
> 기본적으로 `{"artifacts": {...}, "stats": {...}}` 형태의 **compact summary** 를 사용합니다.
> 이전의 verbose summary key, selection summary, dedup/token auxiliary outputs 관련 설명과
> 충돌하는 오래된 항목이 있다면 **현재 코드와 tests가 우선**입니다.

## 범위

기준 구현:

- `tools/run_pipeline.py`

참조 스크립트:

- `experiments/epic001_manifest_comment_scan/scripts/scan_manifest_comments.py`
- `experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py`
- `experiments/epic001b_function_inventory/scripts/extract_function_inventory.py`
- `experiments/epic001b_function_inventory/scripts/categorize_function_names.py`
- `experiments/epic001c_testcase_flow_partition/scripts/add_flow_tags_to_testcase.py`
- `tools/stage/stage03_infer.py`
- `tools/stage/stage03_signature.py`
- `experiments/epic001d_trace_flow_filter/scripts/filter_traces_by_flow.py`
- `tools/stage/stage05_pair_trace.py`
- `tools/stage/stage06_slices.py`
- `tools/stage/stage07b_patched_export.py`

## 읽는 법

- 이 문서의 “단계”는 **현재 파이프라인이 실제로 실행하는 물리 단계**입니다.
- 각 단계는 다음 네 가지를 중심으로 적습니다.
  - 무엇을 실행하는가
  - 무엇을 입력으로 받는가
  - 무엇을 다음 단계에 넘기는가
  - `run_pipeline.py`가 호출하는 오케스트레이션이 어떤 산출물 존재를 실제로 검사하는가
- 테스트를 쓸 때는 가능하면
  - **계약 체크(invariant / schema / required fields)** 와
  - **golden regression check**
  를 구분하는 쪽을 권장합니다.

## 전체 실행 순서

현재 구현의 실제 실행 순서는 아래와 같습니다.

1. `01_manifest_comment_scan`
2. `02a_code_field_inventory`
3. `02b_function_inventory_extract`
4. `02b_function_inventory_categorize`
5. `02b_testcase_flow_partition`
6. taint config 선택 (`tools/run_pipeline.py` 내부 분기)
7. `03_infer_and_signature`
8. `04_trace_flow_filter`
9. `05_pair_trace_dataset`
10. `06_generate_slices`
11. `07_dataset_export`
12. `07b_train_patched_counterparts_export`

---

## 공통 입력

`tools/run_pipeline.py full` 은 아래 입력을 받습니다.

- `cwes` 또는 `--all` 또는 `--files`
- `--manifest`
- `--source-root`
- `--pipeline-root`
- `--run-id`
- `--committed-taint-config`
- `--pair-split-seed`
- `--pair-train-ratio`
- `--dedup-mode`

기본 run 디렉터리는 다음 구조를 사용합니다.

- `01_manifest/`
- `02a_taint/`
- `02b_flow/`
- `03_infer-results/`
- `03_signatures/`
- `04_trace_flow/`
- `05_pair_trace_ds/`
- `06_slices/`
- `07_dataset_export/`
- `logs/`
- `run_summary.json`

---

## 1. `01_manifest_comment_scan`

### 실행 스크립트
- `experiments/epic001_manifest_comment_scan/scripts/scan_manifest_comments.py`

### 입력
- `--manifest <manifest>`
- `--source-root <source_root>`

### 출력 경로
- `01_manifest/manifest_with_comments.xml`

### 다음 단계로 넘기는 핵심 출력
- `manifest_with_comments.xml`

### 현재 코드가 실제로 하는 일
- manifest와 source tree를 읽어 comment 정보가 포함된 manifest를 생성합니다.
- 이후 `02a`, `02b_extract`, `02b_categorize`, `02b_flow_partition` 가 모두 이 결과를 사용합니다.

### XML에서 실제로 바뀌는 것
현재 구현은 기존 manifest 구조를 크게 바꾸지 않고, 각 `<file>` 아래에 새 태그를 추가합니다.

- 추가 가능한 태그:
  - `<comment_flaw ... />`
  - `<comment_fix ... />`

현재 코드상 새 태그는 아래 속성으로 생성됩니다.

- `line`
- `code`
- `function`

생성 코드는 실제로 아래 형태입니다.

```python
ET.SubElement(
    file_elem,
    tag,
    {"line": str(line_no), "code": code_text, "function": function_name},
)
```

즉 Stage 01의 핵심 계약은
**“기존 manifest의 `<file>` 아래에 `comment_flaw/comment_fix(line, code, function)` 를 추가한 XML”**
이라고 볼 수 있습니다.

### downstream이 실제로 쓰는 필드
Stage 01 출력의 새 태그/속성은 이후 단계에서 직접 사용됩니다.

- `02a_code_field_inventory`
  - `comment_flaw`, `comment_fix`
  - `line`
  - `code`
- `02b_function_inventory_extract`
  - `comment_flaw`, `comment_fix`
  - `function`
- `02b_function_inventory_categorize`
  - `file/path`
  - `comment_flaw`, `comment_fix`
  - `function`
- `02b_testcase_flow_partition`
  - `comment_flaw`, `comment_fix`
  - `line`
  - `function`

따라서 최소 계약 관점에서 보면 Stage 01은 적어도 아래를 보장해야 합니다.

- `comment_flaw` / `comment_fix` 태그가 올바른 위치에 추가됨
- 각 태그에 `line`, `code`, `function` 이 채워짐
- `function` 이 없는 comment는 태그로 남기지 않음

### 현재 코드가 실제로 검사하는 것
- 이 단계 직후 별도 존재 검사는 하지 않습니다.
- 하지만 다음 단계들이 이 파일을 직접 입력으로 사용하므로 사실상 필수 출력입니다.

### 현재 코드상 생성 규칙
- 스캔 대상 확장자 인덱싱: `.c`, `.cpp`, `.h`
- 실제 파싱/주석 스캔 대상: `.c`, `.cpp`
- `/* ... FLAW */` 는 잡지만 `INCIDENTAL FLAW` 는 제외합니다.
- `/* FIX */` 는 `comment_fix` 로 잡습니다.
- inline comment 이면:
  - 같은 줄의 이전 named sibling 코드를 사용
  - `code` 앞에 `[INLINE] ` 를 붙입니다.
- 일반 comment 이면:
  - 다음 named sibling 코드를 사용합니다.
- 다음 코드 노드를 찾지 못하면:
  - `line` 은 comment line
  - `code` 는 `WARNING_NOT_FOUND`
- 함수 span에 매핑되지 않으면:
  - 태그를 생성하지 않고 drop 합니다.
- parse 실패 / source file missing 인 경우:
  - 해당 file에서는 태그가 추가되지 않을 수 있습니다.

### 테스트 작성용 계약 체크리스트
Stage 01 테스트는 아래 두 층으로 나누는 것이 좋습니다.

#### A. 계약 체크 테스트
가능하면 전체 XML diff와 별개로 아래를 명시적으로 검사합니다.

- 출력 파일 `manifest_with_comments.xml` 이 생성된다.
- 새로 생성된 태그 이름은 `comment_flaw`, `comment_fix` 뿐이다.
- 모든 `comment_flaw`, `comment_fix` 는 `<file>` 하위에 존재한다.
- 모든 `comment_flaw`, `comment_fix` 는 다음 속성을 가진다.
  - `line`
  - `code`
  - `function`
- `line` 은 정수로 파싱 가능하고 `> 0` 이다.
- `code.strip()` 는 비어 있지 않다.
- `function.strip()` 는 비어 있지 않다.
- `WARNING_NOT_FOUND` 는 허용되는 sentinel 값으로 본다.
- 기존 `testcase` / `file` / `flaw` 구조는 유지된다.

#### B. golden regression 테스트
아래는 전체 regression 관점에서 유용하지만, 핵심 계약과는 분리해 생각할 수 있습니다.

- XML pretty formatting / indent
- 새 태그들의 정확한 출력 순서
- summary stdout JSON 의 key 집합이 fixture와 정확히 일치한다.
- summary stdout JSON 의 각 key에 대한 값이 fixture와 정확히 일치한다.
  - 현재 구현 기준 주요 key:
    - `output_xml`
    - `total_files`
    - `scanned_files`
    - `missing_files`
    - `parse_failed_files`
    - `dropped_comment_lines`

### 테스트에서 계약으로 보기 어려운 것
아래는 현재 구현 결과일 수는 있지만, downstream 계약으로는 우선순위가 낮습니다.

- XML 들여쓰기 방식
- `comment_*` 태그의 파일 내 출력 순서 자체
- 통계용 stdout JSON 의 상세 필드 수

---


## 2. `02a_code_field_inventory`

### 실행 스크립트
- `experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py`

### 입력
- `--input-xml 01_manifest/manifest_with_comments.xml`
- `--source-root <source_root>`
- `--output-dir 02a_taint/`
- `--pulse-taint-config-output 02a_taint/pulse-taint-config.json`

### 출력 경로
- `02a_taint/pulse-taint-config.json`
- `02a_taint/function_name_macro_resolution.csv`
- `02a_taint/summary.json`

### 다음 단계로 넘기는 핵심 출력
- `02a_taint/pulse-taint-config.json` (생성되면 사용)

### 현재 코드가 실제로 하는 일
- stage core는 pulse taint config를 생성합니다.
- `function_name_macro_resolution.csv` 는 debugging용으로 함께 남깁니다.
- 그 외 inventory / candidate-map dump는 experiments 전용 산출물입니다.

### 현재 코드가 실제로 검사하는 것
- 이 단계 직후 별도 존재 검사는 하지 않습니다.
- 이후 `tools/run_pipeline.py` 내부 분기에서 `generated_taint_config.exists()` 를 확인합니다.

### downstream이 실제로 쓰는 출력
현재 파이프라인에서 직접 쓰는 것은 아래 하나입니다.

- `02a_taint/pulse-taint-config.json`

### 현재 코드상 생성 규칙
- 입력 XML에서 `<file>` 하위 태그 중 아래만 처리합니다.
  - `comment_flaw`
  - `comment_fix`
  - `flaw`
- `comment_flaw`, `comment_fix` 는 `code` 속성을 key로 사용합니다.
  - `code` 가 없으면 해당 레코드는 skip 합니다.
- `flaw` 는 `line` 기준으로 code-like key를 유도합니다.
  - source context가 없으면 `WARNING_FLAW_CODE_NOT_FOUND`
- macro 해석 후 unique function name 집합으로 pulse taint config를 생성합니다.
- `function_name_macro_resolution.csv` 는 매크로 해석 결과를 남기는 debug artifact입니다.

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 디렉터리에 최소한 아래 파일이 생성된다.
  - `pulse-taint-config.json`
  - `function_name_macro_resolution.csv`
  - `summary.json`
- `pulse-taint-config.json` 은 JSON object이다.
- `pulse-taint-config.json` 은 아래 top-level key를 가진다.
  - `pulse-taint-sources`
  - `pulse-taint-sinks`
- `pulse-taint-sources[*].taint_target` 은 현재 구현 기준
  - `ReturnValue`
  - `AllArguments`
  중 하나다.
- `pulse-taint-sinks[*].taint_target` 은 현재 구현 기준
  - `AllArguments`
  여야 한다.
- `function_name_macro_resolution.csv` 는 비어 있지 않다.
- `summary.json` 의 `artifacts` 는 아래 key를 가진다.
  - `pulse_taint_config`
  - `function_name_macro_resolution_csv`
  - `summary_json`
- `summary.json` 의 `stats.unique_function_names` 는 pulse taint config의 procedure 수와 모순되지 않아야 한다.
- `summary.json` 의 `stats.keys_with_calls` 는 `stats.candidate_map_keys` 이하이어야 한다.

#### B. golden regression 테스트
- `pulse-taint-config.json` 의 key / value 구조와 내용이 fixture와 정확히 일치한다.
- `function_name_macro_resolution.csv` 의 내용이 fixture와 정확히 일치한다.
- `summary.json` 의 key / value 구조와 내용이 fixture와 정확히 일치한다.

### 테스트에서 계약으로 보기 어려운 것
- experiments 전용 inventory dump 전체

## 3. `02b_function_inventory_extract`

### 실행 스크립트
- `experiments/epic001b_function_inventory/scripts/extract_function_inventory.py`

### 입력
- `--input-xml 01_manifest/manifest_with_comments.xml`
- `--output-csv 02b_flow/function_names_unique.csv`
- `--output-summary 02b_flow/function_inventory_summary.json`

### 출력 경로
- `02b_flow/function_names_unique.csv`
- `02b_flow/function_inventory_summary.json`

### 다음 단계로 넘기는 핵심 출력
- `02b_flow/function_names_unique.csv`

### 현재 코드가 실제로 하는 일
- function inventory를 뽑고, 다음 categorize 단계에 넘깁니다.

### 현재 코드가 실제로 검사하는 것
- 이 단계 직후 별도 존재 검사는 하지 않습니다.
- 다음 단계가 `function_names_unique.csv` 를 직접 입력으로 사용합니다.

### downstream이 실제로 쓰는 출력
- `02b_flow/function_names_unique.csv`

### 현재 코드상 생성 규칙
- 입력 XML 전체를 순회하면서 아래 태그만 셉니다.
  - `comment_flaw`
  - `comment_fix`
- 각 태그의 `function` 속성을 읽습니다.
- `function` 이 비어 있으면 count에 넣지 않고 `missing_or_empty_function` 으로 집계합니다.
- 출력 CSV는 현재 코드상 아래 컬럼을 가집니다.
  - `function_name`
  - `count`
- 정렬은 현재 코드상
  - `count` 내림차순
  - `function_name` 오름차순
  입니다.

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 파일이 생성된다.
  - `function_names_unique.csv`
  - `function_inventory_summary.json`
- `function_names_unique.csv` 가 비어 있지 않다.
- `function_inventory_summary.json` 이 JSON object 로 읽힌다.

#### B. golden regression 테스트
- `function_names_unique.csv` 는 fixture와 exact match로 본다.
  - 구현 방식은 whole-file diff 또는 md5sum 비교면 충분하다.
- `function_inventory_summary.json` 은 현재 구현상 `generated_at` 이 들어가므로
  whole-file exact match 대상에서 제외한다.
- 필요하면 summary는 아래 핵심 필드만 별도로 확인한다.
  - `total_comment_tags_seen`
  - `total_function_values`
  - `missing_or_empty_function`
  - `unique_function_names`

### 테스트에서 계약으로 보기 어려운 것
- `function_inventory_summary.json` 전체 파일의 exact match
- summary JSON 의 생성 시각
- summary 의 부가 분포 필드 전체

---

## 4. `02b_function_inventory_categorize`

### 실행 스크립트
- `experiments/epic001b_function_inventory/scripts/categorize_function_names.py`

### 입력
- `--input-csv 02b_flow/function_names_unique.csv`
- `--manifest-xml 01_manifest/manifest_with_comments.xml`
- `--source-root <source_root>/testcases`
- `--output-jsonl 02b_flow/function_names_categorized.jsonl`
- `--output-nested-json 02b_flow/grouped_family_role.json`
- `--output-summary 02b_flow/category_summary.json`

### 출력 경로
- `02b_flow/function_names_categorized.jsonl`
- `02b_flow/grouped_family_role.json`
- `02b_flow/category_summary.json`

### 다음 단계로 넘기는 핵심 출력
- `02b_flow/function_names_categorized.jsonl`

### 현재 코드가 실제로 하는 일
- function inventory를 분류하고, flow partition 단계에서 사용할 categorized 결과를 생성합니다.

### 현재 코드가 실제로 검사하는 것
- 이 단계 직후 별도 존재 검사는 하지 않습니다.
- 다음 단계가 `function_names_categorized.jsonl` 를 직접 입력으로 사용합니다.

### downstream이 실제로 쓰는 출력
현재 다음 단계(`02b_testcase_flow_partition`)가 직접 쓰는 것은 아래 파일입니다.

- `02b_flow/function_names_categorized.jsonl`

그중에서도 실제로 필요한 필드는 현재 코드 기준으로 주로 아래 둘입니다.

- `function_name`
- `flow_family`

따라서 이 단계의 테스트 우선순위는 `function_names_categorized.jsonl` 에 두는 것이 맞습니다.
`grouped_family_role.json`, `category_summary.json` 는 현재 기준으로는 보조 산출물로 봅니다.

### 현재 코드상 생성 규칙
- 입력 CSV의 각 row마다 정확히 하나의 categorized row를 생성합니다.
- output JSONL record는 현재 코드상 아래 필드를 가집니다.
  - `function_name`
  - `count`
  - `simple_name`
  - `flow_family`
  - `operation_role`
  - `role_variant`
- `flow_family` 의 현재 구현상 가능한 값
  - `g2b_family`
  - `b2g_family`
  - `g2g_family`
  - `b2b_family`
  - `helper_family`
  - `class_family`
  - `misc_family`
- `operation_role` 의 현재 구현상 가능한 값
  - `source`
  - `sink`
  - `source_sink`
- `role_variant` 는 `operation_role` 에 따라 달라집니다.
  - `source` → `source`
  - `sink` → `direct_sink` / `va_sink` / `action_sink`
  - `source_sink` → `source_func_only` / `sink_func_only` / `both_func_included` / `both_func_excluded`

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 파일이 생성된다.
  - `function_names_categorized.jsonl`
- JSONL record 수는 input CSV row 수와 같아야 한다.
- 각 JSONL record는 아래 필드를 가진다.
  - `function_name`
  - `count`
  - `simple_name`
  - `flow_family`
  - `operation_role`
  - `role_variant`
- `function_name` 은 비어 있지 않다.
- `count` 는 정수이고 `> 0` 이다.
- `flow_family` 는 허용 집합 안에 있어야 한다.
- `operation_role` 는 허용 집합 안에 있어야 한다.
- `role_variant` 는 해당 `operation_role` 에 맞는 허용 집합 안에 있어야 한다.

#### B. golden regression 테스트
- `function_names_categorized.jsonl` 는 fixture와 exact match로 본다.
  - 구현 방식은 whole-file diff 또는 md5sum 비교면 충분하다.
- `category_summary.json` 은 whole-file exact match 대신 **상세 분포 숫자**를 golden regression으로 본다.
  - 현재 구현 기준으로 우선 확인할 key:
    - `total_unique_function_names`
    - `total_weighted_count`
    - `flow_family_distribution`
    - `operation_role_distribution`
    - `role_variant_distribution`
    - `flow_family_operation_role_distribution`
  - 이때 path 계열 필드와 `generated_at` 는 exact match 대상으로 보지 않는다.
- `grouped_family_role.json` 는 현재 기준으로 golden regression의 필수 대상으로 보지 않는다.

### 테스트에서 계약으로 보기 어려운 것
- `grouped_family_role.json` 전체 파일 exact match
- `category_summary.json` 전체 파일 exact match
- nested JSON의 정렬 순서
- `generated_at` timestamp
- 보고용 grouped JSON의 상세 item 배열 구조 전체

---

## 5. `02b_testcase_flow_partition`

### 실행 스크립트
- `experiments/epic001c_testcase_flow_partition/scripts/add_flow_tags_to_testcase.py`

### 입력
- `--input-xml 01_manifest/manifest_with_comments.xml`
- `--output-xml 02b_flow/manifest_with_testcase_flows.xml`
- `--summary-json 02b_flow/summary.json`

### 출력 경로
- `02b_flow/manifest_with_testcase_flows.xml`
- `02b_flow/summary.json`

### 다음 단계로 넘기는 핵심 출력
- `02b_flow/manifest_with_testcase_flows.xml`

### 현재 코드가 실제로 하는 일
- testcase 단위 flow 정보가 포함된 manifest를 생성합니다.
- 이후 trace-flow filter 단계가 이 XML을 직접 사용합니다.

### 현재 코드가 실제로 검사하는 것
- 이 단계 직후 별도 존재 검사는 하지 않습니다.
- 다음 단계가 `manifest_with_testcase_flows.xml` 을 직접 입력으로 사용합니다.

### XML에서 실제로 바뀌는 것
현재 구현은 input XML의 각 `<testcase>` 아래에 새 `<flow type="...">` 태그를 추가합니다.

다만 코드에는 방어적으로 **기존 `<flow>` 태그가 이미 있으면 먼저 제거하는 로직**이 들어 있습니다.
즉, 일반적인 Stage 01 출력(`manifest_with_comments.xml`)처럼 `<flow>` 가 아직 없는 입력에서는
실질적으로는 **새 `<flow>` 태그를 추가하는 동작**이라고 보는 것이 맞습니다.

- flow 하위 태그는 현재 Stage02b에서 정규화됩니다.
  - `comment_flaw` → `flaw`
  - `comment_fix` → `fix`
  - 기존 `flaw` → `flaw`
- flow 안으로 복사된 각 태그에는 `file`, `function`, `origin` 속성이 추가되거나 유지됩니다.
- 원래 manifest의 `<flaw>` 에서 온 항목은 `origin="manifest_flaw"` 이고 `name` 속성을 유지합니다.
- 같은 `(file, line)` 에서 `manifest_flaw` 와 `comment_flaw` 가 겹치면
  원래 있던 `manifest_flaw` 를 남기고 comment 쪽 `flaw` 는 제거합니다.
- 같은 `(file, line)` 에 `manifest_flaw` 가 여러 개 있으면, file명의 CWE prefix와 `name` 의
  CWE prefix가 모두 비교 가능하고 그중 일치하는 항목이 있을 때만 불일치 `manifest_flaw` 를 제거합니다.
- 기본 동작에서는 dedup 후 child가 1개뿐인 `<flow>` 는 생성하지 않습니다.
  필요하면 `--keep-single-child-flows` 또는 `prune_single_child_flows=False` 로 유지할 수 있습니다.

### downstream이 실제로 쓰는 필드
다음 단계(`04_trace_flow_filter`)는 flow XML에서 적어도 아래 정보를 사용합니다.

- `testcase/flow@type`
- flow 하위 태그의
  - `file`
  - `line`
  - 태그 이름(`flaw`, `fix`)

### 현재 코드상 생성 규칙
- testcase에 기존 `<flow>` 태그가 있으면 먼저 제거합니다.
- `comment_flaw`, `comment_fix` 는 `function` 이름에서 직접 flow family를 추론해 flow를 결정합니다.
- 원래 manifest의 `flaw` 는 같은 file 안의 comment tag line 분포를 이용해 가장 가까운 함수로 `function` 을 추정합니다.
- flow type은 base flow + suffix 규칙을 따릅니다.
  - `b2b`
  - `b2g`, `b2g1`, `b2g2`, ...
  - `g2b`, `g2b1`, `g2b2`, ...
  - numbered source/sink 함수도 같은 numbered flow로 묶입니다.
    - 예: `goodB2G1` / `goodB2G1Source` / `goodB2G1Sink` → `b2g1`
    - 예: `goodG2B2` / `goodG2B2Source` / `goodG2B2Sink` → `g2b2`
- 분류할 수 없는 comment/flaw는 flow에 넣지 않고 unresolved count로 집계합니다.

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 파일이 생성된다.
  - `manifest_with_testcase_flows.xml`
  - `summary.json`
- 각 `<testcase>` 아래의 `<flow>` 는 direct child 로 존재한다.
- 각 `<flow>` 는 `type` 속성을 가진다.
- 각 `<flow>` 하위 태그는 아래 집합 안에 있어야 한다.
  - `flaw`
  - `fix`
- flow 하위의 모든 태그는 `file`, `function`, `origin` 속성을 가진다.
- flow 하위의 모든 태그는 `line` 이 정수로 파싱 가능해야 한다.
- `fix` 의 `origin` 은 `comment_fix` 여야 한다.
- `flaw` 의 `origin` 은
  - `manifest_flaw`
  - `comment_flaw`
  중 하나여야 한다.
- `origin == "manifest_flaw"` 인 `flaw` 는 `name` 속성을 유지해야 한다.
- summary 는 최소한 아래 성격의 정보를 담는다.
  - testcase 수
  - flow별 item count
  - unresolved comment/flaw count
  - dedup으로 제거된 `comment_flaw` 수

#### B. golden regression 테스트
- 생성된 `flow@type` 집합이 fixture와 일치한다.
- 각 `flow@type` 별로 포함된 item들의 핵심 정보 집합이 fixture와 일치한다.
  - 예: 태그 이름, `file`, `line`, `function`, `origin`, `name`
- summary 의 정확한 수치

### 테스트에서 계약으로 보기 어려운 것
- XML pretty formatting / indent
- `<flow>` 태그의 XML 내 순서
- flow 내부 item 순서 자체
- summary JSON 의 필드 순서

---

## 6. taint config 선택

이 단계는 별도 외부 스크립트를 실행하지 않습니다.
`tools/run_pipeline.py` 안에서 **Step 02a 결과를 보고 Step 03에 넘길 taint config 경로를 고르는 분기**입니다.

### 입력
- `02a_taint/pulse-taint-config.json`
- `--committed-taint-config`

### 현재 코드의 실제 분기
- `02a_taint/pulse-taint-config.json` 이 존재하면
  - `selected_taint_config = generated_taint_config`
  - `selected_reason = "generated"`
- 존재하지 않으면
  - `selected_taint_config = committed_taint_config`
  - `selected_reason = "fallback_committed"`

### 다음 단계로 넘기는 런타임 값
- `selected_taint_config`
- `selected_reason`

### 현재 코드가 실제로 검사하는 것
- `generated_taint_config.exists()`

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- generated taint config가 존재하면 그것이 선택된다.
- generated taint config가 없으면 committed taint config가 선택된다.
- `selected_reason` 값은 현재 구현 기준
  - `generated`
  - `fallback_committed`
  중 하나다.
- Step 03 실행 시 `--pulse-taint-config <selected_taint_config>` 로 전달된다.

#### B. golden regression 테스트
- `run_summary.json` 내 경로 문자열 전체

### 테스트에서 계약으로 보기 어려운 것
- `selected_taint_config` 경로 문자열의 절대/상대 표현 방식

---

## 7. `03_infer_and_signature`

### 실행 스크립트
- `tools/run_pipeline.py stage03`

### 입력
- `--pulse-taint-config <selected_taint_config>`
- `--infer-results-root 03_infer-results/`
- `--signatures-root 03_signatures/`
- `--summary-json 03_infer_summary.json`
- 대상 선택:
  - `cwes`
  - 또는 `--all`
  - 또는 반복 가능한 `--files`

### 출력 경로
- `03_infer-results/...`
- `03_signatures/...`
- `03_infer_summary.json`

### 다음 단계로 넘기는 핵심 출력
- `signature_non_empty_dir`
- `03_infer_summary.json`

### 현재 코드가 실제로 하는 일
- Infer 실행과 signature 생성을 한 번에 수행합니다.
- 실행 후 `03_infer_summary.json` 을 읽어 downstream에 사용할 `signature_non_empty_dir` 를 해석합니다.
  - summary에 `signature_non_empty_dir` 가 있으면 그것을 사용
  - 없으면 `signature_output_dir/non_empty` 로 계산

### 현재 코드가 실제로 검사하는 것
- `03_infer_summary.json`
- summary에서 해석한 `signature_non_empty_dir`

### downstream이 실제로 쓰는 출력
다음 단계(`04_trace_flow_filter`)가 직접 쓰는 것은 아래입니다.

- `03_infer_summary.json`
- `signature_non_empty_dir`

그중 핵심은 실제 signature JSON들이 들어 있는 `signature_non_empty_dir` 입니다.

### 현재 코드상 생성 규칙
- Infer run 결과는 `03_infer-results/infer-<timestamp>/` 아래에 생성됩니다.
- signature 결과는 `03_signatures/infer-<timestamp>/signature-<timestamp>/` 아래에 생성됩니다.
- `03_infer_summary.json` 은 현재 코드상 최소한 아래 정보를 담습니다.
  - `pulse_taint_config`
  - `infer_results_root`
  - `infer_run_dir`
  - `infer_run_name`
  - `signatures_root`
  - `signature_output_dir`
  - `signature_non_empty_dir`
  - `analysis_result_csv`
  - `analysis_no_issue_files`
  - `result_by_target`
  - `totals`
- `signature_non_empty_dir` 는 downstream이 읽을 수 있는 existing directory 여야 합니다.

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- `03_infer_summary.json` 이 생성된다.
- summary 는 JSON object 이다.
- summary 는 최소한 아래 key를 가진다.
  - `infer_run_dir`
  - `signature_output_dir`
  - `signature_non_empty_dir`
  - `analysis_result_csv`
  - `analysis_no_issue_files`
  - `result_by_target`
  - `totals`
- `signature_non_empty_dir` 경로가 실제로 존재한다.
- `analysis_result_csv` 경로가 실제로 존재한다.
- `analysis_no_issue_files` 경로가 실제로 존재한다.
- `totals` 는 JSON object 이고 최소한 아래 key를 가진다.
  - `issue`
  - `no_issue`
  - `error`
  - `total_cases`
  - `elapsed_seconds`
- `result_by_target` 는 JSON object 이다.
- 각 target summary는 최소한
  - `issue`
  - `no_issue`
  - `error`
  - `total_cases`
  - `time`
  를 가진다.

#### B. golden regression 테스트
- summary 안의 정확한 target별 숫자
- 특정 fixture에서 생성되는 signature 파일 목록 전체

### 테스트에서 계약으로 보기 어려운 것
- `infer_run_dir` / `signature_output_dir` 의 정확한 경로명
- stdout 출력 문구

---

## 8. `04_trace_flow_filter`

### 실행 스크립트
- `experiments/epic001d_trace_flow_filter/scripts/filter_traces_by_flow.py`

### 입력
- `--flow-xml 02b_flow/manifest_with_testcase_flows.xml`
- `--signatures-dir <signature_non_empty_dir>`
- `--output-dir 04_trace_flow/`

### 출력 경로
- `04_trace_flow/trace_flow_match_all.jsonl`
- `04_trace_flow/trace_flow_match_strict.jsonl`
- `04_trace_flow/trace_flow_match_partial_or_strict.jsonl`
- `04_trace_flow/summary.json`

### 다음 단계로 넘기는 핵심 출력
- `04_trace_flow/trace_flow_match_strict.jsonl`

### 현재 코드가 실제로 하는 일
- testcase flow XML과 signature trace를 비교해 strict / partial match 결과를 만듭니다.
- 다음 단계는 strict 결과만 사용합니다.

### 현재 코드가 실제로 검사하는 것
- `04_trace_flow/trace_flow_match_strict.jsonl`

### downstream이 실제로 쓰는 출력
다음 단계(`05_pair_trace_dataset`)는 아래 파일만 직접 사용합니다.

- `04_trace_flow/trace_flow_match_strict.jsonl`

하지만 테스트 관점에서는 아래 파일들도 함께 보는 것이 유익합니다.

- `trace_flow_match_all.jsonl`
- `trace_flow_match_partial_or_strict.jsonl`
- `summary.json`

### 현재 코드상 생성 규칙
- signature dir 아래 testcase 디렉터리별로 JSON trace를 순회합니다.
- 각 trace record는 현재 코드상 최소한 아래 필드를 가집니다.
  - `trace_file`
  - `testcase_key`
  - `status`
  - `best_flow_type`
  - `best_flow_meta`
  - `flow_match`
- `flow_match[*].hit_tag_counts` 는 현재 `flaw` / `fix` 태그 기준으로 집계됩니다.
- trace에 flow hit가 없으면
  - `status = "no_flow_hit"`
- flow index가 없으면
  - `status = "no_flow_index"`
- best flow가 strict면
  - `status = "strict_match"`
- best flow가 partial이면
  - `status = "partial_match"`
- strict output에는 `status == "strict_match"` 인 record만 들어갑니다.
- partial_or_strict output에는
  - `strict_match`
  - `partial_match`
  가 들어갑니다.

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 파일이 생성된다.
  - `trace_flow_match_all.jsonl`
  - `trace_flow_match_strict.jsonl`
  - `trace_flow_match_partial_or_strict.jsonl`
  - `summary.json`
- `trace_flow_match_strict.jsonl` 의 각 record는 JSON object 이다.
- strict record는 최소한 아래 key를 가진다.
  - `trace_file`
  - `testcase_key`
  - `status`
  - `best_flow_type`
  - `best_flow_meta`
  - `flow_match`
- strict output의 모든 record는 `status == "strict_match"` 이다.
- strict output의 모든 record는 `best_flow_type` 이 비어 있지 않다.
- `best_flow_meta.strict_match` 는 `true` 여야 한다.
- `trace_file` 경로 문자열은 비어 있지 않다.
- `summary.json` 은 최소한 아래 정보를 담는다.
  - `flow_index`
  - `trace_stats`
  - `matched_best_flow_counts`
  - `output_files`

#### B. golden regression 테스트
- 각 trace의 `best_flow_type` 정확한 값
- `hit_points`, `coverage`, `hit_tag_counts` 정확한 값
- strict/partial 분류 수치

### 테스트에서 계약으로 보기 어려운 것
- JSONL 레코드 순서 자체
- `matched_best_flow_counts` 의 dict key 순서
- summary 안의 절대 경로 문자열

---

## 9. `05_pair_trace_dataset`

### 실행 스크립트
- `tools/run_pipeline.py stage05`

### 입력
- `--trace-jsonl 04_trace_flow/trace_flow_match_strict.jsonl`
- `--output-dir 05_pair_trace_ds/`

### 출력 경로
- `05_pair_trace_ds/pairs.jsonl`
- `05_pair_trace_ds/leftover_counterparts.jsonl`
- `05_pair_trace_ds/paired_signatures/`
- `05_pair_trace_ds/summary.json`

### 다음 단계로 넘기는 핵심 출력
- `05_pair_trace_ds/pairs.jsonl`
- `05_pair_trace_ds/paired_signatures/`

### 현재 코드가 실제로 하는 일
- strict trace에서 testcase별 `b2b` 와 counterpart를 선택합니다.
- pair 메타데이터와 paired signature-style 디렉터리를 같이 생성합니다.

### 현재 코드가 실제로 검사하는 것
- `05_pair_trace_ds/pairs.jsonl`
- `05_pair_trace_ds/paired_signatures/`
- `05_pair_trace_ds/summary.json`

### downstream이 실제로 쓰는 출력
다음 단계들은 아래를 직접 씁니다.

- `06_generate_slices`
  - `05_pair_trace_ds/paired_signatures/`
- `07_dataset_export`
  - `05_pair_trace_ds/pairs.jsonl`
  - `05_pair_trace_ds/paired_signatures/`
- `07b_train_patched_counterparts_export`
  - `05_pair_trace_ds/pairs.jsonl`
  - `05_pair_trace_ds/leftover_counterparts.jsonl`

### 현재 코드상 생성 규칙
- 입력 strict trace JSONL의 각 row는 최소한
  - `testcase_key`
  - `trace_file`
  - `best_flow_type`
  를 가져야 합니다.
- testcase별로
  - `best_flow_type == "b2b"` 인 record 중 하나
  - counterpart flow(`g2b*`, `b2g*`) 중 하나
  를 선택합니다.
- 선택 기준은 현재 코드상 `record_sort_key` 이고, 실질적으로
  - `bug_trace_length` 내림차순
  - trace path
  - flow type
  - procedure
  순입니다.
- `pairs.jsonl` 의 각 record는 현재 코드상 최소한 아래를 가집니다.
  - `pair_id`
  - `testcase_key`
  - `selection_reason`
  - `b2b_flow_type`
  - `b2b_trace_file`
  - `b2b_bug_trace_length`
  - `b2b_signature`
  - `counterpart_flow_type`
  - `counterpart_trace_file`
  - `counterpart_bug_trace_length`
  - `counterpart_signature`
  - `output_files`
- `paired_signatures/<testcase_key>/` 아래에는 현재 코드상
  - `b2b.json`
  - `<counterpart_flow_type>.json`
  가 생성됩니다.
- 각 exported signature JSON에는 `pairing_meta` 가 추가됩니다.
- 선택되지 않은 counterpart는 `leftover_counterparts.jsonl` 로 기록됩니다.

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 파일/디렉터리가 생성된다.
  - `pairs.jsonl`
  - `leftover_counterparts.jsonl`
  - `paired_signatures/`
  - `summary.json`
- `pairs.jsonl` 의 각 record는 JSON object 이다.
- 각 pair record는 최소한 아래 key를 가진다.
  - `pair_id`
  - `testcase_key`
  - `b2b_flow_type`
  - `counterpart_flow_type`
  - `output_files`
- `pair_id` 는 비어 있지 않다.
- `b2b_flow_type == "b2b"` 여야 한다.
- `counterpart_flow_type` 은 비어 있지 않고 `b2b` 가 아니어야 한다.
- `output_files["b2b"]` 경로가 존재한다.
- `output_files[<counterpart_flow_type>]` 경로가 존재한다.
- exported signature JSON은 `pairing_meta` 를 가진다.
- `pairing_meta.pair_id` 는 pair record의 `pair_id` 와 일치한다.
- `summary.json` 은 최소한 아래 정보를 담는다.
  - `records_total`
  - `summary_counts`
  - `paired_testcases`
  - `leftover_counterparts`

#### B. golden regression 테스트
- testcase별 선택된 counterpart 종류
- `pair_id` 의 정확한 값
- leftover record의 정확한 목록
- summary count 세부 값

### 테스트에서 계약으로 보기 어려운 것
- `pair_id` 생성 해시 알고리즘 자체
- JSON pretty formatting
- leftover JSONL 레코드 순서

---

## 10. `06_generate_slices`

### 실행 스크립트
- `tools/run_pipeline.py stage06`

### 입력
- `--signature-db-dir 05_pair_trace_ds/paired_signatures/`
- `--output-dir 06_slices/`

### 출력 경로
- `06_slices/slice/`
- `06_slices/summary.json`

### 다음 단계로 넘기는 핵심 출력
- `06_slices/slice/`

### 현재 코드가 실제로 하는 일
- paired signatures의 `bug_trace` 를 읽어 slice 파일을 생성합니다.
- 다음 단계 dataset export가 이 `slice/` 디렉터리를 직접 사용합니다.

### 현재 코드가 실제로 검사하는 것
- `06_slices/slice/`
- `06_slices/summary.json`

### downstream이 실제로 쓰는 출력
다음 단계(`07_dataset_export`)는 아래를 직접 사용합니다.

- `06_slices/slice/`

### 현재 코드상 생성 규칙
- 입력은 `paired_signatures/<testcase_key>/*.json` 입니다.
- 각 JSON의 `bug_trace` 에서 표준 trace를 추출합니다.
  - `list[dict]` 이면 그대로 사용
  - `list[list[dict]]` 이면 가장 긴 subtrace를 사용
- 각 trace node는 최소한
  - `filename`
  - `line_number`
  를 가져야 합니다.
- source line을 읽을 수 없는 경우 slice를 생성하지 않고 skip 합니다.
- 중복 `(filename, line_number)` 는 한 번만 사용합니다.
- 출력 파일명은 현재 코드상
  - `slice_<testcase_key>_<json_stem>.c`
  - 또는 `.cpp`
  입니다.
- suffix는 trace/source path 정보를 보고 추정합니다.

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 디렉터리/파일이 생성된다.
  - `06_slices/slice/`
  - `06_slices/summary.json`
- `summary.json` 은 최소한 아래 정보를 담는다.
  - `signature_db_dir`
  - `output_dir`
  - `slice_dir`
  - `total_slices`
  - `counts`
- 생성된 slice 파일은 `.c` 또는 `.cpp` 확장자를 가진다.
- 생성된 slice 파일 내용은 비어 있지 않다.
- `summary.counts.generated` 는 실제 생성된 slice 파일 수와 모순되지 않아야 한다.
- skip이 발생할 수 있으므로, 입력 JSON 수와 생성 slice 수가 꼭 같을 필요는 없다.

#### B. golden regression 테스트
- 각 slice의 정확한 파일명
- slice 안에 들어간 정확한 source line 집합
- skip reason별 count

### 테스트에서 계약으로 보기 어려운 것
- `errors` count의 정확한 값 전체
- 동일 trace에서 line 중복 제거의 내부 구현 방식
- summary dict key 순서

---

## 11. `07_dataset_export`

### 실행 위치
- `tools/run_pipeline.py full` 내부 함수 호출
- 구현 함수: `export_dataset_from_pipeline()`

### 입력
- `05_pair_trace_ds/pairs.jsonl`
- `05_pair_trace_ds/paired_signatures/`
- `06_slices/slice/`
- `pair_split_seed`
- `pair_train_ratio`
- `dedup_mode`

### 출력 경로
- `07_dataset_export/normalized_slices/`
- `07_dataset_export/Real_Vul_data.csv`
- `07_dataset_export/Real_Vul_data_dedup_dropped.csv`
- `07_dataset_export/normalized_token_counts.csv`
- `07_dataset_export/slice_token_distribution.png`
- `07_dataset_export/split_manifest.json`
- `07_dataset_export/summary.json`

### 다음 단계로 넘기는 핵심 출력
- `07_dataset_export/split_manifest.json`
- `07_dataset_export/summary.json`

### 현재 코드가 실제로 하는 일
- pair 단위 split을 계산합니다.
- slice normalize / dedup / tokenize / export 를 수행합니다.
- 이 단계의 출력은 이후 `07b` 에서 다시 사용됩니다.

### 현재 코드가 실제로 검사하는 것
- `07_dataset_export/normalized_slices/`
- `07_dataset_export/Real_Vul_data.csv`
- `07_dataset_export/Real_Vul_data_dedup_dropped.csv`
- `07_dataset_export/normalized_token_counts.csv`
- `07_dataset_export/slice_token_distribution.png`
- `07_dataset_export/split_manifest.json`
- `07_dataset_export/summary.json`

### downstream이 실제로 쓰는 출력
현재 `07b_train_patched_counterparts_export` 가 직접 쓰는 것은 주로 아래입니다.

- `07_dataset_export/split_manifest.json`

그 외 파일은 최종 deliverable / 보고용 산출물 성격이 강합니다.

### 현재 코드상 생성 규칙
- pair split 단위는 `pair_id` 입니다.
- 기본 split label은 현재 코드상
  - `train_val`
  - `test`
  입니다.
- `Real_Vul_data.csv` 는 현재 코드상 아래 header를 가집니다.
  - `file_name`
  - `unique_id`
  - `target`
  - `vulnerable_line_numbers`
  - `project`
  - `source_signature_path`
  - `commit_hash`
  - `dataset_type`
  - `processed_func`
- `split_manifest.json` 은 현재 코드상 최소한 아래를 포함합니다.
  - split metadata
  - `normalized_slices_dir`
  - `dedup_dropped_csv`
  - `dedup`
  - `counts`
  - `pair_ids`
- `pair_ids` 는 현재 코드상
  - `train_val`
  - `test`
  key를 사용합니다.
- `summary.json` 은 최소한 아래 성격의 정보를 포함합니다.
  - output paths
  - dedup summary
  - token stats
  - filtered pair reasons
  - counts

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 파일/디렉터리가 생성된다.
  - `normalized_slices/`
  - `Real_Vul_data.csv`
  - `Real_Vul_data_dedup_dropped.csv`
  - `normalized_token_counts.csv`
  - `slice_token_distribution.png`
  - `split_manifest.json`
  - `summary.json`
- `Real_Vul_data.csv` header 는 현재 구현과 일치해야 한다.
- `split_manifest.json` 은 JSON object 이다.
- `split_manifest.json` 은 최소한 아래 key를 가진다.
  - `counts`
  - `pair_ids`
  - `normalized_slices_dir`
  - `dedup_dropped_csv`
- `split_manifest.json["pair_ids"]` 는 최소한
  - `train_val`
  - `test`
  를 가진다.
- `summary.json` 은 JSON object 이다.
- `summary.json` 은 최소한 아래 key를 가진다.
  - `normalized_slices_dir`
  - `dedup_dropped_csv`
  - `split_manifest_json`
  - `dedup`
  - `token_stats`
  - `filtered_pair_reasons`
  - `counts`
- `normalized_slices/` 의 파일 수는 CSV row 수와 모순되지 않아야 한다.
- `summary.counts.train_val_pairs` 는 `split_manifest.pair_ids.train_val` 길이와 일치해야 한다.
- `summary.counts.test_pairs` 는 `split_manifest.pair_ids.test` 길이와 일치해야 한다.

#### B. golden regression 테스트
- 최종 CSV row 전체
- dedup dropped CSV row 전체
- normalized token counts 값
- split 결과의 정확한 pair_id 목록
- summary의 세부 통계값

### 테스트에서 계약으로 보기 어려운 것
- normalized slice 파일명 번호 자체
- plot 이미지의 픽셀 단위 차이
- tokenizer 내부 버전에 따른 미세한 통계 차이

---

## 12. `07b_train_patched_counterparts_export`

### 실행 스크립트
- `tools/run_pipeline.py stage07b`

### 입력
- `--run-dir <run_dir>`
- `--dedup-mode <dedup_mode>`

기본적으로 내부에서 아래 산출물을 다시 읽습니다.

- `05_pair_trace_ds/pairs.jsonl`
- `05_pair_trace_ds/leftover_counterparts.jsonl`
- `07_dataset_export/split_manifest.json`

### 출력 경로
- `05_pair_trace_ds/train_patched_counterparts_pairs.jsonl`
- `05_pair_trace_ds/train_patched_counterparts_selection_summary.json`
- `05_pair_trace_ds/train_patched_counterparts_signatures/`
- `06_slices/train_patched_counterparts/slice/`
- `06_slices/train_patched_counterparts/summary.json`
- `07_dataset_export/train_patched_counterparts.csv`
- `07_dataset_export/train_patched_counterparts_dedup_dropped.csv`
- `07_dataset_export/train_patched_counterparts_slices/`
- `07_dataset_export/train_patched_counterparts_token_counts.csv`
- `07_dataset_export/train_patched_counterparts_token_distribution.png`
- `07_dataset_export/train_patched_counterparts_split_manifest.json`
- `07_dataset_export/train_patched_counterparts_summary.json`

### 다음 단계로 넘기는 핵심 출력
- 현재 기본 파이프라인에서는 마지막 단계입니다.

### 현재 코드가 실제로 하는 일
- train split 기준 primary pair와 leftover counterpart를 다시 조합합니다.
- signature materialization, slice 생성, export 를 한 번 더 수행합니다.

### 현재 코드가 실제로 검사하는 것
- `05_pair_trace_ds/train_patched_counterparts_pairs.jsonl`
- `05_pair_trace_ds/train_patched_counterparts_signatures/`
- `05_pair_trace_ds/train_patched_counterparts_selection_summary.json`
- `06_slices/train_patched_counterparts/slice/`
- `06_slices/train_patched_counterparts/summary.json`
- `07_dataset_export/train_patched_counterparts.csv`
- `07_dataset_export/train_patched_counterparts_dedup_dropped.csv`
- `07_dataset_export/train_patched_counterparts_slices/`
- `07_dataset_export/train_patched_counterparts_token_counts.csv`
- `07_dataset_export/train_patched_counterparts_token_distribution.png`
- `07_dataset_export/train_patched_counterparts_split_manifest.json`
- `07_dataset_export/train_patched_counterparts_summary.json`

### downstream이 실제로 쓰는 출력
- 현재 기본 파이프라인에서는 마지막 단계라서 downstream consumer는 없습니다.
- 다만 평가용/분석용 산출물 집합으로 간주할 수 있습니다.

### 현재 코드상 생성 규칙
- source split manifest에서 `train_val` pair id만 읽습니다.
- 각 testcase에 대해 leftover counterpart 후보를 정렬해 최상위 1개를 고릅니다.
- 선택된 pair는 `train_patched_counterparts_pairs.jsonl` 로 기록됩니다.
- `train_patched_counterparts_signatures/` 아래에는 testcase별로
  - `b2b.json`
  - `<counterpart_flow_type>.json`
  가 생성됩니다.
- 각 exported signature JSON에는 `pairing_meta` 가 추가됩니다.
  - `selection_reason`
  - `source_primary_pair_id`
  등 추가 메타가 포함됩니다.
- 이후 별도 slice 생성과 dataset export를 다시 수행합니다.
- 최종 export 파일 이름은 `train_patched_counterparts_*` 접두를 사용합니다.

### 테스트 작성용 계약 체크리스트
#### A. 계약 체크 테스트
- 출력 파일/디렉터리가 생성된다.
  - `train_patched_counterparts_pairs.jsonl`
  - `train_patched_counterparts_signatures/`
  - `train_patched_counterparts_selection_summary.json`
  - `06_slices/train_patched_counterparts/slice/`
  - `06_slices/train_patched_counterparts/summary.json`
  - `07_dataset_export/train_patched_counterparts.csv`
  - `07_dataset_export/train_patched_counterparts_dedup_dropped.csv`
  - `07_dataset_export/train_patched_counterparts_slices/`
  - `07_dataset_export/train_patched_counterparts_token_counts.csv`
  - `07_dataset_export/train_patched_counterparts_token_distribution.png`
  - `07_dataset_export/train_patched_counterparts_split_manifest.json`
  - `07_dataset_export/train_patched_counterparts_summary.json`
- `train_patched_counterparts_pairs.jsonl` 의 각 record는 JSON object 이다.
- 각 pair record는 최소한 아래 key를 가진다.
  - `pair_id`
  - `testcase_key`
  - `source_primary_pair_id`
  - `b2b_flow_type`
  - `counterpart_flow_type`
  - `output_files`
- selection summary는 최소한 아래를 담는다.
  - `source_split_manifest_json`
  - `output_pairs_jsonl`
  - `counts`
  - `selected_testcases`
- patched export CSV / split manifest / summary 는 기본 Step 07 산출물과 같은 계열의 구조를 유지해야 한다.
- patched split manifest 는 최소한 `pair_ids` 와 `counts` 를 가져야 한다.

#### B. golden regression 테스트
- 어떤 train_val pair가 선택되었는지
- testcase별 선택된 leftover counterpart 목록
- patched export CSV 전체
- patched split manifest의 정확한 pair_id 목록
- patched summary 상세 통계

### 테스트에서 계약으로 보기 어려운 것
- `leftover_rank` 같은 보조 메타의 세부 값 전부
- signature JSON pretty formatting
- plot 이미지의 픽셀 단위 차이

---

## 단계 간 실제 의존 관계

현재 구현의 핵심 파일 의존 관계는 아래와 같습니다.

- `01_manifest_comment_scan`
  - `manifest_with_comments.xml`
- `02a_code_field_inventory`
  - `manifest_with_comments.xml` → `pulse-taint-config.json`
- `02b_testcase_flow_partition`
  - `manifest_with_comments.xml` → `manifest_with_testcase_flows.xml`
- taint config 선택
  - `pulse-taint-config.json` 또는 committed config → `selected_taint_config`
- `03_infer_and_signature`
  - `selected_taint_config` → `03_infer_summary.json` + `signature_non_empty_dir`
- `04_trace_flow_filter`
  - `manifest_with_testcase_flows.xml` + `signature_non_empty_dir` → `trace_flow_match_strict.jsonl`
- `05_pair_trace_dataset`
  - `trace_flow_match_strict.jsonl` → `pairs.jsonl` + `paired_signatures/`
- `06_generate_slices`
  - `paired_signatures/` → `06_slices/slice/`
- `07_dataset_export`
  - `pairs.jsonl` + `paired_signatures/` + `06_slices/slice/` → `07_dataset_export/*`
- `07b_train_patched_counterparts_export`
  - `pairs.jsonl` + `leftover_counterparts.jsonl` + `split_manifest.json` → patched counterpart outputs

---

## 현재 구현에서 중요한 관찰

- `02b` 는 개념적으로 하나처럼 보일 수 있지만 현재 구현은 **3개의 별도 실행 단계**입니다.
- `03` 은 on-disk 결과는 `03_infer-results` 와 `03_signatures` 로 나뉘지만
  현재 오케스트레이션에서는 **한 번의 실행 단계**입니다.
- `06` 과 `07` 도 개념적으로 묶을 수 있지만 현재 코드는
  **서로 다른 산출물 존재 여부를 따로 검사**합니다.
- `07b` 는 기본 파이프라인의 마지막 단계로 항상 실행됩니다.
- `selected_taint_config` 는 파일명이 아니라 `tools/run_pipeline.py` 내부에서 결정되는 값입니다.

---

## 개념 단계 재정리 메모 (백업)

아래는 나중에 단계 축소를 논의할 때 참고하려는 **백업 메모**입니다.
현재 구현 설명이 우선이므로, 여기서는 상세 설명 없이 이름만 남깁니다.

| 개념 단계 후보 | 현재 구현 묶음 |
| --- | --- |
| `prepare_metadata` | `01_manifest` + `02a_taint` + `02b_flow` |
| `run_analysis` | `03_infer-results` + `03_signatures` |
| `select_pairs` | `04_trace_flow` + `05_pair_trace_ds` |
| `build_dataset` | `06_slices` + `07_dataset_export` |
| `optional_patched_eval_export` | `07b` |
