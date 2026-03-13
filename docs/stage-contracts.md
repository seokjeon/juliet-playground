# Stage contracts

현재 파이프라인의 **개념 단계(contract boundary)** 를 얇게 정리한 문서입니다.

이 문서의 목적은 다음과 같습니다.

- 각 단계의 **책임**을 짧게 정의한다.
- downstream이 실제로 의존하는 **핵심 입력/출력**만 계약으로 본다.
- 보고용 산출물과 핵심 계약 산출물을 구분한다.
- 이후 단계 병합, 옵션화, top-level 리팩토링의 기준점으로 사용한다.

이 문서는 현재 on-disk 디렉터리 구조를 그대로 고정하려는 문서가 아닙니다.
오히려 현재 구현을 더 적은 개념 단계로 재정리하기 위한 초안입니다.

다만 초안이라도 **현재 코드와 직접 대응**되도록 작성합니다.
기준이 되는 실제 코드는 주로 다음 위치입니다.

- `tools/lib/pipeline_run.py`
- `tools/run-infer-all-juliet.py`
- `tools/build-paired-trace-signatures.py`
- `tools/generate_slices.py`
- `tools/export_train_patched_counterparts.py`

## 공통 원칙

- **계약 출력(contract output)**: 다음 단계가 실제로 읽는 핵심 산출물
- **보고용 산출물(report/debug output)**: summary, CSV, plot, inventory 등
- 한 단계는 **핵심 계약 출력이 존재할 때만 성공**으로 본다.
- 보고용 산출물은 중요하지만, 가능하면 계약과 분리해서 다룬다.
- 단계 병합 시에도 downstream이 쓰는 핵심 출력은 보존하거나 명시적으로 대체한다.
- 아래 서술에서 “현재 코드 기준”은 `tools/lib/pipeline_run.py` 가 실제로 생성/전달/검증하는 값을 뜻한다.

## 현재 구현 ↔ 개념 단계 매핑

| 개념 단계 | 현재 구현 | 핵심 계약 출력 |
| --- | --- | --- |
| `prepare_metadata` | `01_manifest` + `02a_taint` + `02b_flow` | `manifest_with_testcase_flows.xml`, `selected_taint_config` |
| `run_analysis` | `03_infer-results` + `03_signatures` | `signature_non_empty_dir`, `03_infer_summary.json` |
| `select_pairs` | `04_trace_flow` + `05_pair_trace_ds` | `pairs.jsonl`, `paired_signatures/` |
| `build_dataset` | `06_slices` + `07_dataset_export` | `Real_Vul_data.csv`, `split_manifest.json`, `summary.json` |
| `optional_patched_eval_export` | `07b` | `train_patched_counterparts.csv`, `train_patched_counterparts_summary.json` |

---

## 1. `prepare_metadata`

### 목적
manifest와 source tree를 읽어 downstream 분석에 필요한 metadata를 준비합니다.

이 단계는 두 가지를 만들어야 합니다.

1. testcase별 flow 정보가 들어 있는 manifest
2. Infer 실행에 사용할 taint config 경로

### 현재 구현 포함 범위
- `01_manifest_comment_scan`
- `02a_code_field_inventory`
- `02b_function_inventory_extract`
- `02b_function_inventory_categorize`
- `02b_testcase_flow_partition`

### 입력
- `manifest.xml`
- `source_root`
- `committed_taint_config` (fallback 용)

### 계약 출력
- `manifest_with_testcase_flows.xml`
- `selected_taint_config`
  - 우선순위:
    1. generated taint config
    2. committed taint config fallback

### 현재 코드상 단계 연결
- `01_manifest_comment_scan`
  - 입력: `manifest.xml`, `source_root`
  - 출력: `01_manifest/manifest_with_comments.xml`
- `02a_code_field_inventory`
  - 입력: `manifest_with_comments.xml`, `source_root`
  - 출력: `02a_taint/pulse-taint-config.json`
- `02b_function_inventory_extract`
  - 입력: `manifest_with_comments.xml`
  - 출력: `02b_flow/function_names_unique.csv`
- `02b_function_inventory_categorize`
  - 입력:
    - `function_names_unique.csv`
    - `manifest_with_comments.xml`
    - `source_root/testcases`
  - 출력:
    - `function_names_categorized.jsonl`
    - `grouped_family_role.json`
    - `category_summary.json`
- `02b_testcase_flow_partition`
  - 입력:
    - `manifest_with_comments.xml`
    - `function_names_categorized.jsonl`
  - 출력:
    - `manifest_with_testcase_flows.xml`
    - `testcase_flow_summary.json`

### 최소 성공 조건
- `manifest_with_testcase_flows.xml` 이 존재한다.
- downstream에서 사용할 taint config 경로가 존재한다.

### 현재 코드가 실제로 확인하는 것
- `generated_taint_config` 가 있으면 그것을 사용한다.
- 없으면 `--committed-taint-config` 경로를 fallback으로 사용한다.
- 즉 `selected_taint_config` 는 **현재 코드상 on-disk 산출물 이름이 아니라 orchestration 값**이다.

### 보장해야 하는 것
- testcase별 flow 정보가 downstream에서 읽을 수 있는 형태여야 한다.
- taint config 선택 결과가 deterministic 해야 한다.
- 이 단계는 Infer 실행을 포함하지 않는다.

### 보고용 산출물 예시
- `manifest_with_comments.xml`
- code inventory / frequency CSV
- function inventory CSV / categorized JSONL
- grouped family-role JSON
- 각종 summary JSON

### 독립 단계로 남길 이유
- Infer 이전의 저비용 준비 단계다.
- 중간 결과를 사람이 확인하기 쉽다.
- 재실행 비용이 낮아 checkpoint 가치가 있다.

---

## 2. `run_analysis`

### 목적
선택된 taint config로 Infer를 실행하고 downstream이 사용할 signature 집합을 만듭니다.

### 현재 구현 포함 범위
- `tools/run-infer-all-juliet.py`
- 내부 signature 생성 로직

### 입력
- `selected_taint_config`
- 분석 대상 선택
  - `cwes`
  - `--all`
  - `--files`
- `source_root`

### 계약 출력
- `signature_non_empty_dir`
- `03_infer_summary.json`

### 현재 코드상 단계 연결
- `tools/lib/pipeline_run.py` 는 다음 인자를 넣어 `tools/run-infer-all-juliet.py` 를 실행한다.
  - `--pulse-taint-config <selected_taint_config>`
  - `--infer-results-root <run_dir>/03_infer-results`
  - `--signatures-root <run_dir>/03_signatures`
  - `--summary-json <run_dir>/03_infer_summary.json`
- 실행 후 `03_infer_summary.json` 을 읽어서
  - `signature_non_empty_dir` 가 있으면 그대로 사용하고
  - 없으면 `signature_output_dir/non_empty` 로 해석한다.

### 최소 성공 조건
- `03_infer_summary.json` 이 존재한다.
- `signature_non_empty_dir` 가 존재한다.

### 현재 코드가 실제로 확인하는 것
- `03_infer_summary.json`
- summary에서 해석한 `signature_non_empty_dir`

### 보장해야 하는 것
- downstream은 `signature_non_empty_dir` 만으로 다음 단계로 진행할 수 있어야 한다.
- summary에는 signature 출력 위치를 해석할 수 있는 정보가 있어야 한다.
- 이 단계는 선택된 대상에 대해서만 실행된다.

### 보고용 산출물 예시
- raw infer results
- `analysis/result.csv`
- `analysis/no_issue_files.txt`
- signature counts CSV

### 독립 단계로 남길 이유
- 실행 비용이 가장 크다.
- rerun / cache / 실패 복구 단위로 자연스럽다.
- 파이프라인에서 가장 명확한 계산 경계다.

---

## 3. `select_pairs`

### 목적
trace를 testcase flow에 매칭하고 dataset 후보로 사용할 `b2b` / counterpart 쌍을 선택합니다.

### 현재 구현 포함 범위
- `04_trace_flow_filter`
- `05_pair_trace_ds`

### 입력
- `manifest_with_testcase_flows.xml`
- `signature_non_empty_dir`

### 계약 출력
- `pairs.jsonl`
- `paired_signatures/`

### 현재 코드상 단계 연결
- `04_trace_flow_filter`
  - 입력:
    - `manifest_with_testcase_flows.xml`
    - `signature_non_empty_dir`
  - 출력:
    - `04_trace_flow/trace_flow_match_all.jsonl`
    - `04_trace_flow/trace_flow_match_strict.jsonl`
    - `04_trace_flow/trace_flow_match_partial_or_strict.jsonl`
    - `04_trace_flow/summary.json`
- `05_pair_trace_ds`
  - 입력:
    - `04_trace_flow/trace_flow_match_strict.jsonl`
  - 출력:
    - `05_pair_trace_ds/pairs.jsonl`
    - `05_pair_trace_ds/leftover_counterparts.jsonl`
    - `05_pair_trace_ds/paired_signatures/`
    - `05_pair_trace_ds/summary.json`

### 최소 성공 조건
- `pairs.jsonl` 이 존재한다.
- `paired_signatures/` 디렉터리가 존재한다.

### 현재 코드가 실제로 확인하는 것
- Step 04 후:
  - `04_trace_flow/trace_flow_match_strict.jsonl`
- Step 05 후:
  - `05_pair_trace_ds/pairs.jsonl`
  - `05_pair_trace_ds/paired_signatures/`
  - `05_pair_trace_ds/summary.json`

### 보장해야 하는 것
- 각 pair는 동일 testcase 내에서 선택된 `b2b` 와 counterpart를 표현해야 한다.
- `paired_signatures/` 는 `pairs.jsonl` 과 대응되는 signature-style 입력 집합이어야 한다.
- pair selection 정책은 deterministic 해야 한다.
  - 현재 기준: 여러 후보가 있으면 `bug_trace_length` 우선

### 보고용 산출물 예시
- `trace_flow_match_all.jsonl`
- `trace_flow_match_strict.jsonl`
- `trace_flow_match_partial_or_strict.jsonl`
- `leftover_counterparts.jsonl`
- 각종 summary JSON

### 독립 단계로 남길 이유
- 어떤 trace를 dataset 후보로 인정할지 결정하는 품질 게이트다.
- 정책 변경을 export 로직과 분리할 수 있다.
- 중간 결과를 따로 분석할 가치가 있다.

---

## 4. `build_dataset`

### 목적
선택된 pair에서 slice를 만들고 최종 dataset export를 생성합니다.

### 현재 구현 포함 범위
- `06_generate_slices`
- `07_dataset_export`

### 입력
- `pairs.jsonl`
- `paired_signatures/`
- export 파라미터
  - `pair_split_seed`
  - `pair_train_ratio`
  - `dedup_mode`

### 계약 출력
- `07_dataset_export/Real_Vul_data.csv`
- `07_dataset_export/split_manifest.json`
- `07_dataset_export/summary.json`

### 현재 코드상 단계 연결
- `06_generate_slices`
  - 입력:
    - `05_pair_trace_ds/paired_signatures/`
  - 출력:
    - `06_slices/slice/`
    - `06_slices/summary.json`
- `07_dataset_export`
  - 입력:
    - `05_pair_trace_ds/pairs.jsonl`
    - `05_pair_trace_ds/paired_signatures/`
    - `06_slices/slice/`
    - `pair_split_seed`
    - `pair_train_ratio`
    - `dedup_mode`
  - 구현:
    - `tools/lib/pipeline_run.py` 의 `export_dataset_from_pipeline()`
  - 출력:
    - `07_dataset_export/Real_Vul_data.csv`
    - `07_dataset_export/Real_Vul_data_dedup_dropped.csv`
    - `07_dataset_export/normalized_slices/`
    - `07_dataset_export/normalized_token_counts.csv`
    - `07_dataset_export/slice_token_distribution.png`
    - `07_dataset_export/split_manifest.json`
    - `07_dataset_export/summary.json`

### 최소 성공 조건
- `Real_Vul_data.csv` 가 존재한다.
- `split_manifest.json` 이 존재한다.
- `summary.json` 이 존재한다.

### 현재 코드가 실제로 확인하는 것
- Step 06 후:
  - `06_slices/slice/`
  - `06_slices/summary.json`
- Step 07 후:
  - `07_dataset_export/normalized_slices/`
  - `07_dataset_export/Real_Vul_data.csv`
  - `07_dataset_export/Real_Vul_data_dedup_dropped.csv`
  - `07_dataset_export/normalized_token_counts.csv`
  - `07_dataset_export/slice_token_distribution.png`
  - `07_dataset_export/split_manifest.json`
  - `07_dataset_export/summary.json`

### 보장해야 하는 것
- split 단위는 `pair_id` 이다.
- 동일 seed / ratio / dedup mode 에 대해 재현 가능한 결과를 생성해야 한다.
- 최종 CSV와 split manifest가 서로 모순되지 않아야 한다.
- 현재 구현은 중간에 slice를 물리적으로 생성할 수 있으나, 개념상 이 단계 내부 작업으로 본다.

### 보고용 산출물 예시
- `06_slices/slice/`
- `07_dataset_export/normalized_slices/`
- token count CSV
- token distribution plot
- dedup dropped CSV

### 독립 단계로 남길 이유
- 최종 deliverable 생성 경계다.
- split / dedup / export 정책을 한 곳에서 통제할 수 있다.
- slicing 자체는 장기적으로 내부 구현으로 흡수될 수 있다.

---

## 5. `optional_patched_eval_export`

### 목적
기본 dataset export와 별도로 train split 기반의 patched counterpart 평가용 export를 생성합니다.

### 현재 구현 포함 범위
- `07b_train_patched_counterparts_export`
- `tools/rerun-step07.py` 에서 재실행 가능한 후속 작업

### 입력
- 기존 run의 Step 05/06/07 산출물
- 특히:
  - pair 관련 산출물
  - slice 관련 산출물
  - `07_dataset_export/split_manifest.json`
- `dedup_mode`

### 계약 출력
- `train_patched_counterparts.csv`
- `train_patched_counterparts_summary.json`

### 현재 코드상 단계 연결
- `tools/export_train_patched_counterparts.py` 는 기본적으로 다음 산출물을 사용한다.
  - `05_pair_trace_ds/pairs.jsonl`
  - `05_pair_trace_ds/leftover_counterparts.jsonl`
  - `07_dataset_export/split_manifest.json`
- 기본 출력 위치:
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

### 최소 성공 조건
- `train_patched_counterparts.csv` 가 존재한다.
- `train_patched_counterparts_summary.json` 이 존재한다.

### 현재 코드가 실제로 확인하는 것
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

### 보장해야 하는 것
- 기본 dataset export를 깨지 않고 독립적으로 실행 가능해야 한다.
- train split 기준 selection 정책이 일관되어야 한다.

### 보고용 산출물 예시
- patched counterpart pairs / signatures
- patched slice dir
- token counts CSV
- plot
- patched split manifest

### 독립 단계로 남길 이유
- 핵심 dataset 생성이 아니라 파생 평가용 export다.
- 기본 실행 경로에서 옵션 단계로 분리할 가치가 크다.

---

## 잠정 결론

현재 파이프라인은 on-disk 단계 수보다 **개념 단계 수가 더 적습니다**.

우선은 아래 4개 + optional 1개로 보는 것이 자연스럽습니다.

1. `prepare_metadata`
2. `run_analysis`
3. `select_pairs`
4. `build_dataset`
5. `optional_patched_eval_export`

리팩토링은 먼저 이 개념 경계에 맞춰 top-level 코드를 정리하고,
그 다음에 실제 디렉터리/스크립트 구조를 단순화하는 순서가 적합합니다.

단, 현재 코드는 여전히 `01`~`07b` 의 **물리 단계와 파일 존재 여부 검사**에 의존합니다.
따라서 실제 리팩토링 전까지는 이 문서를 **개념 계약 문서**로 사용하되,
경로/파일/성공 조건은 `tools/lib/pipeline_run.py` 와 함께 읽는 것이 안전합니다.

## 리팩토링 원칙

1. 계약 출력을 먼저 고정하고 구현은 나중에 바꾼다.
2. 보고용 산출물은 가능하면 contract 바깥으로 민다.
3. 현재 경로 호환성은 최대한 유지한다.
4. `07b` 는 기본 파이프라인의 필수 단계로 취급하지 않는다.
5. `06` 은 장기적으로 `build_dataset` 내부 구현으로 흡수될 수 있다.
