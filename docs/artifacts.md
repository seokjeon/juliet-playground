# Artifacts reference

현재 파이프라인 산출물은 **실제 artifact + compact summary** 구조를 사용합니다.
대부분의 summary JSON 은 아래 형태로 통일되었습니다.

```json
{
  "artifacts": {...},
  "stats": {...}
}
```

운영 전반은 [`pipeline-runbook.md`](pipeline-runbook.md), 재실행/운영 주의사항은 [`rerun.md`](rerun.md), 단계 계약은 [`stage-contracts.md`](stage-contracts.md)를 참고하세요.

## 단일 Infer / Signature 산출물

`run_infer_and_signature()` 는 기본적으로 아래를 생성합니다.

```text
artifacts/
├── infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
└── signatures/
    └── infer-YYYY.MM.DD-HH:MM:SS/
        └── signature-YYYY.MM.DD-HH:MM:SS/
            ├── non_empty/
            │   ├── CWE.../*.json
            │   └── analysis/signature_counts.csv
            └── flow_matched/
```

선택적으로 `03_infer_summary.json` 을 쓰면 summary 는 아래 성격만 담습니다.

- `artifacts`
  - `infer_run_dir`
  - `signature_output_dir`
  - `signature_non_empty_dir`
- `stats`
  - `issue`
  - `no_issue`
  - `error`
  - `total_cases`
  - `elapsed_seconds`
  - `targets_analyzed`

## 파이프라인 run 산출물

`python tools/run_pipeline.py full ...` 는 `artifacts/pipeline-runs/run-.../` 아래에 아래 구조를 만듭니다.

```text
artifacts/pipeline-runs/run-YYYY.MM.DD-HH:MM:SS/
├── 01_manifest/
│   └── manifest_with_comments.xml
├── 02a_taint/
│   ├── function_name_macro_resolution.csv
│   ├── pulse-taint-config.json
│   └── summary.json
├── 02b_flow/
│   ├── epic002/
│   │   ├── source_sink_classified.xml
│   │   ├── source_sink_exceptions.xml
│   │   └── summary.json
│   ├── manifest_with_testcase_flows.xml
│   └── summary.json
├── 03_infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
├── 03_signatures/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
│       └── signature-YYYY.MM.DD-HH:MM:SS/
│           ├── non_empty/
│           └── flow_matched/
├── 03_infer_summary.json
├── 04_trace_flow/
│   ├── trace_flow_match_strict.jsonl
│   └── summary.json
├── 05_trace_ds/                           # 기본 trace-first 모드
│   ├── traces.jsonl
│   └── summary.json
├── 05_pair_trace_ds/                      # --enable-pair 모드
│   ├── pairs.jsonl
│   ├── leftover_counterparts.jsonl
│   ├── paired_signatures/<testcase_key>/{b2b.json,g2b.json,...}
│   ├── summary.json
│   ├── train_patched_counterparts_pairs.jsonl
│   └── train_patched_counterparts_signatures/<testcase_key>/{b2b.json,g2b.json,...}
├── 06_trace_slices/                       # 기본 trace-first 모드
│   ├── slice/*.c|*.cpp
│   └── summary.json
├── 06_slices/                             # --enable-pair 모드
│   ├── slice/*.c|*.cpp
│   ├── summary.json
│   └── train_patched_counterparts/
│       ├── slice/*.c|*.cpp
│       └── summary.json
└── 07_dataset_export/
    ├── normalized_slices/*.c|*.cpp
    ├── Real_Vul_data.csv
    ├── split_manifest.json
    ├── summary.json
    ├── trace_dedup_dropped.jsonl       # 기본 trace-first 모드
    ├── train_patched_counterparts.csv
    ├── train_patched_counterparts_slices/*.c|*.cpp
    ├── train_patched_counterparts_split_manifest.json
    ├── train_patched_counterparts_summary.json
    └── vuln_patch/
        ├── Real_Vul_data.csv
        └── summary.json
```

## external fast path run 산출물

`python tools/run_external_trace_pipeline.py ...` 는 기본적으로
`artifacts/external-runs/<run-id>/` 아래에 아래 구조를 만듭니다.

```text
artifacts/external-runs/<run-id>/
├── 03_infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
├── 03_signatures/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
│       └── signature-YYYY.MM.DD-HH:MM:SS/
│           ├── non_empty/
│           └── flow_matched/
├── 03_infer_summary.json
├── 05b_manual_line_filter/
│   ├── dropped_traces.jsonl
│   ├── normalized_manual_lines.jsonl
│   ├── summary.json
│   └── traces.jsonl
├── 06_trace_slices/
│   ├── slice/*.c|*.cpp
│   └── summary.json
└── 07_dataset_export/
    ├── normalized_slices/*.c|*.cpp
    ├── Real_Vul_data.csv
    ├── summary.json
    └── trace_row_manifest.jsonl
```

운영 중에는 `--output-root artifacts/external-runs/<CVE-or-project>` 처럼 상위 디렉터리를
한 번 더 주어 `artifacts/external-runs/<CVE-or-project>/<run-id>/` 형태로 저장하는 경우가 많습니다.
또한 `artifacts/external-runs/archive/` 는 과거 실험 run을 옮겨 둔 관례용 디렉터리입니다.

external fast path에서 후속 소비용 대표 파일은 아래 둘입니다.

- `07_dataset_export/Real_Vul_data.csv`
  - external project용 test-only dataset CSV
- `07_dataset_export/trace_row_manifest.jsonl`
  - dataset row와 trace/source line 매핑
  - 예: `tools/run_pdbert_eval_only.py --dataset-csv ... --row-manifest ...`

## 핵심 summary 파일

- `02a_taint/summary.json`
  - `artifacts`: pulse taint config, candidate map, summary path
  - `stats`: code/function count 핵심 값
- `02b_flow/summary.json`
  - `artifacts`: 02b 최종 산출물 경로
  - `stats`: function count / weighted count / testcase count
- `03_infer_summary.json`
  - infer + signature 핵심 경로와 집계 통계
- `04_trace_flow/summary.json`
  - strict trace JSONL 경로와 strict match 집계
- `05_pair_trace_ds/summary.json`
  - pair/leftover/signature 경로와 testcase 집계
- `05_trace_ds/summary.json`
  - trace-first dataset JSONL 경로와 flow/label 집계
- `06_slices/summary.json`
  - slice dir 경로와 generated/skipped/errors 집계
- `06_trace_slices/summary.json`
  - trace-first slice dir 경로와 generated/skipped/errors 집계
- `07_dataset_export/summary.json`
  - dataset artifact 경로와 dedup/filter/split 집계
  - 기본 trace-first 모드에서는 trace dedup audit JSONL과 `vuln_patch` holdout 경로도 포함
- `07_dataset_export/train_patched_counterparts_summary.json`
  - patched dataset artifact 경로와 dedup/filter/split 집계
  - 추가로 `stats.selection` 에 patched counterpart selection 집계를 포함
- `07_dataset_export/vuln_patch/summary.json`
  - trace-first holdout dataset 선택 결과와 CSV 경로를 포함

## 디버깅 팁

- 03 이후 흐름 확인 순서:
  - `03_infer_summary.json`
  - `04_trace_flow/summary.json`
  - 기본 trace-first 모드:
    - `05_trace_ds/summary.json`
    - `06_trace_slices/summary.json`
    - `07_dataset_export/summary.json`
    - `07_dataset_export/vuln_patch/summary.json`
  - `--enable-pair` 모드:
    - `05_pair_trace_ds/summary.json`
    - `06_slices/summary.json`
    - `07_dataset_export/summary.json`
    - `07_dataset_export/train_patched_counterparts_summary.json`
- legacy verbose summary, dedup audit CSV, token count CSV, token plot PNG 는 기본 계약에서 제거되었습니다.
- 현재 코드 기준 source of truth 는 `tools/stage/*.py` 와 `tests/` 입니다.
