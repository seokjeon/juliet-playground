# Artifacts reference

산출물 구조, summary JSON, 로그/디버깅 포인트를 정리한 문서입니다.
운영 전반은 [`pipeline-runbook.md`](pipeline-runbook.md), 재실행/운영 주의사항은 [`rerun.md`](rerun.md)를 참고하세요.

## 단일 Infer / Signature 산출물

`python tools/run_pipeline.py stage03 ...` 또는
`python tools/generate-signature.py ...`를 독립 실행하면 기본적으로 아래 위치를 사용합니다.

```text
artifacts/
├── infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
│       ├── CWE.../infer-out/
│       └── analysis/
│           ├── result.csv
│           └── no_issue_files.txt
└── signatures/
    └── infer-YYYY.MM.DD-HH:MM:SS/
        └── signature-YYYY.MM.DD-HH:MM:SS/
            ├── non_empty/
            │   ├── CWE.../*.json
            │   └── analysis/signature_counts.csv
            └── flow_matched/
```

추가로 `run_pipeline.py stage03 --summary-json <path>`를 주면 아래 내용을 포함한 요약 JSON을 별도로 저장합니다.

- `infer_run_dir`, `infer_run_name`
- `signature_output_dir`, `signature_non_empty_dir`
- `analysis_result_csv`, `analysis_no_issue_files`
- target별 결과와 총합 통계

`--global-result`를 주면 infer 결과 root는
`artifacts/infer-results/` 대신 `/data/pattern/result/infer-results/`를 사용합니다.
이 경로는 `tools/shared/paths.py`의 환경 전제입니다.

## 파이프라인 run 산출물

`python tools/run_pipeline.py full ...`는 `artifacts/pipeline-runs/run-.../` 아래에 아래 구조를 만듭니다.

```text
artifacts/pipeline-runs/run-YYYY.MM.DD-HH:MM:SS/
├── 01_manifest/
│   └── manifest_with_comments.xml
├── 02a_taint/
│   ├── code_unique.txt
│   ├── code_frequency.csv
│   ├── source_sink_candidate_map.json
│   ├── function_name_frequency.csv
│   ├── function_name_unique.txt
│   ├── function_name_macro_resolution.csv
│   ├── global_macro_definitions_by_name.json
│   ├── global_macro_definitions_by_name.jsonl
│   ├── pulse-taint-config.json
│   └── summary.json
├── 02b_flow/
│   ├── function_names_unique.csv
│   ├── function_inventory_summary.json
│   ├── function_names_categorized.jsonl
│   ├── grouped_family_role.json
│   ├── category_summary.json
│   ├── manifest_with_testcase_flows.xml
│   └── testcase_flow_summary.json
├── 03_infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
├── 03_signatures/
│   └── infer-YYYY.MM.DD-HH:MM:SS/signature-YYYY.MM.DD-HH:MM:SS/non_empty/
├── 03_infer_summary.json
├── 04_trace_flow/
│   ├── trace_flow_match_all.jsonl
│   ├── trace_flow_match_strict.jsonl
│   ├── trace_flow_match_partial_or_strict.jsonl
│   └── summary.json
├── 05_pair_trace_ds/
│   ├── pairs.jsonl
│   ├── leftover_counterparts.jsonl
│   ├── paired_signatures/<testcase_key>/{b2b.json,g2b.json,...}
│   ├── summary.json
│   ├── train_patched_counterparts_pairs.jsonl
│   ├── train_patched_counterparts_selection_summary.json
│   └── train_patched_counterparts_signatures/<testcase_key>/{b2b.json,g2b.json,...}
├── 06_slices/
│   ├── slice/*.c|*.cpp
│   ├── summary.json
│   └── train_patched_counterparts/
│       ├── slice/*.c|*.cpp
│       └── summary.json
├── 07_dataset_export/
│   ├── normalized_slices/*.c|*.cpp
│   ├── Real_Vul_data.csv
│   ├── Real_Vul_data_dedup_dropped.csv
│   ├── normalized_token_counts.csv
│   ├── slice_token_distribution.png
│   ├── split_manifest.json
│   ├── summary.json
│   ├── train_patched_counterparts.csv
│   ├── train_patched_counterparts_dedup_dropped.csv
│   ├── train_patched_counterparts_slices/*.c|*.cpp
│   ├── train_patched_counterparts_token_counts.csv
│   ├── train_patched_counterparts_token_distribution.png
│   ├── train_patched_counterparts_split_manifest.json
│   └── train_patched_counterparts_summary.json
├── logs/
│   ├── 01_manifest_comment_scan.stdout.log
│   ├── 01_manifest_comment_scan.stderr.log
│   ├── ...
│   ├── 07_dataset_export.stdout.log
│   └── 07_dataset_export.stderr.log
└── run_summary.json
```

## 핵심 summary / log 파일

- `run_summary.json`
  - run의 mode, 선택된 taint config, step별 stdout/stderr 로그 경로,
    대표 산출물 경로, infer summary를 포함
- `03_infer_summary.json`
  - Infer run 디렉터리, signature 출력 경로, 결과 CSV/텍스트, target별 통계를 포함
- `04_trace_flow/summary.json`
  - flow index 통계, trace match 통계, best flow 선택 통계를 포함
- `05_pair_trace_ds/summary.json`
  - strict trace 수, pair 수, leftover counterpart 수, 선택된 flow type 분포를 포함
- `07_dataset_export/summary.json`
  - dedup 결과, token stats, source parse error, split counts를 포함
- `07_dataset_export/train_patched_counterparts_summary.json`
  - patched counterpart export의 dedup/token/split 결과를 포함
- `logs/<step>.stdout.log`, `logs/<step>.stderr.log`
  - 외부 스크립트 실행 로그와 내부 Step 07 stdout/stderr 캡처

## 디버깅 팁

- 파이프라인 실패 시 가장 먼저 볼 곳:
  - `run_summary.json`
  - `logs/<step>.stderr.log`
  - `logs/<step>.stdout.log`
- Step 03 이후 흐름이 꼬이면:
  - `03_infer_summary.json`
  - `04_trace_flow/summary.json`
  - `05_pair_trace_ds/summary.json`
  - `07_dataset_export/summary.json`
  - `07_dataset_export/train_patched_counterparts_summary.json`
- 개별 experiment를 직접 실행할 때는 각 `experiments/*/README.md`를 따르세요.
