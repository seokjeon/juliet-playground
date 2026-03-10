# juliet-playground

Juliet C/C++ 테스트 스위트에 대해 Infer를 실행하고, 결과에서 signature를 생성/필터링하는 실험 저장소입니다.

## ToC

- [Quick Start](#quick-start)
- [결과 위치](#결과-위치)
- [스크립트 소개](#스크립트-소개)
- [그 외 자주 쓰는 명령어](#그-외-자주-쓰는-명령어)
- [메모](#메모)

## Quick Start

### 1) 환경 설정 (최초 1회)

```bash
# python, clang 설치
sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip clang curl xz-utils libunwind8

# infer 설치
cd /tmp && curl -fL -o infer-linux-x86_64-v1.2.0.tar.xz https://github.com/facebook/infer/releases/download/v1.2.0/infer-linux-x86_64-v1.2.0.tar.xz && tar -xf infer-linux-x86_64-v1.2.0.tar.xz && sudo rm -rf /opt/infer-linux-x86_64-v1.2.0 && sudo mv infer-linux-x86_64-v1.2.0 /opt/ && sudo ln -sf /opt/infer-linux-x86_64-v1.2.0/bin/infer /usr/local/bin/infer

# 파이썬 패키지 설치
cd /home/sojeon/Desktop/juliet-playground && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

### 2) 단일 infer 실행

```bash
source .venv/bin/activate && python tools/run-infer-all-juliet.py 78
```

### 3) 통합 파이프라인 실행

```bash
source .venv/bin/activate && python tools/run-epic001-pipeline.py 78
```

전체 CWE에 대해 실행하려면:

```bash
source .venv/bin/activate && python tools/run-epic001-pipeline.py --all
```

기본 run-id 규칙은 `run-YYYY.MM.DD-HH:MM:SS` 이며,
실제 경로는 `artifacts/pipeline-runs/run-.../` 입니다.

## 결과 위치

```text
artifacts/
├── infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
│       ├── CWE.../infer-out/
│       └── analysis/
│           ├── no_issue_files.txt
│           └── result.csv
├── signatures/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
│       └── signature-YYYY.MM.DD-HH:MM:SS/
│           ├── non_empty/
│           │   ├── CWE.../*.json                 # bug_trace non-empty signature
│           │   └── analysis/signature_counts.csv # CWE별 통계 + TOTAL
│           └── flow_matched/                     # placeholder (추후 생성)
└── pipeline-runs/
    └── run-YYYY.MM.DD-HH:MM:SS/
        ├── 01_manifest/manifest_with_comments.xml
        ├── 02a_taint/pulse-taint-config.json
        ├── 02b_flow/manifest_with_testcase_flows.xml
        ├── 03_infer-results/
        ├── 03_signatures/
        ├── 04_trace_flow/trace_flow_match_strict.jsonl
        ├── 05_pair_trace_ds/
        │   ├── pairs.jsonl
        │   ├── leftover_counterparts.jsonl
        │   ├── paired_signatures/<testcase_key>/{b2b.json,g2b.json,...}
        │   ├── train_patched_counterparts_pairs.jsonl
        │   └── train_patched_counterparts_signatures/<testcase_key>/{b2b.json,g2b.json,...}
        ├── 06_slices/
        │   ├── slice/*.c|*.cpp
        │   ├── summary.json
        │   └── train_patched_counterparts/slice/*.c|*.cpp
        ├── 07_dataset_export/
        │   ├── normalized_slices/*.c|*.cpp
        │   ├── Real_Vul_data.csv
        │   ├── normalized_token_counts.csv
        │   ├── slice_token_distribution.png
        │   ├── split_manifest.json
        │   ├── summary.json
        │   ├── train_patched_counterparts.csv
        │   └── train_patched_counterparts_slices/*.c|*.cpp
        └── run_summary.json
```

## 스크립트 소개

- **Infer 실행**: `tools/run-infer-all-juliet.py`
  - CWE 단위/파일 단위로 Juliet 테스트케이스를 실행
  - `issue / no_issue / error` 집계, `analysis/result.csv`, `analysis/no_issue_files.txt` 생성
  - infer 실행 후 signature도 생성
  - 옵션: `--all`, `--files`, `--pulse-taint-config`, `--infer-results-root`, `--signatures-root`, `--summary-json`
- **Signature 생성**: `tools/generate-signature.py`
  - `infer-out/report.json`에서 `bug_trace`가 있는 이슈를 `non_empty/`에 JSON으로 분리 저장
  - `non_empty/analysis/signature_counts.csv`에 CWE별 통계 저장
- **통합 파이프라인**: `tools/run-epic001-pipeline.py`
  - `manifest -> with_comments -> taint config -> flow xml -> infer/signature -> trace_flow_filter -> paired_trace_ds -> slices -> dataset_export`
  - 실행별 산출물을 `artifacts/pipeline-runs/...`에 분리 저장
  - 타깃 지정: `CWE 번호들` / `--all` / `--files ...`
- **Paired trace dataset 생성**: `tools/build-paired-trace-signatures.py`
  - `trace_flow_match_strict.jsonl`에서 testcase별 `b2b` / 대응 trace를 1:1로 선택
  - 대응 후보가 여러 개면 `bug_trace_length`가 가장 긴 trace를 선택하고 나머지는 별도 보관
  - `paired_signatures/<testcase_key>/b2b.json`, `g2b.json` 등의 형태로 출력
- **Slice 생성**: `tools/generate_slices.py`
  - `paired_signatures`의 `bug_trace`에서 소스 라인만 모아 슬라이스 생성
  - `.c`는 `.c`, C++ trace는 `.cpp`로 저장
- **Dataset export (pipeline 내장)**: `tools/run-epic001-pipeline.py`
  - 06에서 만든 slice를 기준으로 사용자 정의 함수명만 normalize
  - normalize 후 CodeBERT 토큰 수를 재계산하고 pair 단위로 510 토큰 이하만 필터링
  - `Real_Vul_data.csv`, `normalized_slices/`, 히스토그램/CSV를 생성
- **Train patched counterpart export**: `tools/export_train_patched_counterparts.py`
  - 기존 `07_dataset_export/split_manifest.json`에서 `train_val`로 사용된 pair만 대상으로 함
  - `leftover_counterparts.jsonl`에서 testcase별 최상위 leftover counterpart 1개를 골라 평가용 데이터셋 생성
  - `train_patched_counterparts.csv`, `train_patched_counterparts_slices/`, 관련 summary/manifest를 생성

## 그 외 자주 쓰는 명령어

```bash
# Infer만 빠르게 실행
python tools/run-infer-all-juliet.py 78

# 특정 파일(해당 flow variant 그룹)만 실행
python tools/run-infer-all-juliet.py --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c

# 기존 infer 결과에서 signature만 생성
python tools/generate-signature.py --input-dir artifacts/infer-results/infer-2026.03.08-18:04:18

# 통합 파이프라인 (CWE 여러개)
python tools/run-epic001-pipeline.py 78 89

# 통합 파이프라인 (전체 CWE)
python tools/run-epic001-pipeline.py --all

# strict trace 결과만으로 paired trace dataset 생성
python tools/build-paired-trace-signatures.py \
  --trace-jsonl artifacts/pipeline-runs/run-2026.03.09-22:18:32/04_trace_flow/trace_flow_match_strict.jsonl \
  --output-dir /tmp/paired-trace-ds

# 옵션 없이 실행하면 최신 pipeline run의 strict trace를 찾아
# 같은 run 아래 05_pair_trace_ds/ 로 출력
python tools/build-paired-trace-signatures.py

# paired_signatures 로부터 slice 생성
python tools/generate_slices.py \
  --signature-db-dir artifacts/pipeline-runs/run-2026.03.09-22:18:32/05_pair_trace_ds/paired_signatures \
  --output-dir /tmp/paired-slices

# 옵션 없이 실행하면 최신 pipeline run의 paired_signatures 를 찾아
# 같은 run 아래 06_slices/ 로 출력
python tools/generate_slices.py

# 기존 train_val 샘플들에 대응하는 patched counterpart 평가셋 생성
python tools/export_train_patched_counterparts.py \
  --run-dir artifacts/pipeline-runs/run-2026.03.10-00:49:21
```

## 메모

- `.cpp`는 `clang++`, `.c`는 `clang` 사용
- `--files` 사용 시 `cwes` / `--all` 은 무시
- `--all` 사용 시 `cwes` 인자는 무시
- Juliet 파일명 규칙 기반으로 같은 flow variant 그룹을 함께 컴파일
- Pulse taint 기준 설정: `config/pulse-taint-config.json`
- 파이프라인 생성 taint config: `.../02a_taint/pulse-taint-config.json` (수동 승격 대상)
- 개별 experiments 스크립트 실행 시에는 기존 `experiments/*/outputs`를 그대로 사용
