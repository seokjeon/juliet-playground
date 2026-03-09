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
        └── run_summary.json
```

## 스크립트 소개

- **Infer 실행**: `tools/run-infer-all-juliet.py`
  - CWE 단위/파일 단위로 Juliet 테스트케이스를 실행
  - `issue / no_issue / error` 집계, `analysis/result.csv`, `analysis/no_issue_files.txt` 생성
  - infer 실행 후 signature도 생성
  - 옵션: `--pulse-taint-config`, `--infer-results-root`, `--signatures-root`, `--summary-json`
- **Signature 생성**: `tools/generate-signature.py`
  - `infer-out/report.json`에서 `bug_trace`가 있는 이슈를 `non_empty/`에 JSON으로 분리 저장
  - `non_empty/analysis/signature_counts.csv`에 CWE별 통계 저장
- **통합 파이프라인**: `tools/run-epic001-pipeline.py`
  - `manifest -> with_comments -> taint config -> flow xml -> infer/signature -> trace_flow_filter`
  - 실행별 산출물을 `artifacts/pipeline-runs/...`에 분리 저장

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
```

## 메모

- `.cpp`는 `clang++`, `.c`는 `clang` 사용
- `--files` 사용 시 `cwes` 인자는 무시
- Juliet 파일명 규칙 기반으로 같은 flow variant 그룹을 함께 컴파일
- Pulse taint 기준 설정: `config/pulse-taint-config.json`
- 파이프라인 생성 taint config: `.../02a_taint/pulse-taint-config.json` (수동 승격 대상)
- 개별 experiments 스크립트 실행 시에는 기존 `experiments/*/outputs`를 그대로 사용
