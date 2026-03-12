# juliet-playground

Juliet C/C++ 테스트 스위트에 대해 Infer를 실행하고, signature를 추출/필터링하고,
paired trace → slice → dataset export까지 이어지는 실험 저장소입니다.

## 문서 안내

- 운영 문서 인덱스:
  [`docs/pipeline-runbook.md`](docs/pipeline-runbook.md)
- 산출물 구조 / summary JSON / 로그 위치:
  [`docs/artifacts.md`](docs/artifacts.md)
- 재실행 / `--overwrite` / 경로 이식 / 재현성 옵션:
  [`docs/rerun.md`](docs/rerun.md)
- Step 01 (`manifest -> with_comments`):
  [`experiments/epic001_manifest_comment_scan/README.md`](experiments/epic001_manifest_comment_scan/README.md)
- Step 02a (`with_comments -> taint config`):
  [`experiments/epic001a_code_field_inventory/README.md`](experiments/epic001a_code_field_inventory/README.md)
- Step 02b (`function inventory / flow xml`):
  [`experiments/epic001b_function_inventory/README.md`](experiments/epic001b_function_inventory/README.md),
  [`experiments/epic001c_testcase_flow_partition/README.md`](experiments/epic001c_testcase_flow_partition/README.md)
- Step 04 (`trace flow filter`):
  [`experiments/epic001d_trace_flow_filter/README.md`](experiments/epic001d_trace_flow_filter/README.md)

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

### 개발 체크

```bash
# 개발용 git hook 설치
source .venv/bin/activate && pre-commit install

# 평소 개발 루틴
source .venv/bin/activate && ruff check . && pytest -q

# 코드 스타일 자동 정리가 필요하면
source .venv/bin/activate && ruff format .
```

커밋할 때는 `pre-commit` hook이 자동으로 실행됩니다.
개발 확인이 끝나면 아래의 Infer / 파이프라인 실행 명령을 사용하면 됩니다.

### 2) 단일 Infer 실행

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

기본 run-id 규칙은 `run-YYYY.MM.DD-HH:MM:SS`이며,
실제 경로는 `artifacts/pipeline-runs/run-.../` 입니다.

## 파이프라인 개요

`tools/run-epic001-pipeline.py`는 아래 단계를 순서대로 실행합니다.

1. `01_manifest`: manifest에 Juliet 주석 매핑
2. `02a_taint`: code inventory / 함수 후보 추출 / pulse taint config 생성
3. `02b_flow`: 함수 inventory 분류 + testcase별 flow XML 생성
4. `03_infer-results`, `03_signatures`: Infer 실행과 signature 생성
5. `04_trace_flow`: trace와 testcase flow 매칭
6. `05_pair_trace_ds`: strict trace에서 `b2b` / counterpart pair 선택
7. `06_slices`: pair signature의 bug trace를 소스 slice로 변환
8. `07_dataset_export`: normalize / dedup / token filtering / split / CSV export
9. `07b`: train patched counterpart 평가용 export 추가 생성

## 결과 위치 (요약)

```text
artifacts/
├── infer-results/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
│       ├── CWE.../infer-out/
│       └── analysis/{result.csv,no_issue_files.txt}
├── signatures/
│   └── infer-YYYY.MM.DD-HH:MM:SS/
│       └── signature-YYYY.MM.DD-HH:MM:SS/
│           └── non_empty/CWE.../*.json
└── pipeline-runs/
    └── run-YYYY.MM.DD-HH:MM:SS/
        ├── 01_manifest/
        ├── 02a_taint/
        ├── 02b_flow/
        ├── 03_infer-results/
        ├── 03_signatures/
        ├── 04_trace_flow/
        ├── 05_pair_trace_ds/
        ├── 06_slices/
        ├── 07_dataset_export/
        ├── logs/
        └── run_summary.json
```

전체 산출물 트리와 각 파일 의미는
[`docs/artifacts.md`](docs/artifacts.md)를 참고하세요.

## 대표 명령어

```bash
# Infer만 빠르게 실행
python tools/run-infer-all-juliet.py 78

# 특정 파일(해당 flow variant 그룹)만 실행
python tools/run-infer-all-juliet.py --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c

# 기존 infer 결과에서 signature만 생성
python tools/generate-signature.py --input-dir artifacts/infer-results/infer-2026.03.08-18:04:18

# 통합 파이프라인
python tools/run-epic001-pipeline.py 78 89

# strict trace 결과에서 paired trace dataset만 생성
python tools/build-paired-trace-signatures.py

# 기존 run의 Step 07 + 07b 재생성
python tools/rerun-step07.py --run-dir artifacts/pipeline-runs/run-2026.03.10-00:49:21
```

추가 명령 예시와 재실행 패턴은 [`docs/rerun.md`](docs/rerun.md)에 정리되어 있습니다.

## 메모

- `tools/generate-signature.py`는 `infer-out/report.json`의 모든 이슈를 저장하지 않습니다.
  `bug_type == TAINT_ERROR`이면서 `bug_trace`가 non-empty인 레코드만 signature로 저장합니다.
- `--files` 사용 시 `cwes` / `--all`은 무시됩니다.
- `--all` 사용 시 positional `cwes` 인자는 무시됩니다.
- `.cpp`는 `clang++`, `.c`는 `clang`을 사용합니다.
- `run-infer-all-juliet.py --global-result`를 쓰면 infer 결과 root가
  로컬 `artifacts/infer-results/` 대신 `/data/pattern/result/infer-results/`로 바뀝니다.
- CodeBERT tokenizer 캐시, `--overwrite`, `--old-prefix/--new-prefix`,
  `rerun-step07.py`의 suffix 규칙, 재현성 옵션은 [`docs/rerun.md`](docs/rerun.md)를 참고하세요.
