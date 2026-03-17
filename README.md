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
- 현재 구현 단계 계약 / 테스트 기준 (`tools/run_pipeline.py` 기준):
  [`docs/stage-contracts.md`](docs/stage-contracts.md)
- Step 01 실험 메모 (`manifest -> with_comments`):
  [`experiments/epic001_manifest_comment_scan/README.md`](experiments/epic001_manifest_comment_scan/README.md)
- Step 02a 실험 메모 (`with_comments -> taint config`):
  [`experiments/epic001a_code_field_inventory/README.md`](experiments/epic001a_code_field_inventory/README.md)
- Step 02b 실험 메모 (`function inventory / flow xml`):
  [`experiments/epic001b_function_inventory/README.md`](experiments/epic001b_function_inventory/README.md),
  [`experiments/epic001c_testcase_flow_partition/README.md`](experiments/epic001c_testcase_flow_partition/README.md)
- Step 04 실험 메모 (`trace flow filter`):
  [`experiments/epic001d_trace_flow_filter/README.md`](experiments/epic001d_trace_flow_filter/README.md)

현재 구현 기준으로는 Stage 03 / 05 / 06 / 07 / 07b 동작을 `docs/stage-contracts.md`와
`tools/stage/` 코드에서 확인하는 것이 가장 정확합니다.

## 코드 구조 원칙

- `tools/`
  - 사람이 직접 실행하는 CLI entrypoint, 상위 orchestration, 독립 유틸리티를 둡니다.
  - `tools/run_pipeline.py`는 thin wrapper가 아니라 전체 파이프라인 orchestration 본체를
    포함하는 주 entrypoint입니다.
  - hyphenated filename은 CLI entrypoint에만 사용합니다.
- `tools/stage/`
  - 파이프라인 단계의 실제 구현을 둡니다.
  - 특정 단계의 계약, output schema, 단계별 처리 로직을 직접 구현하는 코드는 여기에 둡니다.
- `tools/shared/`
  - 여러 단계/CLI가 함께 쓰는 공통 helper만 둡니다.
  - path/fs/json/signature/trace/source-analysis 같은 공통 로직은 여기에 둡니다.
- `experiments/`
  - stage-specific notes, 실험 스크립트, 보조 분석 코드를 둡니다.
  - 실험이 정착되면 구현은 `tools/stage/` 또는 `tools/shared/`로 승격하고, `experiments/`에는 문서/보조 스크립트만 남기는 쪽을 기본으로 봅니다.

판단 기준은 간단합니다.

- 전체 파이프라인 orchestration 또는 사람이 직접 실행하는 상위 명령이면 `tools/`
- 한 단계의 계약/처리를 직접 구현하면 `tools/stage/`
- 둘 이상이 재사용하면 `tools/shared/`

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

### 2) 단일 Infer + Signature 실행

```bash
source .venv/bin/activate && python tools/run_pipeline.py stage03 78
```

### 3) 통합 파이프라인 실행

```bash
source .venv/bin/activate && python tools/run_pipeline.py full 78
```

pair 기반 기존 흐름을 유지하려면 기본값 그대로 실행하면 됩니다.
trace-first dataset export를 쓰려면:

```bash
source .venv/bin/activate && python tools/run_pipeline.py full 78 --disable-pair
```

전체 CWE에 대해 실행하려면:

```bash
source .venv/bin/activate && python tools/run_pipeline.py full --all
```

기본 run-id 규칙은 `run-YYYY.MM.DD-HH:MM:SS`이며,
실제 경로는 `artifacts/pipeline-runs/run-.../` 입니다.

## 파이프라인 개요

`tools/run_pipeline.py full`은 아래 단계를 순서대로 실행합니다.

1. `01_manifest`: manifest에 Juliet 주석 매핑
2. `02a_taint`: code inventory / 함수 후보 추출 / pulse taint config 생성
3. `02b_flow`: 함수 inventory 분류 + testcase별 flow XML 생성
4. `03_infer-results`, `03_signatures`: Infer 실행과 signature 생성
5. `04_trace_flow`: trace와 testcase flow 매칭
6. `05_pair_trace_ds` 또는 `05_trace_ds`: strict trace에서 pair 선택 또는 trace-first dataset 준비
7. `06_slices` 또는 `06_trace_slices`: pair signature 또는 trace bug trace를 소스 slice로 변환
8. `07_dataset_export`: normalize / dedup / token filtering / split / CSV export
9. `07b`: pair 모드에서만 train patched counterpart 평가용 export 추가 생성
10. `vuln_patch`: disable-pair 모드에서만 평가용 vuln/patch CSV 생성

### Flow XML note

- Stage 01 manifest의 `<comment_flaw>` / `<comment_fix>` 는 Stage 02b flow XML에서 각각
  `<flaw>` / `<fix>` 로 정규화됩니다.
- Stage 02b flow XML의 함수명 필드는 `function` 하나로 통일됩니다.
- 같은 `(file, line)` 에서 원래 manifest의 `<flaw>` 와 comment 유래 `<flaw>` 가 겹치면,
  `origin="manifest_flaw"` 인 원본 `flaw` 를 남기고 comment 유래 `flaw` 는 제거합니다.
- 같은 `(file, line)` 에 원래 manifest 유래 `flaw` 가 여러 개 있을 때, file명의 CWE prefix와
  `name` 의 CWE prefix가 모두 비교 가능하고 그중 일치하는 항목이 있으면 불일치 항목은 flow에서 제거합니다.
- Stage 02b는 기본적으로 dedup 후 child가 1개뿐인 `<flow>` 는 생성하지 않습니다.
  이전 동작이 필요하면 `--keep-single-child-flows` 또는 Python API의
  `prune_single_child_flows=False` 를 사용합니다.
- flow XML에서는 `origin` 속성으로 항목 출처를 구분할 수 있습니다.

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
# Infer + signature만 빠르게 실행
python tools/run_pipeline.py stage03 78

# 특정 파일(해당 flow variant 그룹)만 실행
python tools/run_pipeline.py stage03 --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c

# 기존 infer 결과에서 signature만 생성
python tools/run_pipeline.py stage03-signature --input-dir artifacts/infer-results/infer-2026.03.08-18:04:18

# 통합 파이프라인
python tools/run_pipeline.py full 78 89

# strict trace 결과에서 paired trace dataset만 생성
python tools/run_pipeline.py stage05

# 기존 run의 Step 07 재생성
RUN_DIR=artifacts/pipeline-runs/run-2026.03.10-00:49:21
python tools/run_pipeline.py stage07 \
  --pairs-jsonl "$RUN_DIR/05_pair_trace_ds/pairs.jsonl" \
  --paired-signatures-dir "$RUN_DIR/05_pair_trace_ds/paired_signatures" \
  --slice-dir "$RUN_DIR/06_slices/slice" \
  --output-dir "$RUN_DIR/07_dataset_export"

# 기존 run의 Step 07b 재생성
python tools/run_pipeline.py stage07b \
  --run-dir "$RUN_DIR" \
  --overwrite

# 최신 pipeline run의 Real_Vul_data.csv 를 VP-Bench linevul 컨테이너로 넘겨
# prepare -> train -> test 실행
python tools/run_linevul.py

# 특정 run 대상 dry-run
python tools/run_linevul.py \
  --run-dir artifacts/pipeline-runs/run-2026.03.17-11:28:48 \
  --dry-run

# 두 pipeline run 또는 dataset export 디렉터리 비교
python tools/compare-artifacts.py \
  artifacts/pipeline-runs/run-before \
  artifacts/pipeline-runs/run-after
```

추가 명령 예시와 재실행 패턴은 [`docs/rerun.md`](docs/rerun.md)에 정리되어 있습니다.

## LineVul 연동 메모

- `tools/run_linevul.py` 는 Stage 07의 `Real_Vul_data.csv` 를 읽어
  VP-Bench의 `linevul` 컨테이너에서
  `baseline/RealVul/Experiments/LineVul/line_vul.py` 를 실행합니다.
- 기본 대상 경로:
  - VP-Bench root: `/home/sojeon/Desktop/VP-Bench`
  - container: `linevul`
- 결과는 기본적으로 VP-Bench 쪽에만 저장됩니다.
  - dataset staging:
    `downloads/RealVul/datasets/juliet-playground/<run-id>/`
  - linevul output:
    `baseline/RealVul/Experiments/LineVul/juliet-playground/<run-id>/`
- 이 스크립트는 원본 `linevul_main.py` 대신 VP-Bench 커스텀 `line_vul.py` 를 사용합니다.
  현재 Stage 07 CSV 는 `processed_func`, `vulnerable_line_numbers`, `dataset_type` 기준으로는
  바로 사용할 수 있지만, 원본 `linevul_main.py` 가 기대하는
  `flaw_line`, `flaw_line_index` 컬럼은 포함하지 않습니다.

## 메모

- `tools/run_pipeline.py stage03-signature`는 `infer-out/report.json`의 모든 이슈를 저장하지 않습니다.
  `bug_type == TAINT_ERROR`이면서 `bug_trace`가 non-empty인 레코드만 signature로 저장합니다.
- `--files` 사용 시 `cwes` / `--all`은 무시됩니다.
- `--all` 사용 시 positional `cwes` 인자는 무시됩니다.
- `.cpp`는 `clang++`, `.c`는 `clang`을 사용합니다.
- `run_pipeline.py stage03 --global-result`를 쓰면 infer 결과 root가
  로컬 `artifacts/infer-results/` 대신 `/data/pattern/result/infer-results/`로 바뀝니다.
- CodeBERT tokenizer 캐시, `--overwrite`, `--old-prefix/--new-prefix`,
  stage별 재실행 패턴과 재현성 옵션은 [`docs/rerun.md`](docs/rerun.md)를 참고하세요.
