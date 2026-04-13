# juliet-playground

Juliet C/C++ 테스트 스위트에 대해 Infer를 실행하고, signature를 추출/필터링하고,
paired trace → slice → dataset export까지 이어지는 실험 저장소입니다.

## 문서 안내

- 운영 문서 인덱스:
  [`docs/pipeline-runbook.md`](docs/pipeline-runbook.md)
- 산출물 구조 / summary JSON:
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

현재 공식 CLI는 `python tools/run_pipeline.py full ...` 입니다.
stage 단위 재실행이나 실험은 `tools/stage/*.py` 의 importable 함수나
별도 스크립트(`tools/retrace_strict_trace.py`, `tools/run_linevul.py` 등)를 사용합니다.

### 2) 통합 파이프라인 실행

```bash
source .venv/bin/activate && python tools/run_pipeline.py full 78
```

기본값은 trace-first dataset export입니다.
pair 기반 기존 흐름을 유지하려면:

```bash
source .venv/bin/activate && python tools/run_pipeline.py full 78 --enable-pair
```

전체 CWE에 대해 실행하려면:

```bash
source .venv/bin/activate && python tools/run_pipeline.py full --all
```

기본 run-id 규칙은 `run-YYYY.MM.DD-HH:MM:SS`이며,
실제 경로는 `artifacts/pipeline-runs/run-.../` 입니다.

### 3) 외부 프로젝트 trace fast path 실행

Juliet 전체 파이프라인 대신 외부 프로젝트에 대해
`Infer -> manual-line trace filter -> trace slices -> test-only dataset export`
만 빠르게 실행하려면 아래 스크립트를 사용합니다.

```bash
source .venv/bin/activate

python tools/run_external_trace_pipeline.py \
  --source-root /path/to/project/raw_code \
  --build-targets /path/to/build_targets.csv \
  --manual-line-truth /path/to/manual_line_truth.csv \
  --run-id myproj-test \
  --project-name myproj
```

- 필수 인자
  - `--source-root`: 외부 프로젝트 소스 루트
  - `--build-targets`: testcase별 Infer 빌드 명령 CSV
  - `--manual-line-truth`: 수동 취약 라인 truth CSV
- 선택 인자
  - `--pulse-taint-config`: 기본값 `config/pulse-taint-config.json`
  - `--output-root`: 기본값 `artifacts/external-runs`
  - `--run-id`: 기본값 `run-YYYY.MM.DD-HH:MM:SS`
  - `--project-name`: 기본적으로 `source-root` 이름을 사용합니다.
    `source-root` 이름이 `raw_code` 이면 부모 디렉터리 이름을 사용합니다.

`build_targets.csv` 형식:

```csv
testcase_key,workdir,build_command
case1,/abs/path/to/project,"make clean && make -j1"
```

`manual_line_truth.csv` 형식:

```csv
testcase_key,file_path,line_number,label,note
case1,/abs/path/to/project/src/foo.c,"1187,609,486",1,confirmed vulnerable line
```

- `line_number` 는 쉼표/공백 구분 다 허용합니다.
- `label` 은 `1`, `true`, `yes`, `vuln`, `vulnerable` 등을 취약으로 인식합니다.
- 성공 시 대표 출력은
  `artifacts/external-runs/<run-id>/07_dataset_export/Real_Vul_data.csv`,
  `artifacts/external-runs/<run-id>/07_dataset_export/trace_row_manifest.jsonl`
  입니다.

### 4) case-managed external run 실행

`cases/<project>__<CVE>/<track>/` 구조를 쓰는 case-managed workflow에서는
`tools/run_case.py`가 `runs/<run>/` bootstrap과 실행을 함께 담당합니다.

```bash
source .venv/bin/activate

python tools/run_case.py \
  --case cases/demo-project__CVE-2099-0001 \
  --track vulnerable \
  --run run-001 \
  --infer-jobs 8
```

- `--run`은 명시적으로 넘깁니다. 예: `run-001`
- `--infer-jobs`는 `infer run -j N`의 N을 제어합니다. 기본값은 `1`입니다.
- `--infer-jobs`는 Infer 내부 병렬도만 바꾸며, `build_targets.csv` 안의 build command
  자체 병렬도(예: `make -jN`)는 변경하지 않습니다.
- `runs/<run>/`가 없으면 자동 생성합니다.
- canonical 입력은 `runs/inputs/{build_targets.csv,manual_line_truth.csv,pulse-taint-config.json}`입니다.
- 실행 시마다 `runs/inputs/`의 입력 3개를 `runs/<run>/`로 **copy**해 snapshot을 만들고 그 복사본으로 실행합니다.
- 실제 파이프라인 산출물은 `runs/<run>/outputs/` 아래에 직접 저장됩니다.
- 실행이 중간에 실패해도 partial output은 `runs/<run>/outputs/` 아래에 남습니다.

## 파이프라인 개요

`tools/run_pipeline.py full`은 아래 순서로 실행됩니다.

- 기본 trace-first 모드:
  1. `01_manifest`
  2. `02b_flow`
  3. `02b_flow/epic002`
  4. `02a_taint`
  5. `03_infer-results`, `03_signatures`
  6. `04_trace_flow`
  7. `05_trace_ds`
  8. `06_trace_slices`
  9. `07_dataset_export`
  10. `07_dataset_export/vuln_patch/`
- `--enable-pair` 사용 시:
  1. `01_manifest`
  2. `02b_flow`
  3. `02b_flow/epic002`
  4. `02a_taint`
  5. `03_infer-results`, `03_signatures`
  6. `04_trace_flow`
  7. `05_pair_trace_ds`
  8. `06_slices`
  9. `07_dataset_export`
  10. `07_dataset_export/train_patched_counterparts_*`

Stage 02a는 기본적으로 `02b_flow/epic002/source_sink_classified.xml` 을 입력으로 사용합니다.

### Flow XML note

- Stage 01 manifest의 `<comment_flaw>` / `<comment_fix>` 는 Stage 02b flow XML에서 각각
  `<flaw>` / `<fix>` 로 정규화됩니다.
- Stage 02b flow XML의 함수명 필드는 `function` 하나로 통일됩니다.
- 같은 `(file, line)` 에서 원래 manifest의 `<flaw>` 와 comment 유래 `<flaw>` 가 겹치면,
  `origin="manifest_flaw"` 인 원본 `flaw` 를 남기고 comment 유래 `flaw` 는 제거합니다.
- 같은 `(file, line)` 에 원래 manifest 유래 `flaw` 가 여러 개 있을 때, file명의 CWE prefix와
  `name` 의 CWE prefix가 모두 비교 가능하고 그중 일치하는 항목이 있으면 불일치 항목은 flow에서 제거합니다.
- Stage 02b는 기본적으로 dedup 후 child가 1개뿐인 `<flow>` 는 생성하지 않습니다.
  이전 동작이 필요하면 Python API의 `prune_single_child_flows=False` 를 사용합니다.
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
        ├── 05_trace_ds/            # 기본 trace-first
        ├── 05_pair_trace_ds/       # --enable-pair 시
        ├── 06_trace_slices/        # 기본 trace-first
        ├── 06_slices/              # --enable-pair 시
        ├── 07_dataset_export/
        └── ...
```

전체 산출물 트리와 각 파일 의미는
[`docs/artifacts.md`](docs/artifacts.md)를 참고하세요.

## 대표 명령어

```bash
# 통합 파이프라인
python tools/run_pipeline.py full 78 89

# 특정 파일(해당 flow variant 그룹)만 실행
python tools/run_pipeline.py full \
  --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c

# pair 기반 기존 흐름으로 실행
python tools/run_pipeline.py full 78 --enable-pair

# 기존 run 기준으로 strict trace만 다시 생성
python tools/retrace_strict_trace.py run-2026.03.17-15:11:12

# 최신 pipeline run의 Real_Vul_data.csv 를 VP-Bench linevul 컨테이너로 넘겨
# prepare -> train -> test 실행
# vuln_patch/Real_Vul_data.csv 가 있으면 같은 best_model 로 추가 prepare -> test 실행
python tools/run_linevul.py

# VP-Bench root 가 기본 위치가 아니면 명시
python tools/run_linevul.py \
  --vpbench-root /path/to/VP-Bench

# 특정 run 대상 dry-run
python tools/run_linevul.py \
  --run-dir artifacts/pipeline-runs/run-2026.03.17-11:28:48 \
  --dry-run

# Extended RealVul 테스트셋과 fine-tuned LineVul 모델을 다운로드해
# fine-tuned test -> raw baseline test -> combined t-SNE 까지 실행
python tools/run_linevul.py \
  --overwrite \
  --extended-realvul

# 최신 pipeline run의 Real_Vul_data.csv 를 VP-Bench pdbert 컨테이너로 넘겨
# primary dataset 에 대해 prepare -> train -> test -> analyze 실행
# vuln_patch/Real_Vul_data.csv 가 있으면 --raw-model-dir 가 필요하고,
# 학습된 primary model 로 prepare -> test -> analyze,
# raw baseline 으로 raw_test -> raw_analyze 를 추가 실행
python tools/run_pdbert.py \
  --raw-model-dir /home/sojeon/Desktop/VP-Bench/downloads/PDBERT/data/models/pdbert-base

# VP-Bench root 가 기본 위치가 아니면 명시
python tools/run_pdbert.py \
  --vpbench-root /path/to/VP-Bench \
  --raw-model-dir /path/to/VP-Bench/downloads/PDBERT/data/models/pdbert-base

# 특정 run 대상 dry-run
python tools/run_pdbert.py \
  --run-dir artifacts/pipeline-runs/run-2026.03.18-04:05:48 \
  --raw-model-dir /home/sojeon/Desktop/VP-Bench/downloads/PDBERT/data/models/pdbert-base \
  --dry-run

# Extended RealVul 테스트셋과 fine-tuned PDBERT 모델을 다운로드해
# fine-tuned test/analyze + raw baseline test/analyze + combined t-SNE 까지 실행
python tools/run_pdbert.py \
  --overwrite \
  --extended-realvul

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
- 같은 run에 `07_dataset_export/vuln_patch/Real_Vul_data.csv` 가 있으면
  primary dataset 학습이 끝난 뒤 같은 `best_model` 을 재사용해서
  vuln_patch dataset 에 대해 `prepare -> test` 를 추가로 실행합니다.
- 기본 대상 경로:
  - VP-Bench root: `/home/sojeon/Desktop/VP-Bench`
  - container: `linevul`
- VP-Bench가 다른 위치에 있으면 `--vpbench-root /path/to/VP-Bench` 로 지정할 수 있습니다.
- 결과는 기본적으로 VP-Bench 쪽에만 저장됩니다.
  - dataset staging:
    `downloads/RealVul/datasets/juliet-playground/<run-id>/`
  - linevul output:
    `baseline/RealVul/Experiments/LineVul/juliet-playground/<run-id>/`
  - vuln_patch staging/output:
    `downloads/RealVul/datasets/juliet-playground/<run-id>/vuln_patch/`
    `baseline/RealVul/Experiments/LineVul/juliet-playground/<run-id>/vuln_patch/`
- 이 스크립트는 원본 `linevul_main.py` 대신 VP-Bench 커스텀 `line_vul.py` 를 사용합니다.
  현재 Stage 07 CSV 는 `processed_func`, `vulnerable_line_numbers`, `dataset_type` 기준으로는
  바로 사용할 수 있지만, 원본 `linevul_main.py` 가 기대하는
  `flaw_line`, `flaw_line_index` 컬럼은 포함하지 않습니다.
- `--extended-realvul` 을 사용하면 pipeline run 입력 대신
  VP-Bench release의 Extended RealVul 테스트 CSV와 LineVul fine-tuned 모델을 내려받아
  fine-tuned test, raw baseline test, combined t-SNE 생성만 수행합니다.

## PDBERT 연동 메모

- `tools/run_pdbert.py` 는 Stage 07의 `Real_Vul_data.csv` 를 읽어
  VP-Bench의 `pdbert` 컨테이너에서
  `prepare_dataset.py` -> `train_eval_from_config.py` -> `analyze_prediction.py` 를 실행합니다.
- 기본적으로 `processed_func` 컬럼을 직접 사용하므로, Stage 07 CSV를 그대로 넘길 수 있습니다.
- 같은 run에 `07_dataset_export/vuln_patch/Real_Vul_data.csv` 가 있으면
  `--raw-model-dir` 가 필수입니다.
- `--raw-model-dir` 는 두 형식을 받습니다.
  - AllenNLP archive dir: `config.json`, `model.tar.gz`
  - pretrained backbone dir: `config.json`, `pytorch_model.bin`, tokenizer 자산
- vuln_patch 가 있을 때는 다음이 추가됩니다.
  - 학습된 primary `model.tar.gz` / `config.json` 을 재사용해
    vuln_patch dataset 에 대해 `prepare -> test -> analyze`
  - `--raw-model-dir` 를 `raw_model_eval/` 로 준비해
    raw baseline 에 대해 `raw_test -> raw_analyze`
- pretrained backbone dir 를 넘기면 raw baseline 의미는
  `pretrained encoder + 랜덤 초기화 downstream classifier head` 입니다.
  즉 raw baseline 은 fine-tuning 없이 vuln_patch 에 대해서만 평가됩니다.
- 기본 대상 경로:
  - VP-Bench root: `/home/sojeon/Desktop/VP-Bench`
  - container: `pdbert`
- VP-Bench가 다른 위치에 있으면 `--vpbench-root /path/to/VP-Bench` 로 지정할 수 있습니다.
- 결과는 기본적으로 VP-Bench 쪽에 저장됩니다.
  - primary dataset staging:
    `downloads/PDBERT/data/datasets/extrinsic/vul_detect/juliet-playground/<run-id>/primary/vpbench/Real_Vul/`
  - primary model/output:
    `downloads/PDBERT/data/models/extrinsic/vul_detect/juliet-playground/<run-id>/primary/`
  - vuln_patch dataset staging:
    `downloads/PDBERT/data/datasets/extrinsic/vul_detect/juliet-playground/<run-id>/vuln_patch/realvul_test/Real_Vul/`
  - vuln_patch model/output:
    `downloads/PDBERT/data/models/extrinsic/vul_detect/juliet-playground/<run-id>/vuln_patch/`
  - raw baseline output:
    `downloads/PDBERT/data/models/extrinsic/vul_detect/juliet-playground/<run-id>/vuln_patch/raw_model_eval/`
- feature export / t-SNE 산출물은 primary analyze, vuln_patch analyze,
  raw baseline analyze 에서 각각 생성됩니다.
- `--extended-realvul` 을 사용하면 pipeline run 입력 대신
  VP-Bench release의 Extended RealVul 테스트 CSV와 PDBERT fine-tuned 모델을 내려받아
  fine-tuned test/analyze, raw baseline test/analyze, combined t-SNE 생성만 수행합니다.
  이때 기본 `--raw-model-dir` 는
  `../VP-Bench/downloads/PDBERT/data/models/pdbert-base` 입니다.

## 메모

- `tools/run_pipeline.py` 의 현재 공식 subcommand는 `full` 뿐입니다.
- `--files` 사용 시 `cwes` / `--all`은 무시됩니다.
- `--all` 사용 시 positional `cwes` 인자는 무시됩니다.
- `.cpp`는 `clang++`, `.c`는 `clang`을 사용합니다.
- CodeBERT tokenizer 캐시, `--overwrite`, `--old-prefix/--new-prefix`,
  stage별 재실행 패턴과 재현성 옵션은 [`docs/rerun.md`](docs/rerun.md)를 참고하세요.
