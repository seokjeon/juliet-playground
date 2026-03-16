# Re-run and operations guide

재실행, 자주 쓰는 명령, 운영상 주의사항을 정리한 문서입니다.
산출물 구조는 [`artifacts.md`](artifacts.md), 전체 문서 맵은 [`pipeline-runbook.md`](pipeline-runbook.md)를 참고하세요.

## 자주 쓰는 명령

### 1) Infer / Signature

```bash
# Infer + signature만 빠르게 실행
python tools/run_pipeline.py stage03 78

# 특정 파일(해당 flow variant 그룹)만 실행
python tools/run_pipeline.py stage03 --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c

# 기존 infer 결과에서 signature만 생성
python tools/run_pipeline.py stage03-signature --input-dir artifacts/infer-results/infer-2026.03.08-18:04:18
```

### 2) 전체 파이프라인

```bash
# CWE 여러 개
python tools/run_pipeline.py full 78 89

# 전체 CWE
python tools/run_pipeline.py full --all

# 재현성 옵션 예시
python tools/run_pipeline.py full 78 \
  --run-id run-my-fixed-id \
  --pair-split-seed 1234 \
  --pair-train-ratio 0.8 \
  --dedup-mode row
```

### 3) Pair / Slice만 따로 실행

```bash
# strict trace 결과만으로 paired trace dataset 생성
python tools/run_pipeline.py stage05 \
  --trace-jsonl artifacts/pipeline-runs/run-2026.03.09-22:18:32/04_trace_flow/trace_flow_match_strict.jsonl \
  --output-dir /tmp/paired-trace-ds

# 옵션 없이 실행하면 최신 pipeline run의 strict trace를 찾아
# 같은 run 아래 05_pair_trace_ds/ 로 출력
python tools/run_pipeline.py stage05

# paired_signatures로부터 slice 생성
python tools/run_pipeline.py stage06 \
  --signature-db-dir artifacts/pipeline-runs/run-2026.03.09-22:18:32/05_pair_trace_ds/paired_signatures \
  --output-dir /tmp/paired-slices

# 옵션 없이 실행하면 최신 pipeline run의 paired_signatures를 찾아
# 같은 run 아래 06_slices/ 로 출력
python tools/run_pipeline.py stage06
```

### 4) Patched counterpart export / Step 07 재실행

```bash
RUN_DIR=artifacts/pipeline-runs/run-2026.03.10-00:49:21

# 기존 train_val 샘플들에 대응하는 patched counterpart 평가셋 생성
python tools/run_pipeline.py stage07b \
  --run-dir "$RUN_DIR"

# 기존 run의 Step 07 + 07b를 새 timestamped 폴더로 다시 생성 (기본)
python tools/run_pipeline.py rerun-step07 \
  --run-dir "$RUN_DIR"

# Step 07만 다시 생성
python tools/run_pipeline.py rerun-step07 \
  --run-dir "$RUN_DIR" \
  --only-07

# Step 07b만 다시 생성
python tools/run_pipeline.py rerun-step07 \
  --run-dir "$RUN_DIR" \
  --overwrite \
  --only-07b
```

## 운영 메모

### `stage03-signature`의 추출 대상

- `infer-out/report.json`의 모든 이슈를 저장하지 않습니다.
- 현재 구현은 `bug_type == TAINT_ERROR`만 대상으로 하며,
  그중 `bug_trace`가 empty가 아닌 레코드만 `non_empty/`에 저장합니다.

### Step 07 / 07b의 tokenizer 의존성

- `tools/run_pipeline.py stage07`, `tools/run_pipeline.py stage07b`,
  `tools/run_pipeline.py rerun-step07`는 내부적으로
  `microsoft/codebert-base` tokenizer를 로드합니다.
- 먼저 로컬 캐시를 찾고, 캐시가 없으면 원격 다운로드를 시도합니다.
- 네트워크가 제한된 환경에서는 **미리 모델 캐시를 준비해 두는 것**이 안전합니다.

### `--overwrite`가 필요한 경우

다음 스크립트는 출력 디렉터리/파일이 이미 존재하면 기본적으로 실패합니다.

- `tools/run_pipeline.py stage05`
- `tools/run_pipeline.py stage06`
- `tools/run_pipeline.py stage07b`
- `tools/run_pipeline.py rerun-step07` (`--output-dir` 또는 대상 경로가 이미 있는 경우)

재실행 시 기존 산출물을 교체하려면 `--overwrite`를 명시하세요.

### 경로를 옮긴 뒤 재사용할 때

signature의 `bug_trace[].filename`은 원래 경로를 포함할 수 있습니다.
아티팩트를 다른 머신/다른 루트 경로로 옮긴 뒤 slice를 다시 만들면
원본 경로를 못 찾아 실패할 수 있습니다.

이 경우 아래 옵션을 사용합니다.

- `tools/run_pipeline.py stage06 --old-prefix ... --new-prefix ...`
- `tools/run_pipeline.py stage07b --old-prefix ... --new-prefix ...`
- `tools/run_pipeline.py rerun-step07 --old-prefix ... --new-prefix ...` (`--only-07b` 포함)

### 재현성 옵션

- `--run-id`: pipeline run 디렉터리 이름을 고정
- `--pair-split-seed`: pair-level train/test split 난수 시드
- `--pair-train-ratio`: train_val 비율 (`0 < ratio < 1`)
- `--dedup-mode`:
  - `row`: normalized slice 기준 row-level dedup 적용
  - `none`: dedup 비활성화

현재 구현에서 `row` 모드는
`md5("".join(normalized_code.split()))` 기준으로 해시를 만들고,
중복 또는 label collision이 발생한 pair를 걸러냅니다.

## `run_pipeline.py rerun-step07` 동작 정리

- 기본 모드:
  - `<run-dir>/07_dataset_export_<YYYYMMDD_HHMMSS>/`를 새로 만듭니다.
  - Step 07과 07b를 함께 다시 생성합니다.
- `--only-07`:
  - Step 07만 다시 생성합니다.
- `--only-07b`:
  - 기본적으로 기존 `<run-dir>/07_dataset_export/`를 사용합니다.
  - 새 Step 07 결과에 붙이려면 `--output-dir`로 대상 export 디렉터리를 직접 지정해야 합니다.

07b 재실행 시에는 추가로 아래 suffixed 산출물이 생길 수 있습니다.

- `05_pair_trace_ds/train_patched_counterparts_pairs_<suffix>.jsonl`
- `05_pair_trace_ds/train_patched_counterparts_selection_summary_<suffix>.json`
- `05_pair_trace_ds/train_patched_counterparts_signatures_<suffix>/`
- `06_slices/train_patched_counterparts_<suffix>/`
- `<output-dir>/rerun_step07_metadata.json`
