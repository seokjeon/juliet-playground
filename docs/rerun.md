# Re-run and operations guide

재실행, 자주 쓰는 명령, 운영상 주의사항을 정리한 문서입니다.
산출물 구조는 [`artifacts.md`](artifacts.md), 전체 문서 맵은 [`pipeline-runbook.md`](pipeline-runbook.md), 현재 단계 계약은 [`stage-contracts.md`](stage-contracts.md)를 참고하세요.
아래 예시는 현재 `tools/run_pipeline.py full --help` / `tools/compare-artifacts.py --help` 기준입니다.

## 자주 쓰는 명령

### 1) 전체 파이프라인

```bash
# CWE 여러 개
python tools/run_pipeline.py full 78 89

# 전체 CWE
python tools/run_pipeline.py full --all

# pair 기반 기존 흐름으로 실행
python tools/run_pipeline.py full 78 \
  --enable-pair

# 재현성 옵션 예시
python tools/run_pipeline.py full 78 \
  --run-id run-my-fixed-id \
  --pair-split-seed 1234 \
  --pair-train-ratio 0.8
```

### 2) 산출물 비교

```bash
# 두 pipeline run 비교
python tools/compare-artifacts.py \
  artifacts/pipeline-runs/run-before \
  artifacts/pipeline-runs/run-after

# 두 dataset export 디렉터리만 비교
python tools/compare-artifacts.py \
  artifacts/pipeline-runs/run-before/07_dataset_export \
  artifacts/pipeline-runs/run-after/07_dataset_export
```

### 3) case-managed external run bootstrap + 실행

```bash
python tools/run_case.py \
  --case cases/demo-project__CVE-2099-0001 \
  --track vulnerable \
  --run run-001 \
  --infer-jobs 8
```

- `runs/run-001/`가 없으면 자동 생성합니다.
- canonical 입력은 `runs/inputs/` 아래에 둡니다.
- `--infer-jobs`는 `infer run -j N`의 N을 제어하며 기본값은 `1`입니다.
- 이 옵션은 Infer 내부 병렬도만 바꾸고, `build_targets.csv` 안의 build command 병렬도는
  그대로 둡니다.
- 실행 시마다 `runs/inputs/`의 입력 3개를 `runs/run-001/`로 copy한 뒤 그 복사본으로 실행합니다.
- 실제 산출물과 partial output은 항상 `runs/run-001/outputs/` 아래에 직접 저장됩니다.

## 운영 메모

### Case-managed final trace 운영 규칙

- `cases/<project>__<CVE>/<track>/trace_output/Real_Vul_data.csv`는 사람이 관리하는 최종 산출물입니다.
- 이 CSV는 단일 rerun export일 수도 있고, 여러 evidence run을 손으로 stitch한 결과일 수도 있습니다.
- 여러 run을 합쳐 최종 row를 만들었다면 `trace_output/selected_runs/`에 실제 사용한 `runs/run-###/` symlink를 모두 남깁니다.
- 수작업 stitched row가 단일 source signature로 대표되지 않으면 `source_signature_path`는 빈칸으로 두고, 근거는 `selected_runs/`와 track `WORKLOG.md`로 관리합니다.
- `project` 값은 실제 외부 프로젝트 이름으로 통일하고, `inputs` 같은 경로 유래 placeholder는 최종 CSV에 남기지 않는 것을 기본으로 합니다.

### Step 07 / 07b의 tokenizer 의존성

- dataset export 단계는 내부적으로 `microsoft/codebert-base` tokenizer를 로드합니다.
- 먼저 로컬 캐시를 찾고, 캐시가 없으면 원격 다운로드를 시도합니다.
- 네트워크가 제한된 환경에서는 **미리 모델 캐시를 준비해 두는 것**이 안전합니다.

### 재현성 옵션

- `--run-id`: pipeline run 디렉터리 이름을 고정
- `--pair-split-seed`: pair-level train/test split 난수 시드
- `--pair-train-ratio`: train_val 비율 (`0 < ratio < 1`)
- `tools/run_pipeline.py full` 은 dataset export에서 row-level dedup을 고정 사용합니다.

현재 구현에서 row-level dedup은
`md5("".join(normalized_code.split()))` 기준으로 해시를 만들고,
중복 또는 label collision이 발생한 pair를 걸러냅니다.

## Stage 단위 재실행 메모

- `tools/run_pipeline.py`는 이제 `full`만 공식 지원합니다.
- stage 단위 재실행이 필요하면 `tools/stage/*.py`의 importable 함수나
  `experiments/*/scripts/*.py` wrapper를 사용하세요.
- Step 07b는 표준 pipeline run layout(`run_dir/05_pair_trace_ds`, `run_dir/06_slices`, `run_dir/07_dataset_export`)을 전제로 동작합니다.

### Strict trace만 다시 만들기 (Infer 재실행 없이)

- 기존 run을 **read-only**로 두고, `01_manifest` + 기존 `03_signatures/non_empty`를 재사용해
  새 `02b_flow` / `04_trace_flow` 산출물을 만들 수 있습니다.
- 기본 출력 디렉터리는 source run 옆의 `retrace-<source-run-name>/` 입니다.
- v1 범위는 **02b + 04만 재생성**입니다.

```bash
python tools/retrace_strict_trace.py run-2026.03.17-15:11:12
```

예시 출력:

```text
artifacts/pipeline-runs/retrace-run-2026.03.17-15:11:12/
├── 02b_flow/
├── 04_trace_flow/
└── retrace_summary.json
```

유용한 옵션:

```bash
# pipeline root를 명시적으로 지정
python tools/retrace_strict_trace.py run-2026.03.17-15:11:12 \
  --pipeline-root artifacts/pipeline-runs

# 출력 디렉터리 이름을 바꾸기
python tools/retrace_strict_trace.py run-2026.03.17-15:11:12 \
  --output-name retrace-run-2026.03.17-15:11:12-fixed

# 기존 retrace 출력이 있으면 덮어쓰기
python tools/retrace_strict_trace.py run-2026.03.17-15:11:12 \
  --overwrite

```
