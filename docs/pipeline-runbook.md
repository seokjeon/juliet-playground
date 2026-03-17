# Pipeline runbook

파이프라인 운영 문서의 진입점입니다.
빠른 시작은 루트 [`README.md`](../README.md)를 먼저 보세요.

## 문서 맵

- 산출물 구조 / summary JSON:
  [`artifacts.md`](artifacts.md)
- 재실행 / `--overwrite` / 경로 이식 / 재현성 옵션:
  [`rerun.md`](rerun.md)
- 현재 구현 단계 계약 / 테스트 기준 (`tools/run_pipeline.py` 기준):
  [`stage-contracts.md`](stage-contracts.md)
- 실험 단계 메모(주로 01/02a/02b/04):
  `experiments/*/README.md`

## 주요 스크립트와 역할

- `tools/run_pipeline.py`
  - 전체 파이프라인을 실행하는 기본 entrypoint
  - 현재 공식 CLI는 `full`만 지원합니다.
- `tools/stage/*.py`
  - `run_pipeline.py full`이 호출하는 importable stage 구현
  - stage 단위 재실행/실험은 이 모듈이나 `experiments/*/scripts/*.py`를 직접 사용합니다.
  - 현재 동작의 source of truth는 CLI help와 이 모듈들, 그리고 [`stage-contracts.md`](stage-contracts.md)입니다.
- `tools/compare-artifacts.py`
  - pipeline run 디렉터리 또는 dataset export 디렉터리의 before/after 차이를 요약 비교하는 CLI

## 빠른 이동

- 현재 단계 계약:
  [`stage-contracts.md`](stage-contracts.md)
- 단일 Infer / Signature 결과 구조:
  [`artifacts.md`](artifacts.md) → `단일 Infer / Signature 산출물`
- 파이프라인 run 디렉터리 구조:
  [`artifacts.md`](artifacts.md) → `파이프라인 run 산출물`
- 대표 명령 모음:
  [`rerun.md`](rerun.md) → `자주 쓰는 명령`
- Step 07 / 07b 재실행:
  [`rerun.md`](rerun.md) → `Step 07 / 07b 직접 재실행 메모`
- tokenizer / overwrite / path rewrite:
  [`rerun.md`](rerun.md) → `운영 메모`

## 참고

- 루트 `README.md`는 입문용 문서입니다.
- 현재 코드 기준 단계 계약은 `stage-contracts.md`를 우선해서 봅니다.
- `experiments/*/README.md`는 주로 01/02a/02b/04의 실험/보조 스크립트 문맥을 설명합니다.
- 세부 산출물/운영 절차는 이 문서가 아니라 `artifacts.md`, `rerun.md`를 기준으로 봅니다.
