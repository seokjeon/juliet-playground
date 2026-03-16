# Pipeline runbook

파이프라인 운영 문서의 진입점입니다.
빠른 시작은 루트 [`README.md`](../README.md)를 먼저 보세요.

## 문서 맵

- 산출물 구조 / summary JSON / 로그 위치:
  [`artifacts.md`](artifacts.md)
- 재실행 / `--overwrite` / 경로 이식 / 재현성 옵션:
  [`rerun.md`](rerun.md)
- 단계별 세부 규칙:
  `experiments/*/README.md`

## 주요 스크립트와 역할

- `tools/run_pipeline.py`
  - 전체 파이프라인, stage별 실행, `rerun-step07`를 한 곳에서 실행하는 기본 entrypoint
  - 대표 subcommand: `full`, `stage03`, `stage03-signature`, `stage05`, `stage06`, `stage07`, `stage07b`, `rerun-step07`
  - `tools/stage/stage03_infer.py`, `stage05_pair_trace.py`, `stage06_slices.py`, `stage07b_patched_export.py`는 standalone CLI가 아니라 이 entrypoint가 호출하는 내부 모듈입니다.
- `tools/tokenize_slices.py`
  - slice 디렉터리를 독립적으로 토큰화하고 분포 plot을 생성하는 보조 스크립트
  - 메인 파이프라인은 이 스크립트를 직접 호출하지 않고, 내부 유틸리티를 재사용합니다.

## 빠른 이동

- 단일 Infer / Signature 결과 구조:
  [`artifacts.md`](artifacts.md) → `단일 Infer / Signature 산출물`
- 파이프라인 run 디렉터리 구조:
  [`artifacts.md`](artifacts.md) → `파이프라인 run 산출물`
- 대표 명령 모음:
  [`rerun.md`](rerun.md) → `자주 쓰는 명령`
- Step 07 / 07b 재실행:
  [`rerun.md`](rerun.md) → ``run_pipeline.py rerun-step07` 동작 정리`
- tokenizer / overwrite / path rewrite:
  [`rerun.md`](rerun.md) → `운영 메모`

## 참고

- 루트 `README.md`는 입문용 문서입니다.
- 세부 산출물/운영 절차는 이 문서가 아니라 `artifacts.md`, `rerun.md`를 기준으로 봅니다.
