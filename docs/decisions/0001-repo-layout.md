# 0001 - Repository Layout for Trace Dataset Work

- Status: accepted
- Date: 2026-03-06

## Decision
실험(`experiments`), 공용도구(`tools`), 데이터(`data`), 규칙/결정(`docs`)을 분리한다.

데이터 폴더 운영은 아래와 같이 고정한다.
- `data/final/`: 최신 확정본 산출물만 저장한다.
  - `manifest.xml`
  - `source.lst`
  - `sink.lst`
- `data/artifacts/`: `tools/` 실행 시 생성되는 부산물(로그/검증 출력/중간 산출물)을 저장한다.
- `data/interim/`과 `data/manifests/`는 사용하지 않으며 저장소에서 제거한다.

실험 결과물은 `data/`가 아니라 각 실험 폴더에 저장한다.
- `experiments/epicNNN_*/outputs/`: 실험 실행 결과(작은 실험, 릴리스 미반영 실험 포함) 보관 위치

## Rationale
- 실험 시행착오와 재사용 코드를 구분
- 실험 결과(`experiments/.../outputs`)와 운영 부산물(`data/artifacts`)의 책임 분리
- 최신 확정본(`data/final`)과 작업 중 출력의 경계 명확화
- 협업 시 재현성 확보
