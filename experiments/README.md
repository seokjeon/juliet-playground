# Experiments Map

`experiments/`는 Juliet 기반 데이터셋 구축 실험 공간입니다.
현재는 **첫 번째 실험 사이클(epic001)** 만 운영합니다.

## 디렉토리 구조

```text
experiments/
├─ README.md
└─ epic001_good_bad_marker/
   ├─ scripts/      # 추출/검증 스크립트
   ├─ inputs/       # 실행 입력(설정, 대상 목록 등)
   ├─ outputs/      # 실험 출력(XML, 검증 리포트)
   └─ README.md     # 가설/규칙/실행/검증/산출물 기록
```

## epic001 목표
- `/* ... FLAW ... */` / `/* FIX ... */` 마커 기반으로 good/bad 라인을 1차 추출
- source/sink 분류는 제외하고, line 단위 추출 정확도를 먼저 검증
- 결과는 `good_bad_lines.xml`로 확정

## 공통 기록 규칙
각 `experiments/epicNNN_*/README.md`에는 아래를 최소 기록합니다.
- 실험 질문(가설)
- 실행 명령(재현 가능 형태)
- 입력/출력 경로
- 검증 방법과 결과
- 실패 시 리포트 경로
