# Experiments Map

`experiments/`는 취약 trace / 패치 trace 구축을 위한 실험 공간입니다.
이 문서는 실험들의 의미와 연결 관계를 **디렉토리 트리 관점**에서 요약합니다.

## 디렉토리 구조 (의미 포함)

```text
experiments/
├─ README.md                       # 실험 전체 지도
├─ exp001_marker_baseline/         # 주석/마커 기반 baseline 추출
│  ├─ scripts/                     # exp001 전용 실험 스크립트
│  ├─ inputs/                      # manifest, 샘플 목록, 설정
│  ├─ outputs/                     # marker 기반 후보 결과(JSONL)
│  └─ README.md                    # 가설/명령/결과/한계
├─ exp002_ast_trace/               # AST/구문 기반 정밀 추출
│  ├─ scripts/
│  ├─ inputs/                      # exp001 결과 또는 원본 subset
│  ├─ outputs/                     # line 보정/근거 보강 결과
│  └─ README.md
└─ exp003_patch_trace/             # good/bad 대응 기반 patch trace
   ├─ scripts/
   ├─ inputs/                      # exp001/exp002 산출물
   ├─ outputs/                     # vuln trace ↔ patch trace 매핑
   └─ README.md
```

## 연결 방식 (Linear 고정 아님)
- 실험은 기본적으로 **독립 실행 가능**해야 합니다.
- 다만 필요 시 다른 실험의 `outputs/`를 `inputs/`로 참조할 수 있습니다.
- 즉, `exp001 → exp002 → exp003`만 허용하는 선형 파이프라인이 아니라,
  목적에 따라 분기/병합 가능한 트리형 실험 맵을 지향합니다.

## 공통 기록 규칙
각 `expNNN_*/README.md`에는 아래를 최소 기록합니다.
- 실험 질문(무엇을 검증하는지)
- 실행 명령(재현 가능 형태)
- 입력/출력 경로
- 핵심 결과와 실패 원인

## 공통 출력 키 (권장)
`file`, `cwe`, `kind`, `line`, `evidence`
