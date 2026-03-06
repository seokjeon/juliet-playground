# Labeling Rules

## Scope
이 문서는 Juliet C/C++ 테스트케이스에서 source/sink/patch 후보를 라벨링할 때의 기준을 정의합니다.

## Core Labels
- `source`: 취약 데이터가 생성/유입되는 지점
- `sink`: 취약 데이터가 실제로 위험하게 사용되는 지점
- `patch`: 취약 흐름을 완화/차단하는 수정(검증/예외처리) 지점

## Line Number Policy
- 기본 line 번호는 **실제 코드 라인(1-based)** 기준.
- 주석 기반 탐지 시:
  1) 마커 주석 라인 기록 가능
  2) 최종 `line` 필드는 다음 실행 코드 라인으로 보정

## Evidence Policy
- `evidence`에는 해당 라벨의 근거가 되는 주석/코드 일부를 저장.
- 너무 긴 문자열은 핵심 구문만 남겨 축약 가능.

## Output Keys (Required)
`file`, `cwe`, `kind`, `line`, `evidence`

## Open Questions
- dataflow 기반 source-sink pairing 규칙 고도화
- good/bad 함수 경계에서 patch trace 연결 정책
