# 0003 - Dataset Development Lifecycle and Cycle-Scoped Epics

- Status: accepted
- Date: 2026-03-06

## 배경
작업 단위(에픽/스토리/태스크)는 정리되었지만, 매 사이클에서 어떤 순서와 기준으로 일을 반복할지에 대한 공통 수명주기 규칙이 필요하다.
또한 수명주기 단계(정의/구축/검증/배포/운영)와 에픽을 혼동하면, 에픽이 활동명 중심으로 작성되어 결과물 중심 관리가 약해질 수 있다.

## 결정
팀 표준 수명주기를 아래 5단계로 고정한다.

1. **Scope/Define (정의)**
2. **Build (구현)**
3. **Verify (검증)**
4. **Release (배포)**
5. **Operate/Improve (운영·개선)**

수명주기는 매 사이클마다 반복 적용한다(증분 반복).

추가로, 계획 계층과 에픽 정의 원칙을 아래와 같이 고정한다.
- Theme(상위 목표)는 GitHub **Project**로 관리한다(Theme를 이슈 타입으로 만들지 않음).
- Epic은 "개별 실험 사이클" 단위로 정의한다(성공/실패 포함 결과 확정까지).
- 수명주기 단계명 자체를 에픽으로 사용하지 않는다.
- 각 에픽 내부에서 수명주기 5단계를 Story/Task로 분해한다.

## 단계별 기본 산출물
### 1) Scope/Define
- 대상 범위(CWE, manifest, 규칙 변경) 확정
- `docs/decisions/` 업데이트

### 2) Build
- 추출/가공/자동화 구현 (`experiments/`, `tools/`)

### 3) Verify
- 이번 사이클 시작 시 합의한 완료 조건(입출력 형식/필수 필드/품질 기준) 충족 여부 검증
- 라벨/추출 결과의 샘플 검토 및 재실행 가능성 확인

### 4) Release
- 이번 사이클의 목표 산출물을 확정하고 공유
- 실험 목표에 따라 `manifest.xml`, `source.lst`, `sink.lst` 산출물을 확정
- 버전/변경 이력 기록

### 5) Operate/Improve
- 회고 및 개선 backlog 생성
- 다음 사이클 에픽 초안 작성

## 적용 규칙
### 이슈 생성 순서(강제 운영)
1. Verify 담당 Story를 먼저 생성한다.
2. Release 담당 Story를 먼저 생성한다.
3. Epic 생성 시 두 Story 링크를 필수로 기입한다.
4. Epic/Story/Task 제목은 각각 한줄 카드와 동일하게 작성한다.
5. 필요 시 Verify/Release Story 하위에 Task를 완료조건/산출물 개수에 맞게 분해한다.

- Theme는 GitHub Project 필드/뷰로 관리하고, Epic/Story/Task는 GitHub Issue로 관리한다.
- Epic은 실험 사이클 단위로 작성하며, Verify/Release Story 링크를 포함해 생성하고 성공/실패와 무관하게 결과를 확정해 종료한다.
- Verify의 완료 조건은 사이클 시작 시 명시한다(형식은 JSONL로 고정하지 않음: JSONL/CSV/TSV/기타 가능).
- Release는 도구 승격 여부와 무관하게, 이번 사이클의 목표 산출물 확정(실패 리포트 포함 가능)으로 판단한다.
- 버전 관리는 GitHub Release로 수행하고, Release Note에 기준 커밋 SHA를 기록한다.
- 실패 시에는 본 문서의 "Release 실패 처리 규칙"을 따른다.
- 실패 시 failure report는 `experiments/epicNNN_*/outputs/failure_report.md`에 기록한다(`.json`은 선택).
- Task 완료 시 산출물 경로와 검증 방법을 반드시 기록한다.
- 사이클 종료 시 개선 항목을 다음 사이클 backlog로 이관한다.

## 결과
### 기대 효과
- 반복 가능한 실행 체계 확보
- 에픽 단위 목표와 수명주기 운영 원칙의 역할 분리
- 계획/검증/배포의 일관성 향상

### 비용/트레이드오프
- 초기 계획 문서화 비용 증가
- 사이클 종료 시 회고/정리 오버헤드 발생

## 예시 (권장 형태)
- Theme(Project): `Juliet source/sink 추출 신뢰도 확보`
- Epic(실험): `CWE-476 source/sink 추출 규칙 실험 #03 (성공/실패 결과 확정 포함)`
- 에픽(지양): `검증 단계 수행`

## Release 실패 처리 규칙
1. 실패도 Release로 인정한다.
   - 성공 산출물이 없어도 Epic 종료 가능하되, 실패 리포트는 필수다.

2. 실패 분류를 필수 기록한다.
   - `invalid_hypothesis`: 가설이 데이터/증거로 기각됨
   - `execution_failure`: 실행 환경/코드/의존성 문제로 실험 완료 불가
   - `inconclusive`: 증거 부족 또는 판정 불가

3. 실패 리포트 최소 필수 항목을 기록한다.
   - 실패 분류
   - 원인 요약(1~3줄)
   - 증거 경로(로그/출력 파일)
   - 재현 명령
   - 다음 액션(가설 수정/중단/재실험)

4. 실패 시 Epic 종료 게이트를 적용한다.
   - Verify Story 상태 기록
   - Release Story 완료
   - 실패 리포트 경로 기록

## Story 작성 예시 (Verify / Release)
### Verify Story 예시
- 제목(=한줄 카드): `[Story] CWE-476 실험 #03 Verify`
- 수용 기준(AC):
  - [ ] Given 실험 출력이 준비되었을 때, When 필수 필드/형식을 점검하면, Then 누락/형식 오류가 없다.
  - [ ] Given 샘플 검토 대상이 정의되었을 때, When 표본을 검토하면, Then 허용 기준을 충족한다.
  - [ ] Given 동일 입력/환경이 주어졌을 때, When 재실행하면, Then 동일하거나 허용 범위 내 결과를 재현한다.
- 하위 Task 분해 원칙: AC가 독립 실행 가능하면 AC 1개당 Task 1개로 분해한다.
- 하위 Verify Task 예시(AC 대응):
  - Task V1 (AC1 대응): `출력 형식/필수 필드 검증을 수행한다.`
    - 완료 기준(DoD): 누락 필드 0건, 형식 오류 0건
    - 검증 방법: 검증 스크립트 실행 후 오류 리포트 확인
  - Task V2 (AC2 대응): `샘플 표본 검토를 수행한다.`
    - 완료 기준(DoD): 사전 합의한 표본 수 검토 완료, 허용 기준 미달 항목 목록화
    - 검증 방법: 표본 검토 체크리스트와 결과 파일 비교
  - Task V3 (AC3 대응): `동일 조건 재실행 재현성 검증을 수행한다.`
    - 완료 기준(DoD): 기준 실행과 재실행 결과가 동일 또는 허용 오차 이내
    - 검증 방법: 2회 실행 결과 diff/통계 비교

### Release Story 예시
- 제목(=한줄 카드): `[Story] CWE-476 실험 #03 Release`
- 수용 기준(AC):
  - [ ] Given Verify Story가 완료되었을 때, When 산출물을 정리하면, Then 선택한 Release 유형별 결과가 확정된다.
  - [ ] Given 산출물이 확정되었을 때, When 경로/링크를 기록하면, Then 추적 가능하게 참조할 수 있다.
  - [ ] Given 실험이 실패한 경우, When 실패 리포트를 작성하면, Then 원인/로그/다음 가설이 기록된다.
- 하위 Task 분해 원칙: 선택한 Release 산출물 유형 1개당 Task 1개를 생성하고 Story에 링크한다.
- Release 산출물 Task 예시:
  - `manifest.xml 정리 및 경로 기록`
  - `source.lst 산출 및 경로 기록`
  - `sink.lst 산출 및 경로 기록`
  - `실패 리포트 작성 및 경로 기록 (experiments/epicNNN_*/outputs/failure_report.md, 실패 시)`
