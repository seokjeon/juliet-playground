## 요약
- 무엇을 변경했는지 간단히 작성

## 링크된 이슈
- Epic: #
- Story: #
- Task: #

## 생명 주기 현황
- [ ] Build
- [ ] Verify
- [ ] Release
- [ ] Improve

## 산출물
- 산출물 경로:
  - `experiments/epicNNN_*/outputs/...`
  - `data/artifacts/...` (해당 시)
  - `data/final/...` (해당 시)

## 검증
- 검증 방법(명령/절차):
- 검증 결과 요약:

## Release 체크 (해당 시)
- [ ] `manifest.xml` 반영/갱신
- [ ] `source.lst` 반영/갱신
- [ ] `sink.lst` 반영/갱신
- [ ] GitHub Release Note에 기준 커밋 SHA 기록

## 실패 실험 체크 (해당 시)
- [ ] 실패 분류 기록 (`invalid_hypothesis` | `execution_failure` | `inconclusive`)
- [ ] 실패 리포트 작성: `experiments/epicNNN_*/outputs/failure_report.md`
- [ ] (선택) 구조화 리포트 작성: `experiments/epicNNN_*/outputs/failure_report.json`

## 체크리스트
- [ ] 이 PR 제목은 작업 내용을 명확히 설명한다.
- [ ] 관련 이슈(Epic/Story/Task) 링크를 모두 기입했다.
- [ ] 산출물 경로와 검증 방법을 기입했다.
- [ ] 문서/템플릿 변경 시 ADR/README와 일치하도록 반영했다.
