# epic001c_testcase_flow_partition

`manifest_with_comments.xml`의 각 `testcase` 아래에 `<flow type="...">`를 추가하고,
해당 흐름에 속하는 `comment_flaw`, `comment_fix`, `flaw` 태그를 모아 넣습니다.

## 분류 기준
- `comment_flaw`, `comment_fix`
  - 태그의 `function` 속성을 사용
  - `function_names_categorized.jsonl`의 `flow_family`를 이용해 `b2b/b2g/g2b`로 매핑
  - 함수명이 `...B2G1`, `...B2G2`, `...G2B1`, `...G2B2`처럼 끝나면 flow type을 `b2g1`, `b2g2`, `g2b1`, `g2b2`로 세분화
- `flaw`
  - 같은 `file` 안에서 `comment_*` 라인의 함수 분포를 만들고,
  - `flaw.line`과 가장 가까운 라인을 가진 함수를 line 기반으로 추정하여 flow 배정

## 출력
- `outputs/manifest_with_testcase_flows.xml`
  - 기존 구조 + `testcase/flow` 태그 추가
  - flow 안의 각 태그에는 `file` 속성이 추가됨
  - flow에 배정된 `flaw`에는 `inferred_function` 속성이 추가됨
- `outputs/summary.json`

## 실행
```bash
python experiments/epic001c_testcase_flow_partition/scripts/add_flow_tags_to_testcase.py
```
