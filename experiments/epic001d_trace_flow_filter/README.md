# epic001d_trace_flow_filter

`epic001c`에서 생성한 `testcase/flow` 태그를 기준으로,
시그니처 추출 trace(JSON)가 어떤 flow(b2b, b2g, b2g1, g2b2 ...)를 실제로 지나가는지 필터링합니다.

## 입력
- Flow XML: `experiments/epic001c_testcase_flow_partition/outputs/manifest_with_testcase_flows.xml`
- Signatures: 대상 `non_empty` signature 디렉터리를 직접 지정

## 매칭 규칙
1. trace 디렉토리명(`CWE78_12-...`)을 testcase key로 사용
2. flow 태그의 `(file,line)` 포인트와 trace의 `bug_trace[].(filename,line_number)`(+ primary `file,line`)를 비교
3. flow별로 `hit_points`, `coverage` 계산
4. 최고 점수 flow를 `best_flow_type`으로 선택
   - strict_match 우선
   - 그다음 hit_points/coverage 순

## 출력
- `outputs/trace_flow_match_all.jsonl`: 전체 trace 결과
- `outputs/trace_flow_match_strict.jsonl`: flow 포인트를 100% 통과한 trace
- `outputs/trace_flow_match_partial_or_strict.jsonl`: 일부 이상 통과한 trace
- `outputs/summary.json`: 요약 통계

## 실행
```bash
python experiments/epic001d_trace_flow_filter/scripts/filter_traces_by_flow.py \
  --flow-xml experiments/epic001c_testcase_flow_partition/outputs/manifest_with_testcase_flows.xml \
  --signatures-dir artifacts/signatures/infer-2026.03.09-14:42:44/signature-2026.03.09-14:43:10/non_empty \
  --output-dir experiments/epic001d_trace_flow_filter/outputs
```

추가 리포트:
```bash
python experiments/epic001d_trace_flow_filter/scripts/report_partial_misses.py
python experiments/epic001d_trace_flow_filter/scripts/report_nonb2b_presence_vs_hits.py
```
