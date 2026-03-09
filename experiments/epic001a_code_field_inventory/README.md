# epic001a_code_field_inventory

`manifest_with_comments.xml`에서 코드 인벤토리(고유값/빈도)를 만들고,
`code(or flaw-derived code) -> 함수호출 후보` 맵을 생성합니다.

## 대상 태그
- `comment_flaw`, `comment_fix`: `code` 속성 사용
- `flaw`: `code`가 없으므로 `file+line` 기준 파싱으로 code-like key 생성

## 출력
- `outputs/code_unique.txt`: `comment_*` 기준 정렬된 unique code 목록
- `outputs/code_frequency.csv`: `comment_*` 기준 `count,code` (빈도 내림차순)
- `outputs/source_sink_candidate_map.json`: `code -> [{"name","argc"}, ...]`
  - 함수 호출은 선택된 코드 라인 노드의 서브트리에서 찾되, **시작 라인이 해당 line과 같은 호출만** 저장
- `outputs/function_name_frequency.csv`: `count,function_name` (candidate map 기준 빈도 내림차순)
- `outputs/function_name_unique.txt`: candidate map에서 추출된 함수명 unique 목록
- `outputs/global_macro_definitions_by_name.json`: `name -> [unique bodies...]` 형태 전역 `#define` 덤프
- `outputs/global_macro_definitions_by_name.jsonl`: `{"name": ..., "bodies": [...]}` 레코드(JSONL) 덤프
- `outputs/function_name_macro_resolution.csv`: 원본 함수명 → 매크로 치환 결과 및 상태
  - `resolved_names` 컬럼은 다중 body 치환 시 `|`로 연결된 여러 후보를 포함
- `outputs/pulse-taint-config.from_juliet.json`: unique 함수명 기반 Infer pulse taint config
- `outputs/summary.json`:
  - `total_code_entries`, `unique_code_entries`, `max_frequency`
  - `candidate_map_keys`, `keys_with_calls`
  - `unique_function_names`, `total_function_name_occurrences`
  - `global_macro_definition_rows`, `global_macro_unique_names`
  - `macro_names_detected`, `macro_resolved_count`, `macro_ambiguous_count`, `macro_unresolved_count`, `rand_alias_applied_count`
  - `duplicate_key_skipped`, `flaw_records_processed`

## 매크로 치환 규칙
- `juliet-test-suite-v1.3/C/**`에서 `#define`를 전역 수집해 함수명을 치환합니다.
- `RAND32`, `RAND64`는 항상 `rand`로 치환됩니다.
- 다중 후보 매크로는 우선순위(`function_like` > `object_like`, 비조건부 > 조건부, 최신 정의 우선)로 선택합니다.

## pulse-taint config 생성 (옵션)
`function_name_unique` 기준(동일한 unique 함수명 집합)으로 Infer용 `pulse-taint-config.json` 형태 파일을 생성합니다.

```bash
python experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py
```

- 기본 출력 경로: `experiments/epic001a_code_field_inventory/outputs/pulse-taint-config.from_juliet.json`
- 모든 함수가 source/sink 모두에 포함됩니다.
  - source: 각 procedure마다 `ReturnValue`, `AllArguments` 2개 객체
  - sink: 각 procedure마다 `AllArguments` 1개 객체
- 출력 스키마는 `tools/pulse-taint-config.from_tracer.json`과 동일한
  `pulse-taint-sources`, `pulse-taint-sinks`를 사용합니다.

원하면 출력 경로를 변경할 수 있습니다.
```bash
python experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py \
  --pulse-taint-config-output experiments/epic001a_code_field_inventory/outputs/pulse-taint-config.custom.json
```

## 실행
```bash
python experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py
```

옵션:
```bash
python experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py \
  --input-xml experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml \
  --source-root juliet-test-suite-v1.3/C \
  --output-dir experiments/epic001a_code_field_inventory/outputs
```
