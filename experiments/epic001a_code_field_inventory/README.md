# epic001a_code_field_inventory

이 스크립트는 `manifest_with_comments.xml`로부터 code / candidate-map / macro resolution 보고서를 생성하는
**experiments 전용 리포트 생성기**입니다.

파이프라인 Stage 02a의 핵심 책임은 `pulse-taint-config.json` 생성이며,
아래 inventory 산출물은 이 experiments 스크립트에서만 보장됩니다.

## 출력
- `outputs/code_unique.txt`: `comment_*` 기준 정렬된 unique code 목록
- `outputs/code_frequency.csv`: `comment_*` 기준 `count,code`
- `outputs/source_sink_candidate_map.json`: `code -> [{"name","argc"}, ...]`
- `outputs/function_name_frequency.csv`: `count,function_name`
- `outputs/function_name_unique.txt`: candidate map에서 추출된 함수명 unique 목록
- `outputs/global_macro_definitions_by_name.json`: 전역 `#define` 덤프
- `outputs/global_macro_definitions_by_name.jsonl`: 전역 `#define` 덤프(JSONL)
- `outputs/function_name_macro_resolution.csv`: 원본 함수명 → 매크로 해석 결과
- `outputs/pulse-taint-config.from_juliet.json`: unique 함수명 기반 Infer pulse taint config
- `outputs/summary.json`

## 실행
```bash
python experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py
```

옵션:
```bash
python experiments/epic001a_code_field_inventory/scripts/extract_unique_code_fields.py       --input-xml experiments/epic001_manifest_comment_scan/outputs/manifest_with_comments.xml       --source-root juliet-test-suite-v1.3/C       --output-dir experiments/epic001a_code_field_inventory/outputs
```
