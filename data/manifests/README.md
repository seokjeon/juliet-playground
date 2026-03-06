# Manifests

이 디렉터리는 "어떤 파일/케이스를 처리할지"를 정의하는 입력 명세를 저장합니다.

예:
- `subset_v1.json`: 빠른 프로토타입용 소규모 CWE subset
- `subset_v2.json`: 학습용 확장 subset

권장 필드:
- 버전(`version`)
- 포함/제외 규칙(`include`, `exclude`)
- 대상 CWE 목록 또는 파일 목록
- 메모(`note`)
