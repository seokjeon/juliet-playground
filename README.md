# juliet-playground

Juliet C/C++ 테스트 스위트에 대해 Infer를 실행하고, 결과에서 signature를 생성하는 실험 저장소입니다.

## 소개

- **Infer 실행**: `tools/run-infer-all-juliet.py`
  - CWE 단위/파일 단위로 Juliet 테스트케이스를 실행
  - `issue / no_issue / error` 집계, `result.csv`, `no_issue_files.txt` 생성 가능
- **Signature 생성**: `tools/generate-signature.py`
  - `infer-out/report.json`에서 `bug_trace`가 있는 이슈를 JSON으로 분리 저장
  - `analysis/signature_counts.csv`에 CWE별 통계 저장

## Quick Start

### 1) 환경 설정 (최초 1회)

```bash
sudo apt-get update && sudo apt-get install -y python3 python3-venv python3-pip clang curl xz-utils libunwind8
```

```bash
cd /tmp && curl -fL -o infer-linux-x86_64-v1.2.0.tar.xz https://github.com/facebook/infer/releases/download/v1.2.0/infer-linux-x86_64-v1.2.0.tar.xz && tar -xf infer-linux-x86_64-v1.2.0.tar.xz && sudo rm -rf /opt/infer-linux-x86_64-v1.2.0 && sudo mv infer-linux-x86_64-v1.2.0 /opt/ && sudo ln -sf /opt/infer-linux-x86_64-v1.2.0/bin/infer /usr/local/bin/infer
```

```bash
cd /home/sojeon/Desktop/juliet-playground && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

### 2) 바로 실행 (한 줄)

```bash
source .venv/bin/activate && python tools/run-infer-all-juliet.py 78 --max-cases 3 --generate-signature
```

## 그 외 자주 쓰는 명령어

```bash
# Infer만 빠르게 실행
python tools/run-infer-all-juliet.py 78 --max-cases 3

# Infer + CSV
python tools/run-infer-all-juliet.py 78 --max-cases 3 --generate-csv

# 특정 파일(해당 flow variant 그룹)만 실행
python tools/run-infer-all-juliet.py --files juliet-test-suite-v1.3/C/testcases/CWE78_OS_Command_Injection/s01/CWE78_OS_Command_Injection__char_console_execlp_52a.c

# 기존 infer 결과에서 signature만 생성
python tools/generate-signature.py --input-dir artifacts/juliet-result-2026.03.08-18:04:18
```

## 결과 위치

- `artifacts/juliet-result-YYYY.MM.DD-HH:MM:SS/`
  - `CWE.../infer-out`
  - `no_issue_files.txt`
  - `result.csv` (`--generate-csv` 사용 시)

- `artifacts/signatures/signatures-result-YYYY.MM.DD-HH:MM:SS/`
  - `CWE.../*.json` (alarm별 signature)
  - `analysis/signature_counts.csv` (CWE별 통계 + TOTAL)

## 메모

- `.cpp`는 `clang++`, `.c`는 `clang` 사용
- `--files` 사용 시 `cwes` 인자는 무시
- Juliet 파일명 규칙 기반으로 같은 flow variant 그룹을 함께 컴파일
- Pulse taint 설정: `tools/pulse-taint-config.json`
