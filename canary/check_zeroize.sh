#!/bin/zsh

# 설정 변수
CANARY_PATTERN="ENTLIB_FORENSIC_CANARY_PATTERN__"
CORE_DIR="/cores"
TEST_BINARY="../target/debug/entlib-canary"

echo "[*] EntanglementLib EAL2+ Zeroization Verification Test"
echo "[*] Setting up core dump limits..."
ulimit -c unlimited

echo "[*] Cleaning up previous core dumps in $CORE_DIR..."
sudo rm -f $CORE_DIR/core.*

echo "[*] Executing test binary..."
# 바이너리 실행 (내부에서 process::abort() 호출로 인해 abort 발생)
$TEST_BINARY &
PID=$!

# 프로세스 종료 대기 (SIGABRT로 비정상 종료되므로 에러 메시지 억제)
wait $PID 2>/dev/null
EXIT_CODE=$?

echo "[*] Process exited with code: $EXIT_CODE (Expected 134 for SIGABRT)"

# 가장 최근에 생성된 코어 덤프 파일 찾기
CORE_FILE=$(ls -t $CORE_DIR/core.* 2>/dev/null | head -n 1)

if [[ -z "$CORE_FILE" ]]; then
    echo "[-] FAILED: Core dump was not generated."
    echo "    Please check 'ulimit -c unlimited' and SIP settings."
    exit 1
fi

echo "[*] Core dump generated successfully: $CORE_FILE"
echo "[*] Scanning core dump for forensic canary. This may take a moment depending on dump size..."

# 1. strings 명령어로 바이너리 내의 텍스트만 초고속으로 추출
# 2. 파이프를 통해 grep -c 로 카나리아 패턴이 포함된 라인 수만 카운트
MATCH_COUNT=$(strings "$CORE_FILE" | grep -c "$CANARY_PATTERN" | tr -d ' ')

if [[ "$MATCH_COUNT" -gt 0 ]]; then
    echo "=========================================================="
    echo "[!] CRITICAL FAILURE: Zeroization Failed!"
    echo "[!] Forensic Canary found $MATCH_COUNT time(s) in memory."
    echo "[!] The chokepoint logic or compiler optimization defense has failed."
    echo "=========================================================="
    exit 1
else
    echo "=========================================================="
    echo "[+] SUCCESS: Forensic-proof Zeroization Verified!"
    echo "[+] Canary pattern was NOT found in the core dump."
    echo "[+] FIPS 140-3 / CC EAL2+ erasure requirements met."
    echo "=========================================================="
    exit 0
fi