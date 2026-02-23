#!/bin/bash

set -e

if [ -z "$1" ]; then
    echo "사용법: $0 <target-triple>"
    exit 1
fi

TARGET=$1
CRATE_NAME="entlib_native_constant_time"
MODULE_PATH="constant_time_asm"
EXIT_CODE=0

# 검사할 타입 및 메소드 정의 (tier 1 아키텍처 중심)
TYPES=("u32" "u64")
METHODS=("ct_nonzero" "ct_zero" "ct_negative" "ct_equal" "ct_not_equal" "ct_mux")

# 아키텍처별 금지된 조건부 분기 명령어 (정규표현식)
if [[ "$TARGET" == *"x86_64"* ]]; then
    FORBIDDEN_BRANCHES="\b(je|jz|jne|jnz|jg|jge|jl|jle|ja|jae|jb|jbe)\b"
elif [[ "$TARGET" == *"aarch64"* ]]; then
    FORBIDDEN_BRANCHES="\b(cbz|cbnz|tbz|tbnz|b\.eq|b\.ne|b\.cs|b\.cc|b\.mi|b\.pl|b\.vs|b\.vc|b\.hi|b\.ls|b\.ge|b\.lt|b\.gt|b\.le)\b"
else
    echo "지원하지 않는 아키텍처입니다: $TARGET"
    exit 0
fi

echo "[$TARGET] 상수-시간 어셈블리 검증 시작..."

for TYPE in "${TYPES[@]}"; do
    for METHOD in "${METHODS[@]}"; do
        # Rust 심볼 경로 조합 (<u64 as entlib_native_constant_time::constant_time_asm::CtPrimitive>::ct_mux 등)
        SYMBOL="<$TYPE as ${CRATE_NAME}::${MODULE_PATH}::CtPrimitive>::${METHOD}"

        echo "검사 중: $SYMBOL"

        # cargo-show-asm을 통해 어셈블리 추출 후 금지된 명령어 검색
        # --simplify 플래그를 통해 불필요한 디렉티브를 제거하여 검색 정확도 향상
        ASM_OUTPUT=$(cargo asm --target "$TARGET" --simplify "$CRATE_NAME" "$SYMBOL" 2>/dev/null || true)

        if echo "$ASM_OUTPUT" | grep -qE "$FORBIDDEN_BRANCHES"; then
            echo "[오류] 분기 명령어(timing leak)가 감지되었습니다: $SYMBOL"
            echo "$ASM_OUTPUT" | grep -E -C 2 "$FORBIDDEN_BRANCHES"
            EXIT_CODE=1
        fi
    done
done

if [ $EXIT_CODE -eq 0 ]; then
    echo "[$TARGET] 어셈블리 검증 통과: 분기문이 존재하지 않습니다."
else
    echo "[$TARGET] 어셈블리 검증 실패: 상수-시간 제약 위반."
fi

exit $EXIT_CODE