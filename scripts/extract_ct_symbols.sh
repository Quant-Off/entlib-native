#!/bin/bash
# 컴파일된 바이너리에서 검증 대상 상수-시간 함수를 Zero-Trust 기반으로 자동 추출하기 위해 만듦

set -euo pipefail

TARGET_ARCH=$1
PACKAGE_NAME="entlib-native-constant-time"
CRATE_NAME="entlib_native_constant_time"

echo "[INFO] $TARGET_ARCH 아키텍처 바이너리 심볼 추출 시작"

# 라이브러리 내의 모든 심볼 목록 추출
# stderr 노이즈를 제거하여 순수 심볼 목록만 ALL_SYMBOLS에 담음
# cargo asm 자체가 실패할 경우 명시적인 에러 메시지 던짐
if ! ALL_SYMBOLS=$(cargo asm -p "$PACKAGE_NAME" --target "$TARGET_ARCH" --release --lib); then
    echo "[CRITICAL] cargo asm 실행 실패! 시스템 컴파일 에러 또는 타겟 아키텍처 의존성 누락을 확인하세요."
    exit 1
fi

# 대상 크레이트 네임스페이스 및 핵심 보안 트레이트 메소드 패턴 정의
# 명시된 모든 ConstantTime 연산 포함
SECURE_PATTERNS="(ct_eq|ct_ne|ct_is_ge|ct_select|ct_swap|ct_is_zero|ct_is_negative|from_mask_normalized|not|unwrap_u8)"

# 심볼 필터링 및 배열 저장
# - grep "$CRATE_NAME": 크레이트 네임스페이스 필터링
# - grep -E: 보안 패턴 메소드 필터링
# - sed: cargo-show-asm 출력에서 인덱스 번호 및 불필요한 공백을 제거하고 순수 함수 시그니처만 추출
# grep이 결과를 찾지 못해 Exit Code 1을 반환하더라도 pipefail에 의해 스크립트가 비정상 종료되는 현상 해결
mapfile -t TARGET_FUNCTIONS < <(echo "$ALL_SYMBOLS" \
  | (grep "$SYMBOL_NAMESPACE" || true) \
  | (grep -E "$SECURE_PATTERNS" || true) \
  | sed -E 's/^[0-9]+[[:space:]]+//g' \
  | sed -E 's/ \([0-9]+ bytes, [0-9]+ instructions\)//g')

if [ ${#TARGET_FUNCTIONS[@]} -eq 0 ]; then
    echo "[CRITICAL] 추출된 타겟 함수가 없습니다."
    exit 1
fi

# 검증 실패 통제
# 추출된 함수가 0개일 때, 원본 심볼 목록의 일부를 출력하여 디버깅 지원
if [ ${#TARGET_FUNCTIONS[@]} -eq 0 ]; then
    echo "[CRITICAL] 추출된 타겟 함수가 없습니다! 심볼 테이블이 손상되었거나 컴파일러에 의해 모두 최적화(DCE)되었을 가능성이 있습니다."
    echo "--- [디버그: 원본 심볼 목록 (상위 20개)] ---"
    echo "$ALL_SYMBOLS" | head -n 20
    echo "--------------------------------------------------------"
    exit 1
fi

echo "--- [자동 추출된 검증 대상 함수 목록: ${#TARGET_FUNCTIONS[@]}개] ---"
for FUNC in "${TARGET_FUNCTIONS[@]}"; do
    echo "$FUNC"
done
echo "--------------------------------------------------------"

# 환경 변수로 내보내어 CI 파이프라인의 다음 단계에서 사용 가능하도록 조치 (JSON 형식 변환)
# jq를 사용하여 쉘 배열을 JSON 배열 문자열로 안전히 직렬화
printf '%s\n' "${TARGET_FUNCTIONS[@]}" | jq -R . | jq -s . > target_functions.json