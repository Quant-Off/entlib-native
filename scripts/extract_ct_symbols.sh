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
ALL_SYMBOLS=$(cargo asm -p "$PACKAGE_NAME" --target "$TARGET_ARCH" --release --lib 2>&1 || true)
if [ -z "$ALL_SYMBOLS" ]; then
    echo "[CRITICAL] cargo asm 실행에 실패하여 심볼을 추출할 수 없습니다!"
    exit 1
fi

# 대상 크레이트 네임스페이스 및 핵심 보안 트레이트 메소드 패턴 정의
# 명시된 모든 ConstantTime 연산 포함
PATTERN_PREFIX="audit_verify_"
SECURE_PATTERNS="${PATTERN_PREFIX}(choice_from_mask_normalized|choice_not|choice_unwrap_u8|u64_ct_eq|u64_ct_is_ge|u64_ct_is_negative|u64_ct_is_zero|u64_ct_ne|u64_ct_select|u64_ct_swap)"

# 심볼 필터링 및 배열 저장
# - 첫 번째 안내 문구 제거 및 공백으로 분리된 항목을 줄 단위로 변환
# - grep -E: 보안 패턴 메소드 필터링
# - sed: 쌍따옴표, [bytes] 부분, 숫자 인덱스 제거 및 불필요한 공백 정리
mapfile -t TARGET_FUNCTIONS < <(echo "$ALL_SYMBOLS" \
  | sed 's/Try one of those by name or a sequence number //' \
  | tr ' ' '\n' \
  | grep -E "$SECURE_PATTERNS" \
  | sed -E 's/"//g' \
  | sed -E 's/\[[0-9]+\]//g')

# 검증 실패 통제
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