use entlib_native_constant_time::choice::Choice;
use entlib_native_constant_time::traits::{
    ConstantTimeEq, ConstantTimeIsNegative, ConstantTimeSelect,
};

/// 0~15 사이의 니블(Nibble)을 상수 시간으로 Hex ASCII 문자로 변환합니다.
///
/// # Security
/// 자체 구현된 `ConstantTimeIsNegative` 및 `ConstantTimeSelect` 트레이트를 사용하여
/// 데이터에 의존하는 어떠한 분기문(Branch)이나 메모리 룩업(Lookup)도 발생하지 않도록 통제합니다.
#[inline(always)]
fn encode_nibble_ct(nibble: u8) -> u8 {
    let v = nibble & 0x0F;

    // 1. 논리적 음수(Underflow) 유도
    // v가 10보다 작으면 언더플로우가 발생하여 MSB가 1이 됩니다.
    let diff = v.wrapping_sub(10);

    // 2. Choice 타입 생성
    // diff의 최상위 비트(MSB)를 확인하여 언더플로우 발생 여부를
    // 안전하게 캡슐화된 Choice(0xFF 또는 0x00)로 반환받습니다.
    let is_lt_10 = diff.ct_is_negative();

    // 3. 상수 시간 선택 (Constant-Time Select)
    // is_lt_10이 Choice(0xFF)일 경우 (참) -> a 인자 (48 + v) 선택 ('0'~'9')
    // is_lt_10이 Choice(0x00)일 경우 (거짓) -> b 인자 (87 + v) 선택 ('a'~'f')
    // 인자를 참조(&Self)로 전달하여 트레이트 규격을 준수합니다.
    u8::ct_select(&(48 + v), &(87 + v), is_lt_10)
}

/// 주어진 평문 슬라이스를 상수 시간으로 Hex 인코딩하여 출력 슬라이스에 작성합니다.
pub(crate) fn encode_hex_core_ct(input: &[u8], output: &mut [u8]) {
    // 출력 버퍼의 크기가 입력의 2배인지 엄격히 검증 (Zero-Trust 원칙)
    assert!(
        output.len() >= input.len() * 2,
        "Security Violation: Output buffer overflow"
    );

    for (i, &byte) in input.iter().enumerate() {
        let high = (byte >> 4) & 0x0F;
        let low = byte & 0x0F;

        output[i * 2] = encode_nibble_ct(high);
        output[i * 2 + 1] = encode_nibble_ct(low);
    }
}

/// 단일 ASCII 문자를 상수-시간으로 0~15 사이의 니블(Nibble)로 디코딩합니다.
///
/// # Returns
/// (디코딩된 값, 유효성 여부를 나타내는 Choice) 튜플을 반환합니다.
/// 문자가 유효하지 않더라도 연산 시간은 동일하며, 반환되는 Choice는 거짓(0x00)이 됩니다.
#[inline(always)]
#[allow(non_snake_case)] // for a, A, f, F
fn decode_nibble_ct(c: u8) -> (u8, Choice) {
    // 1. '0' ~ '9' (48 ~ 57) 판별
    // c < 48 이면 MSB가 1, 57 < c 이면 MSB가 1이 됨 (언더플로우 활용)
    let is_lt_0 = c.wrapping_sub(b'0').ct_is_negative();
    let is_gt_9 = b'9'.wrapping_sub(c).ct_is_negative();
    // ! 연산자는 Choice에 대해 상수-시간 NOT 연산을 수행합니다.
    let is_digit = !is_lt_0 & !is_gt_9;

    // 2. 'a' ~ 'f' (97 ~ 102) 판별
    let is_lt_a = c.wrapping_sub(b'a').ct_is_negative();
    let is_gt_f = b'f'.wrapping_sub(c).ct_is_negative();
    let is_lower_hex = !is_lt_a & !is_gt_f;

    // 3. 'A' ~ 'F' (65 ~ 70) 판별
    let is_lt_A = c.wrapping_sub(b'A').ct_is_negative();
    let is_gt_F = b'F'.wrapping_sub(c).ct_is_negative();
    let is_upper_hex = !is_lt_A & !is_gt_F;

    // 4. 단일 문자 유효성 병합
    // | 연산자는 Choice에 대해 상수-시간 OR 연산을 수행합니다.
    let is_valid = is_digit | is_lower_hex | is_upper_hex;

    // 5. 각 케이스별 논리적 반환값 계산 (분기 없이 모두 계산)
    let val_digit = c.wrapping_sub(b'0');
    let val_lower = c.wrapping_sub(87); // c - 97 + 10
    let val_upper = c.wrapping_sub(55); // c - 65 + 10

    // 6. 상수 시간 선택 (Constant-Time Select)
    // 기본값 0에서 시작하여 조건이 참(0xFF)일 때만 해당 값을 덮어씁니다.
    let mut result = 0u8;
    result = u8::ct_select(&result, &val_digit, is_digit);
    result = u8::ct_select(&result, &val_lower, is_lower_hex);
    result = u8::ct_select(&result, &val_upper, is_upper_hex);

    (result, is_valid)
}

/// 주어진 Hex 인코딩 슬라이스를 상수-시간으로 디코딩하여 출력 슬라이스에 작성합니다.
///
/// # Security
/// - 입력의 내용과 상관없이 항상 일정한 시간(O(N))에 실행됩니다.
/// - 에러가 발생해도 즉시 반환(Early Return)하지 않고 전체 길이를 모두 처리합니다.
pub(crate) fn decode_hex_core_ct(input: &[u8], output: &mut [u8]) -> Choice {
    assert!(
        output.len() >= input.len() / 2,
        "Security Violation: Output buffer overflow"
    );

    // 길이 검증: Hex 문자열은 항상 짝수 길이여야 합니다.
    // 길이는 비밀 데이터가 아니므로 일반 분기(if)를 사용해도 무방하지만,
    // 엄격한 상수-시간 제어를 위해 Choice를 생성합니다.
    let is_even_len = (input.len() % 2_usize).ct_eq(&0usize);

    // from_mask_unchecked 대신 ct_eq를 사용하여 True(0xFF) Choice를 초기화합니다.
    let mut all_valid = 0u8.ct_eq(&0u8);
    // 길이 홀수 에러도 통합 에러 상태에 병합
    all_valid = all_valid & is_even_len;

    // 실제 디코딩 루프 (입력 길이의 절반만큼 무조건 수행)
    let iter_count = input.len() / 2;
    for i in 0..iter_count {
        let (high_nibble, high_valid) = decode_nibble_ct(input[i * 2]);
        let (low_nibble, low_valid) = decode_nibble_ct(input[i * 2 + 1]);

        // & 연산자는 Choice에 대해 상수-시간 AND 연산을 수행합니다.
        let byte_valid = high_valid & low_valid;
        all_valid = all_valid & byte_valid;

        // 바이트 조합
        let decoded_byte = (high_nibble << 4) | low_nibble;

        // 유효하지 않은 바이트인 경우 출력 버퍼에 0을 기록하여 쓰레기값 생성을 방지합니다.
        output[i] = u8::ct_select(&0, &decoded_byte, byte_valid);
    }

    all_valid
}
