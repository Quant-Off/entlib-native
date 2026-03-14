use entlib_native_constant_time::traits::{
    ConstantTimeEq, ConstantTimeIsNegative, ConstantTimeSelect,
};

/// 단일 6비트 값을 상수-시간으로 Base64 문자(ASCII)로 인코딩합니다.
///
/// # Arguments
/// `c`는 반드시 `0..=63` 범위의 값이어야 합니다.
///
/// # Security Note
/// - 분기 없는 비트 마스크 연산으로 타이밍 공격을 방어합니다.
/// - `ct_is_negative`: `wrapping_sub` 결과의 MSB를 이용한 상수-시간 범위 판별
/// - `ct_select`: CPU 분기 없는 조건부 값 선택
#[inline(always)]
pub fn ct_bin_to_b64_u8(c: u8) -> u8 {
    use entlib_native_constant_time::choice::Choice;

    // c < 26 이면 대문자 영역 (MSB 기반 언더플로우 감지)
    let mask_upper: Choice = c.wrapping_sub(26).ct_is_negative();
    // 26 <= c < 52 이면 소문자 영역
    let mask_lower: Choice = c.wrapping_sub(52).ct_is_negative() & !mask_upper;
    // 52 <= c < 62 이면 숫자 영역
    let mask_digit: Choice = c.wrapping_sub(62).ct_is_negative() & !mask_lower & !mask_upper;
    // c == 62 이면 '+'
    let mask_plus: Choice = c.ct_eq(&62u8);
    // c == 63 이면 '/'
    let mask_slash: Choice = c.ct_eq(&63u8);

    let v_upper = c.wrapping_add(65); // c + 'A' (0..=25 → 'A'..='Z')
    let v_lower = c.wrapping_add(71); // c - 26 + 'a' (26..=51 → 'a'..='z')
    let v_digit = c.wrapping_sub(4); // c - 52 + '0' (52..=61 → '0'..='9')
    let v_plus = b'+';
    let v_slash = b'/';

    // 후순위 마스크가 낮은 것부터 적용: 최종 유효 마스크가 res를 덮어씁니다.
    let mut res = 0u8;
    res = u8::ct_select(&v_upper, &res, mask_upper);
    res = u8::ct_select(&v_lower, &res, mask_lower);
    res = u8::ct_select(&v_digit, &res, mask_digit);
    res = u8::ct_select(&v_plus, &res, mask_plus);
    res = u8::ct_select(&v_slash, &res, mask_slash);

    res
}

/// 단일 Base64 문자(ASCII)를 상수-시간으로 6비트 값으로 디코딩합니다.
///
/// # Returns
/// | 반환값      | 의미                         |
/// |-------------|------------------------------|
/// | `0x00..=0x3F` | 유효한 Base64 값 (0..=63)  |
/// | `0x80`      | 공백 문자 (skip 권장)        |
/// | `0x81`      | 패딩 문자 `'='`              |
/// | `0xFF`      | 유효하지 않은 문자           |
///
/// # Security Note
/// - 모든 경로에서 동일한 수의 연산을 수행하여 타이밍 공격을 방어합니다.
#[inline(always)]
pub fn ct_b64_to_bin_u8(b: u8) -> u8 {
    use entlib_native_constant_time::choice::Choice;

    // 각 문자 범위에 대한 상수-시간 마스크 생성
    // 범위 [lo, hi): !b.wrapping_sub(lo).ct_is_negative() & b.wrapping_sub(hi).ct_is_negative()
    // = b >= lo AND b < hi
    let mask_upper: Choice = !b.wrapping_sub(65).ct_is_negative()   // b >= 'A'
        & b.wrapping_sub(91).ct_is_negative(); // b <  '['
    let mask_lower: Choice = !b.wrapping_sub(97).ct_is_negative()   // b >= 'a'
        & b.wrapping_sub(123).ct_is_negative(); // b <  '{'
    let mask_digit: Choice = !b.wrapping_sub(48).ct_is_negative()   // b >= '0'
        & b.wrapping_sub(58).ct_is_negative(); // b <  ':'
    let mask_plus: Choice = b.ct_eq(&b'+');
    let mask_slash: Choice = b.ct_eq(&b'/');
    let mask_pad: Choice = b.ct_eq(&b'=');
    let mask_ws: Choice = b.ct_eq(&b' ') | b.ct_eq(&b'\t') | b.ct_eq(&b'\r') | b.ct_eq(&b'\n');

    let v_upper: u8 = b.wrapping_sub(65); // 'A'..='Z' → 0..=25
    let v_lower: u8 = b.wrapping_sub(71); // 'a'..='z' → 26..=51
    let v_digit: u8 = b.wrapping_add(4); // '0'..='9' → 52..=61
    let v_plus: u8 = 62;
    let v_slash: u8 = 63;
    let v_pad: u8 = 0x81;
    let v_ws: u8 = 0x80;
    let v_invalid: u8 = 0xFF; // 기본값: 무효

    let mut res = v_invalid;
    res = u8::ct_select(&v_upper, &res, mask_upper);
    res = u8::ct_select(&v_lower, &res, mask_lower);
    res = u8::ct_select(&v_digit, &res, mask_digit);
    res = u8::ct_select(&v_plus, &res, mask_plus);
    res = u8::ct_select(&v_slash, &res, mask_slash);
    res = u8::ct_select(&v_pad, &res, mask_pad);
    res = u8::ct_select(&v_ws, &res, mask_ws);

    res
}
