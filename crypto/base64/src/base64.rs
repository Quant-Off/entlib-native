use entlib_native_constant_time::constant_time::ConstantTimeOps;

/// 단일 바이트 상수-시간 `Base64` 인코딩을 수행하는 함수입니다.
#[inline(always)]
pub fn ct_bin_to_b64_u8(c: u8) -> u8 {
    // 0 <= c < 26
    let mask_upper = c.wrapping_sub(26).ct_is_negative();
    // 26 <= c < 52
    let mask_lower = c.wrapping_sub(52).ct_is_negative() & !mask_upper;
    // 52 <= c < 62
    let mask_digit = c.wrapping_sub(62).ct_is_negative() & !mask_lower & !mask_upper;

    let mask_plus = c.ct_eq(62);
    let mask_slash = c.ct_eq(63);

    let v_upper = c.wrapping_add(65); // c + 'A'
    let v_lower = c.wrapping_add(71); // c - 26 + 'a'
    let v_digit = c.wrapping_sub(4); // c - 52 + '0'
    let v_plus = b'+';
    let v_slash = b'/';

    let mut res = 0u8;
    res = v_upper.ct_select(res, mask_upper);
    res = v_lower.ct_select(res, mask_lower);
    res = v_digit.ct_select(res, mask_digit);
    res = v_plus.ct_select(res, mask_plus);
    res = v_slash.ct_select(res, mask_slash);

    res
}

/// 단일 바이트 상수-시간 `Base64` 디코딩을 수행하는 함수입니다.
#[inline(always)]
pub fn ct_b64_to_bin_u8(b: u8) -> u8 {
    // 범위 검사
    let mask_upper = !b.wrapping_sub(65).ct_is_negative() & b.wrapping_sub(91).ct_is_negative();
    let mask_lower = !b.wrapping_sub(97).ct_is_negative() & b.wrapping_sub(123).ct_is_negative();
    let mask_digit = !b.wrapping_sub(48).ct_is_negative() & b.wrapping_sub(58).ct_is_negative();

    let mask_plus = b.ct_eq(b'+');
    let mask_slash = b.ct_eq(b'/');
    let mask_pad = b.ct_eq(b'=');

    // 공백 문자 허용 처리
    let mask_ws = b.ct_eq(b' ') | b.ct_eq(b'\t') | b.ct_eq(b'\r') | b.ct_eq(b'\n');

    let v_upper = b.wrapping_sub(65);
    let v_lower = b.wrapping_sub(71);
    let v_digit = b.wrapping_add(4);
    let v_plus = 62;
    let v_slash = 63;
    let v_pad = 0x81;
    let v_ws = 0x80;
    let v_invalid = 0xFF;

    let mut res = v_invalid;
    res = v_upper.ct_select(res, mask_upper);
    res = v_lower.ct_select(res, mask_lower);
    res = v_digit.ct_select(res, mask_digit);
    res = v_plus.ct_select(res, mask_plus);
    res = v_slash.ct_select(res, mask_slash);
    res = v_pad.ct_select(res, mask_pad);
    res = v_ws.ct_select(res, mask_ws);

    res
}
