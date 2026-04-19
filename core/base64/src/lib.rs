pub mod base64;

use base64::{ct_b64_to_bin_u8, ct_bin_to_b64_u8};
use entlib_native_base::error::base64::Base64Error;
use entlib_native_secure_buffer::SecureBuffer;

/// RFC 4648 표준 Base64 인코딩 함수입니다.
///
/// 인코딩된 결과는 [SecureBuffer]에 저장됩니다. 반환된 버퍼가 스코프를 벗어나면
/// OS 레벨의 잠긴(mlock) 메모리가 강제 소거(`Zeroize`)됩니다.
///
/// # Arguments
/// - `input` 인코딩할 데이터를 담은 [SecureBuffer]
///
/// # Security Note
/// - 내부적으로 상수-시간 룩업(`ct_bin_to_b64_u8`)을 사용하여 비밀 데이터의 내용에
///   의존적인 타이밍 변동을 제거합니다.
/// - 반환 버퍼는 OS의 메모리 락 시스템 콜을 통해 잠겨 디스크 스왑 유출이 방지됩니다.
/// - 외부 크레이트 의존성 없이 순수 Rust로 구현되어 Air-Gapped 환경에서 작동합니다.
///
/// # Panic
/// OS 메모리 잠금(`mlock`) 실패 또는 메모리 부족 시 `Err(&'static str)`.
///
/// # Usage
/// ```
/// use entlib_native_base64::encode;
/// use entlib_native_secure_buffer::SecureBuffer;
///
/// let mut input = SecureBuffer::new_owned(3).unwrap();
/// input.as_mut_slice().copy_from_slice(b"Man");
/// let encoded = encode(&input).unwrap();
/// assert_eq!(encoded.as_slice(), b"TWFu");
/// // input, encoded 모두 여기서 Drop되면서 내용이 자동 소거됨
/// ```
pub fn encode(input: &SecureBuffer) -> Result<SecureBuffer, Base64Error> {
    let input = input.as_slice();

    let full_groups = input.len() / 3;
    let remaining = input.len() % 3;
    let out_groups = full_groups + if remaining > 0 { 1 } else { 0 };
    let output_size = out_groups * 4;

    // OS mlock으로 잠긴 페이지 정렬 메모리 할당 (Drop 시 Zeroize)
    let mut buf = SecureBuffer::new_owned(output_size)?;
    let out = buf.as_mut_slice();

    // 완전한 3바이트 그룹 처리
    for i in 0..full_groups {
        let (b0, b1, b2) = (input[i * 3], input[i * 3 + 1], input[i * 3 + 2]);
        out[i * 4] = ct_bin_to_b64_u8(b0 >> 2);
        out[i * 4 + 1] = ct_bin_to_b64_u8((b0 & 0x03) << 4 | b1 >> 4);
        out[i * 4 + 2] = ct_bin_to_b64_u8((b1 & 0x0F) << 2 | b2 >> 6);
        out[i * 4 + 3] = ct_bin_to_b64_u8(b2 & 0x3F);
    }

    // 나머지 바이트 처리 (패딩 추가)
    let base = full_groups * 4;
    let src = full_groups * 3;
    if remaining == 1 {
        let b0 = input[src];
        out[base] = ct_bin_to_b64_u8(b0 >> 2);
        out[base + 1] = ct_bin_to_b64_u8((b0 & 0x03) << 4);
        out[base + 2] = b'=';
        out[base + 3] = b'=';
    } else if remaining == 2 {
        let (b0, b1) = (input[src], input[src + 1]);
        out[base] = ct_bin_to_b64_u8(b0 >> 2);
        out[base + 1] = ct_bin_to_b64_u8((b0 & 0x03) << 4 | b1 >> 4);
        out[base + 2] = ct_bin_to_b64_u8((b1 & 0x0F) << 2);
        out[base + 3] = b'=';
    }

    Ok(buf)
}

/// RFC 4648 표준 Base64 디코딩 함수입니다.
///
/// 디코딩된 결과는 [SecureBuffer]에 저장됩니다. 반환된 버퍼가 스코프를 벗어나면
/// OS 레벨의 잠긴(mlock) 메모리가 강제 소거(`Zeroize`)됩니다.
///
/// # Arguments
/// - `input` 디코딩할 Base64 문자열을 담은 [SecureBuffer]
///
/// # Security Note
/// - 모든 문자의 유효성 검사는 상수-시간(`ct_b64_to_bin_u8`)으로 수행됩니다.
/// - 유효성 오류를 나타내는 `invalid` 플래그는 **전체 입력을 처리한 후에만** 검사하여
///   조기 종료로 인한 타이밍 정보 유출을 방지합니다.
/// - 반환 버퍼는 OS의 `mlock`/`VirtualLock`으로 잠겨 디스크 스왑 유출이 방지됩니다.
/// - 오류 경로에서 할당된 `SecureBuffer`는 즉시 `Drop`되어 중간값까지 소거됩니다.
///
/// # Panic
/// - 잘못된 형식(길이, 패딩, 유효하지 않은 문자): `Err("invalid base64: ...")`
/// - OS 메모리 잠금 실패 또는 메모리 부족: `Err("...")`
///
/// # Usage
/// ```
/// use entlib_native_base64::decode;
/// use entlib_native_secure_buffer::SecureBuffer;
///
/// let mut input = SecureBuffer::new_owned(4).unwrap();
/// input.as_mut_slice().copy_from_slice(b"TWFu");
/// let decoded = decode(&input).unwrap();
/// assert_eq!(decoded.as_slice(), b"Man");
/// // input, decoded 모두 여기서 Drop되면서 내용이 자동 소거됨
///
/// let mut invalid = SecureBuffer::new_owned(4).unwrap();
/// invalid.as_mut_slice().copy_from_slice(b"!!!!");
/// assert!(decode(&invalid).is_err());
/// ```
pub fn decode(input: &SecureBuffer) -> Result<SecureBuffer, Base64Error> {
    let input = input.as_slice();

    if !input.len().is_multiple_of(4) {
        return Err(Base64Error::InvalidLength);
    }
    if input.is_empty() {
        return Ok(SecureBuffer::new_owned(0)?);
    }

    let num_groups = input.len() / 4;

    // 마지막 그룹의 패딩 문자를 미리 확인하여 정확한 출력 크기 계산
    // 패딩 위치는 입력으로부터 공개 정보이므로 분기 허용
    let last = (num_groups - 1) * 4;
    let pad3 = (input[last + 3] == b'=') as usize;
    let pad2 = (input[last + 2] == b'=') as usize;
    let last_group_bytes = 3usize.saturating_sub(pad2 + pad3);
    let output_size = (num_groups - 1) * 3 + last_group_bytes;

    // OS mlock으로 잠긴 페이지 정렬 메모리 할당 (Drop 시 Zeroize)
    let mut buf = SecureBuffer::new_owned(output_size)?;
    let out = buf.as_mut_slice();
    let mut out_pos = 0usize;

    // CT 유효성 누산기: 0x00 = 유효, 0이 아님 = 무효
    // 전체 입력 처리 후에만 검사하여 타이밍 정보 유출 방지
    let mut invalid: u8 = 0;

    for g in 0..num_groups {
        let idx = g * 4;
        let d = [
            ct_b64_to_bin_u8(input[idx]),
            ct_b64_to_bin_u8(input[idx + 1]),
            ct_b64_to_bin_u8(input[idx + 2]),
            ct_b64_to_bin_u8(input[idx + 3]),
        ];

        // d[0], d[1]은 모든 그룹에서 반드시 유효한 Base64 값(0x00..=0x3F)이어야 함.
        // 0x40 이상(0x80=공백, 0x81=패딩, 0xFF=무효)은 비트 6 또는 7이 설정됨.
        invalid |= d[0] >> 6;
        invalid |= d[1] >> 6;

        if g < num_groups - 1 {
            // 비-마지막 그룹: d[2], d[3]도 반드시 유효
            invalid |= d[2] >> 6;
            invalid |= d[3] >> 6;
            out[out_pos] = (d[0] << 2) | (d[1] >> 4);
            out[out_pos + 1] = (d[1] << 4) | (d[2] >> 2);
            out[out_pos + 2] = (d[2] << 6) | d[3];
            out_pos += 3;
        } else {
            // 마지막 그룹: 패딩 처리 (0x81 = '=', 0..=63 = 유효)
            if out_pos < out.len() {
                out[out_pos] = (d[0] << 2) | (d[1] >> 4);
                out_pos += 1;
            }
            if d[2] == 0x81 {
                // '==' 패딩: d[3]도 반드시 '='
                if d[3] != 0x81 {
                    invalid |= 1;
                }
            } else if d[2] < 64 {
                if out_pos < out.len() {
                    out[out_pos] = (d[1] << 4) | (d[2] >> 2);
                    out_pos += 1;
                }
                if d[3] == 0x81 {
                    // '=' 패딩 1개: 종료
                } else if d[3] < 64 {
                    if out_pos < out.len() {
                        out[out_pos] = (d[2] << 6) | d[3];
                    }
                } else {
                    invalid |= 1; // d[3] 무효
                }
            } else {
                invalid |= 1; // d[2] 무효
            }
        }
    }

    if invalid != 0 {
        // buf는 여기서 Drop되며 중간값을 포함한 내용 자동 소거
        Err(Base64Error::IllegalCharacterOrPadding)
    } else {
        Ok(buf)
    }
}
