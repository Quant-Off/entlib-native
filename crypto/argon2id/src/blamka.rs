//! BLAMKA(BLAke2 Mixed cAr Key Algorithm) 함수 모듈입니다.
//! RFC 9106 Section 3.5에서 정의된 Argon2 블록 혼합 함수를 구현합니다.

/// BLAMKA G_B 함수 — 64비트 곱셈 추가 혼합입니다.
///
/// # Security Note
/// 64비트 곱셈 항(`2 * lo32(a) * lo32(b)`)이 메모리 경화성을 제공합니다.
/// 하드웨어 병렬 처리 저항이 핵심 보안 속성입니다.
#[inline(always)]
pub(crate) fn gb(a: u64, b: u64, c: u64, d: u64) -> (u64, u64, u64, u64) {
    let a = a.wrapping_add(b).wrapping_add(2u64.wrapping_mul(a & 0xFFFF_FFFF).wrapping_mul(b & 0xFFFF_FFFF));
    let d = (d ^ a).rotate_right(32);
    let c = c.wrapping_add(d).wrapping_add(2u64.wrapping_mul(c & 0xFFFF_FFFF).wrapping_mul(d & 0xFFFF_FFFF));
    let b = (b ^ c).rotate_right(24);
    let a = a.wrapping_add(b).wrapping_add(2u64.wrapping_mul(a & 0xFFFF_FFFF).wrapping_mul(b & 0xFFFF_FFFF));
    let d = (d ^ a).rotate_right(16);
    let c = c.wrapping_add(d).wrapping_add(2u64.wrapping_mul(c & 0xFFFF_FFFF).wrapping_mul(d & 0xFFFF_FFFF));
    let b = (b ^ c).rotate_right(63);
    (a, b, c, d)
}

/// 16-워드(128바이트) 슬라이스에 BLAMKA 라운드를 적용하는 함수입니다.
///
/// 4회 열(column) 혼합 + 4회 대각선(diagonal) 혼합 = 1 라운드.
#[inline(always)]
pub(crate) fn blamka_round(v: &mut [u64]) {
    // column mixing
    let (a, b, c, d) = gb(v[0], v[4], v[8], v[12]);
    v[0] = a; v[4] = b; v[8] = c; v[12] = d;
    let (a, b, c, d) = gb(v[1], v[5], v[9], v[13]);
    v[1] = a; v[5] = b; v[9] = c; v[13] = d;
    let (a, b, c, d) = gb(v[2], v[6], v[10], v[14]);
    v[2] = a; v[6] = b; v[10] = c; v[14] = d;
    let (a, b, c, d) = gb(v[3], v[7], v[11], v[15]);
    v[3] = a; v[7] = b; v[11] = c; v[15] = d;
    // diagonal mixing
    let (a, b, c, d) = gb(v[0], v[5], v[10], v[15]);
    v[0] = a; v[5] = b; v[10] = c; v[15] = d;
    let (a, b, c, d) = gb(v[1], v[6], v[11], v[12]);
    v[1] = a; v[6] = b; v[11] = c; v[12] = d;
    let (a, b, c, d) = gb(v[2], v[7], v[8], v[13]);
    v[2] = a; v[7] = b; v[8] = c; v[13] = d;
    let (a, b, c, d) = gb(v[3], v[4], v[9], v[14]);
    v[3] = a; v[4] = b; v[9] = c; v[14] = d;
}

/// Argon2 블록 G 함수입니다.
///
/// R = X XOR Y 를 계산한 뒤 BLAMKA를 적용하고 R과 XOR합니다.
/// `dst`에 결과를 기록합니다. pass > 0이면 기존 `dst`와 XOR합니다.
pub(crate) fn block_g(dst: &mut [u64; 128], x: &[u64; 128], y: &[u64; 128], xor: bool) {
    let mut r = [0u64; 128];
    for i in 0..128 {
        r[i] = x[i] ^ y[i];
    }

    // Z = BLAMKA permutation of R
    // 블록을 8×8 행렬(각 셀 = 16 u64)로 해석:
    // 8개 행(row) 처리: 각 행 = 연속적인 16개 워드
    let mut z = r;
    for row in 0..8 {
        blamka_round(&mut z[row * 16..(row + 1) * 16]);
    }
    // 8개 열(column) 처리: 각 열 = stride-8로 떨어진 16개 워드
    for col in 0..8 {
        let mut tmp = [0u64; 16];
        for i in 0..16 {
            // column j = 각 행의 j번째 16-워드 그룹에서 col번째
            // 인덱싱: z[i*16 + col*2], z[i*16 + col*2 + 1] ... 복잡
            // 실제 인덱싱: 블록은 8행×8열의 16-word 셀
            // z[row*16 + col*2], z[row*16 + col*2 + 1] 로 16개 꺼냄
            // -> (row, col*2) 와 (row, col*2+1) 를 모든 row(0..8)에서
            let row = i / 2;
            let word = (i % 2) + col * 2;
            tmp[i] = z[row * 16 + word];
        }
        blamka_round(&mut tmp);
        for i in 0..16 {
            let row = i / 2;
            let word = (i % 2) + col * 2;
            z[row * 16 + word] = tmp[i];
        }
    }

    if xor {
        for i in 0..128 {
            dst[i] ^= r[i] ^ z[i];
        }
    } else {
        for i in 0..128 {
            dst[i] = r[i] ^ z[i];
        }
    }
}
