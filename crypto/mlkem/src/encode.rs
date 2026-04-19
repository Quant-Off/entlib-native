use crate::field::Q;
use crate::ntt::N;

/// FIPS 203 Algorithm 3: Compress_d(x) = round(2^d/q · x) mod 2^d.
#[inline(always)]
pub(crate) fn compress(x: i32, d: u32) -> i32 {
    // round(x * 2^d / q) = (x * 2^d + q/2) / q  (integer ceiling)
    let num = (x as i64) * (1i64 << d) + (Q as i64 / 2);
    (num / Q as i64) as i32 & ((1 << d) - 1)
}

/// FIPS 203 Algorithm 3: Decompress_d(x) = round(q/2^d · x).
#[inline(always)]
pub(crate) fn decompress(x: i32, d: u32) -> i32 {
    // round(q * x / 2^d) = (q * x + 2^(d-1)) >> d
    ((Q as i64 * x as i64 + (1i64 << (d - 1))) >> d) as i32
}

/// FIPS 203 Algorithm 4: ByteEncode_d.
/// Encodes 256 d-bit values into (256·d/8) bytes.
pub(crate) fn byte_encode(coeffs: &[i32; N], d: u32) -> Vec<u8> {
    let out_len = (N * d as usize) / 8;
    let mut out = vec![0u8; out_len];
    let mask = if d == 12 { 0xFFF } else { (1u32 << d) - 1 };
    let mut bit_pos = 0usize;
    for &c in coeffs.iter() {
        let val = (c as u32) & mask;
        for b in 0..d as usize {
            let bit = ((val >> b) & 1) as u8;
            out[bit_pos / 8] |= bit << (bit_pos % 8);
            bit_pos += 1;
        }
    }
    out
}

/// FIPS 203 Algorithm 5: ByteDecode_d.
/// Decodes (256·d/8) bytes into 256 d-bit values mod q (or mod 2^d for d<12).
pub(crate) fn byte_decode(bytes: &[u8], d: u32) -> [i32; N] {
    let mut coeffs = [0i32; N];
    let mask = if d == 12 { 0xFFF } else { (1u32 << d) - 1 };
    let mut bit_pos = 0usize;
    for coeff in coeffs.iter_mut() {
        let mut val = 0u32;
        for b in 0..d as usize {
            let byte_idx = bit_pos / 8;
            let bit_idx = bit_pos % 8;
            let bit = ((bytes[byte_idx] >> bit_idx) & 1) as u32;
            val |= bit << b;
            bit_pos += 1;
        }
        *coeff = (val & mask) as i32;
    }
    coeffs
}

/// Compressed byte encoding: compress each coefficient then encode.
pub(crate) fn compress_and_encode(coeffs: &[i32; N], d: u32) -> Vec<u8> {
    let mut compressed = [0i32; N];
    for (i, &c) in coeffs.iter().enumerate() {
        compressed[i] = compress(c, d);
    }
    byte_encode(&compressed, d)
}

/// Decode then decompress.
pub(crate) fn decode_and_decompress(bytes: &[u8], d: u32) -> [i32; N] {
    let decoded = byte_decode(bytes, d);
    let mut out = [0i32; N];
    for (i, &x) in decoded.iter().enumerate() {
        out[i] = decompress(x, d);
    }
    out
}
