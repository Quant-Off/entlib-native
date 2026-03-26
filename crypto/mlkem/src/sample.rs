use crate::error::MLKEMError;
use crate::field::{Q, reduce_q};
use crate::ntt::N;
use entlib_native_sha3::api::{SHAKE128, SHAKE256};

/// FIPS 203 Algorithm 6: SampleNTT.
/// Samples a uniform NTT-domain polynomial using XOF = SHAKE128(rho || i || j).
pub(crate) fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> Result<[i32; N], MLKEMError> {
    let mut seed = [0u8; 34];
    seed[..32].copy_from_slice(rho);
    seed[32] = i;
    seed[33] = j;

    let mut xof = SHAKE128::new();
    xof.update(&seed);
    // 256 coefficients * 3 bytes each = 768 bytes; draw 840 for headroom.
    let buf = xof.finalize(840)?;
    let data = buf.as_slice();

    let mut coeffs = [0i32; N];
    let mut count = 0usize;
    let mut idx = 0usize;

    while count < N && idx + 3 <= data.len() {
        let b0 = data[idx] as u32;
        let b1 = data[idx + 1] as u32;
        let b2 = data[idx + 2] as u32;

        // Parse two 12-bit values per 3 bytes (little-endian).
        let d1 = b0 | ((b1 & 0x0F) << 8);
        let d2 = (b1 >> 4) | (b2 << 4);
        idx += 3;

        if d1 < Q as u32 {
            coeffs[count] = d1 as i32;
            count += 1;
        }
        if count < N && d2 < Q as u32 {
            coeffs[count] = d2 as i32;
            count += 1;
        }
    }

    if count < N {
        return Err(MLKEMError::InternalError("SampleNTT: 출력 부족"));
    }
    Ok(coeffs)
}

/// FIPS 203 Algorithm 7: SamplePolyCBD_η.
/// PRF_η(s, b) = SHAKE256(s || [b], 64·η).
/// Returns a polynomial with coefficients in [0, q-1].
pub(crate) fn sample_poly_cbd(s: &[u8; 32], b: u8, eta: usize) -> Result<[i32; N], MLKEMError> {
    let prf_len = 64 * eta;
    let mut prf_input = vec![0u8; 33];
    prf_input[..32].copy_from_slice(s);
    prf_input[32] = b;

    let mut prf = SHAKE256::new();
    prf.update(&prf_input);
    let buf = prf.finalize(prf_len)?;
    let bytes = buf.as_slice();

    cbd(bytes, eta)
}

/// Parse byte array into CBD polynomial (FIPS 203 Algorithm 7 inner logic).
fn cbd(bytes: &[u8], eta: usize) -> Result<[i32; N], MLKEMError> {
    let mut coeffs = [0i32; N];
    // Each coefficient uses 2η bits.
    let bits_per_coeff = 2 * eta;
    let total_bits = N * bits_per_coeff;
    if bytes.len() * 8 < total_bits {
        return Err(MLKEMError::InternalError("CBD: 입력 부족"));
    }

    for (i, coeff) in coeffs.iter_mut().enumerate() {
        let bit_offset = i * bits_per_coeff;
        let mut x = 0i32;
        let mut y = 0i32;
        for b in 0..eta {
            let pos_x = bit_offset + b;
            let pos_y = bit_offset + eta + b;
            x += ((bytes[pos_x / 8] >> (pos_x % 8)) & 1) as i32;
            y += ((bytes[pos_y / 8] >> (pos_y % 8)) & 1) as i32;
        }
        *coeff = reduce_q(x - y);
    }
    Ok(coeffs)
}
