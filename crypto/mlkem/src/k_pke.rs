use crate::encode::{byte_decode, byte_encode, compress_and_encode, decode_and_decompress};
use crate::error::MLKEMError;
use crate::ntt::N;
use crate::poly::{Poly, PolyMatrix, PolyVec, inner_product};
use crate::sample::{sample_ntt, sample_poly_cbd};
use entlib_native_secure_buffer::SecureBuffer;
use entlib_native_sha3::api::SHAKE256;

//
// K-PKE.KeyGen (FIPS 203 Algorithm 12)
//

/// Generates a K-PKE key pair from 32-byte seed d.
/// Returns (ek_pke: Vec<u8>, dk_pke: SecureBuffer).
///
/// # Security Note
/// d must be generated from a CSPRNG. dk_pke is held in locked memory.
pub(crate) fn k_pke_keygen<const K: usize, const ETA1: usize>(
    d: &[u8; 32],
) -> Result<(Vec<u8>, SecureBuffer), MLKEMError> {
    // 1: (rho, sigma) = G(d || k)
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = K as u8;
    let g_out = sha3_512(&g_input)?;
    let rho: [u8; 32] = g_out[..32].try_into().unwrap();
    let sigma: [u8; 32] = g_out[32..].try_into().unwrap();

    // 2: A_hat = SampleNTT(rho, i, j) for i,j in 0..K
    let a_hat = sample_matrix::<K>(&rho)?;

    // 3: s = SamplePolyCBD_η1(sigma, N) for N=0..K
    // 4: e = SamplePolyCBD_η1(sigma, N) for N=K..2K
    let mut s_hat = PolyVec::<K>::zero();
    let mut e = PolyVec::<K>::zero();
    for i in 0..K {
        let s_coeffs = sample_poly_cbd(&sigma, i as u8, ETA1)?;
        s_hat.0[i] = Poly(s_coeffs);
        let e_coeffs = sample_poly_cbd(&sigma, (K + i) as u8, ETA1)?;
        e.0[i] = Poly(e_coeffs);
    }

    // 5: s_hat = NTT(s), e_hat = NTT(e)
    s_hat.ntt();
    let mut e_hat = e;
    e_hat.ntt();

    // 6: t_hat = A_hat · s_hat + e_hat
    let mut t_hat = a_hat.mul_vec(&s_hat);
    t_hat = t_hat.add(&e_hat);

    // 7: ek_pke = ByteEncode_12(t_hat) || rho
    let ek_len = 384 * K + 32;
    let mut ek = Vec::with_capacity(ek_len);
    for i in 0..K {
        ek.extend_from_slice(&byte_encode(&t_hat.0[i].0, 12));
    }
    ek.extend_from_slice(&rho);
    debug_assert_eq!(ek.len(), ek_len);

    // 8: dk_pke = ByteEncode_12(s_hat) → SecureBuffer
    let dk_len = 384 * K;
    let mut dk = SecureBuffer::new_owned(dk_len)
        .map_err(|_| MLKEMError::InternalError("SecureBuffer 할당 실패"))?;
    {
        let dk_bytes = dk.as_mut_slice();
        for i in 0..K {
            let encoded = byte_encode(&s_hat.0[i].0, 12);
            dk_bytes[i * 384..(i + 1) * 384].copy_from_slice(&encoded);
        }
    }

    Ok((ek, dk))
}

//
// K-PKE.Encrypt (FIPS 203 Algorithm 13)
//

/// Encrypts 32-byte message m under ek_pke using randomness r.
pub(crate) fn k_pke_encrypt<
    const K: usize,
    const ETA1: usize,
    const ETA2: usize,
    const DU: u32,
    const DV: u32,
>(
    ek: &[u8],
    m: &[u8; 32],
    r: &[u8; 32],
) -> Result<Vec<u8>, MLKEMError> {
    let expected_ek_len = 384 * K + 32;
    if ek.len() != expected_ek_len {
        return Err(MLKEMError::InvalidLength("k_pke_encrypt: ek 길이 불일치"));
    }

    // 1: Decode t_hat and rho from ek
    let mut t_hat = PolyVec::<K>::zero();
    for i in 0..K {
        t_hat.0[i] = Poly(byte_decode(&ek[i * 384..(i + 1) * 384], 12));
    }
    let rho: [u8; 32] = ek[384 * K..].try_into().unwrap();

    // 2: A_hat = SampleNTT(rho, ...)
    let a_hat = sample_matrix::<K>(&rho)?;

    // 3: r_vec = SamplePolyCBD_η1(r, 0..K)
    // 4: e1 = SamplePolyCBD_η2(r, K..2K)
    // 5: e2 = SamplePolyCBD_η2(r, 2K)
    let mut r_vec = PolyVec::<K>::zero();
    let mut e1 = PolyVec::<K>::zero();
    for i in 0..K {
        r_vec.0[i] = Poly(sample_poly_cbd(r, i as u8, ETA1)?);
        e1.0[i] = Poly(sample_poly_cbd(r, (K + i) as u8, ETA2)?);
    }
    let e2 = Poly(sample_poly_cbd(r, (2 * K) as u8, ETA2)?);

    // 6: r_hat = NTT(r)
    let mut r_hat = r_vec;
    r_hat.ntt();

    // 7: u = INTT(A_hat^T · r_hat) + e1
    let mut u = a_hat.mul_vec_transposed(&r_hat);
    u.intt();
    u = u.add(&e1);

    // 8: mu = Decompress_1(ByteDecode_1(m))
    let mu_coeffs = byte_decode(m, 1);
    let mut mu = Poly([0i32; N]);
    for (i, &x) in mu_coeffs.iter().enumerate() {
        mu.0[i] = if x != 0 { (crate::field::Q + 1) / 2 } else { 0 };
    }

    // 9: v = INTT(t_hat^T · r_hat) + e2 + mu
    let mut v = inner_product(&t_hat, &r_hat);
    v.intt();
    v = v.add(&e2);
    v = v.add(&mu);

    // 10: c1 = ByteEncode_du(Compress_du(u)), c2 = ByteEncode_dv(Compress_dv(v))
    let c1_len = 32 * DU as usize * K;
    let c2_len = 32 * DV as usize;
    let mut c = Vec::with_capacity(c1_len + c2_len);
    for i in 0..K {
        c.extend_from_slice(&compress_and_encode(&u.0[i].0, DU));
    }
    c.extend_from_slice(&compress_and_encode(&v.0, DV));

    Ok(c)
}

//
// K-PKE.Decrypt (FIPS 203 Algorithm 14)
//

/// Decrypts ciphertext c under dk_pke. Returns 32-byte message.
pub(crate) fn k_pke_decrypt<const K: usize, const DU: u32, const DV: u32>(
    dk: &[u8],
    c: &[u8],
) -> Result<[u8; 32], MLKEMError> {
    let c1_len = 32 * DU as usize * K;
    let c2_len = 32 * DV as usize;
    if c.len() != c1_len + c2_len {
        return Err(MLKEMError::InvalidLength("k_pke_decrypt: c 길이 불일치"));
    }
    if dk.len() != 384 * K {
        return Err(MLKEMError::InvalidLength("k_pke_decrypt: dk 길이 불일치"));
    }

    // 1: u = Decompress_du(ByteDecode_du(c1))
    let mut u = PolyVec::<K>::zero();
    for i in 0..K {
        let start = i * 32 * DU as usize;
        let end = start + 32 * DU as usize;
        u.0[i] = Poly(decode_and_decompress(&c[start..end], DU));
    }

    // 2: v = Decompress_dv(ByteDecode_dv(c2))
    let v = Poly(decode_and_decompress(&c[c1_len..], DV));

    // 3: s_hat = ByteDecode_12(dk)
    let mut s_hat = PolyVec::<K>::zero();
    for i in 0..K {
        s_hat.0[i] = Poly(byte_decode(&dk[i * 384..(i + 1) * 384], 12));
    }

    // 4: w = v - INTT(s_hat^T · NTT(u))
    u.ntt();
    let mut su = inner_product(&s_hat, &u);
    su.intt();
    let w = v.sub(&su);

    // 5: m = ByteEncode_1(Compress_1(w))
    let compressed: Vec<u8> = (0..N)
        .map(|i| {
            // Compress_1: nearest to 0 or q/2
            // Compress_1(x) = round(2*x / q) mod 2
            let c1 = ((2 * w.0[i] as i64 + crate::field::Q as i64 / 2) / crate::field::Q as i64)
                as i32
                & 1;
            c1 as u8
        })
        .collect();

    // Pack 256 bits into 32 bytes
    let mut m = [0u8; 32];
    for (i, &bit) in compressed.iter().enumerate() {
        m[i / 8] |= bit << (i % 8);
    }

    Ok(m)
}

//
// Internal helpers
//

/// SHA3-512: G function. Returns 64-byte output.
pub(crate) fn sha3_512(input: &[u8]) -> Result<[u8; 64], MLKEMError> {
    use entlib_native_sha3::api::SHA3_512;
    let mut h = SHA3_512::new();
    h.update(input);
    let out = h.finalize()?;
    let slice = out.as_slice();
    let mut arr = [0u8; 64];
    arr.copy_from_slice(slice);
    Ok(arr)
}

/// SHA3-256: H function. Returns 32-byte output.
pub(crate) fn sha3_256(input: &[u8]) -> Result<[u8; 32], MLKEMError> {
    use entlib_native_sha3::api::SHA3_256;
    let mut h = SHA3_256::new();
    h.update(input);
    let out = h.finalize()?;
    let slice = out.as_slice();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(slice);
    Ok(arr)
}

/// SHAKE256: J function. Returns 32-byte output.
pub(crate) fn shake256_32(input: &[u8]) -> Result<[u8; 32], MLKEMError> {
    let mut h = SHAKE256::new();
    h.update(input);
    let out = h.finalize(32)?;
    let mut arr = [0u8; 32];
    arr.copy_from_slice(out.as_slice());
    Ok(arr)
}

/// Samples the K×K NTT matrix A_hat from rho (FIPS 203 Algorithm 12 step 2).
fn sample_matrix<const K: usize>(rho: &[u8; 32]) -> Result<PolyMatrix<K>, MLKEMError> {
    let mut a = PolyMatrix::<K>::zero();
    for i in 0..K {
        for j in 0..K {
            a.0[i][j] = Poly(sample_ntt(rho, i as u8, j as u8)?);
        }
    }
    Ok(a)
}
