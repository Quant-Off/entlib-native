# ML-DSA Crate (entlib-native-mldsa)

> Q. T. Felix (revised: 26.03.24 UTC+9)
>
> [Korean README](README.md)

`entlib-native-mldsa` is a pure Rust implementation of the Module Lattice-based Digital Signature Algorithm (ML-DSA) as specified in NIST FIPS 204. This crate supports three parameter sets (ML-DSA-44/65/87) and defends against side-channel attacks through private key memory protection, hedged signing, and constant-time field arithmetic.

## Security Threat Model

Classical signature algorithms such as RSA and ECDSA are broken in polynomial time by a quantum computer running Shor's algorithm. ML-DSA grounds its security in the computational hardness of the Learning With Errors (LWE) problem and the Short Integer Solution (SIS) problem over module lattices; no known quantum algorithm reduces these below exponential time.

Three implementation-level attack surfaces are addressed. First, private key memory exposure: secret components such as `s1`, `s2`, `t0`, `K_seed`, and `tr` may leak via swap files or core dumps. This is mitigated by `SecureBuffer` (OS `mlock` + automatic zeroization on `Drop`). Second, timing side-channels during signing: branches dependent on secret components can expose the signing key. Finite field operations (`Fq::add`, `Fq::sub`, `power2round`, etc.) are implemented with constant-time select primitives from `entlib-native-constant-time`. Third, nonce reuse: generating two signatures with the same `rnd` allows full key recovery. Hedged signing mode (`rnd ← RNG`) eliminates this entirely.

## Parameter Sets

Three parameter sets defined in NIST FIPS 204 Section 4 are supported.

| Parameter Set | NIST Security Category  | pk size | sk size | sig size | λ (collision strength) |
|---------------|:-----------------------:|--------:|--------:|---------:|:----------------------:|
| ML-DSA-44     |      2 (≈ AES-128)      | 1312 B  | 2560 B  | 2420 B   | 128-bit                |
| ML-DSA-65     |      3 (≈ AES-192)      | 1952 B  | 4032 B  | 3309 B   | 192-bit                |
| ML-DSA87      |      5 (≈ AES-256)      | 2592 B  | 4896 B  | 4627 B   | 256-bit                |

Each parameter set differs in matrix dimensions $(k, l)$, secret coefficient range $\eta$, challenge polynomial weight $\tau$, masking range $\gamma_1$, decomposition range $\gamma_2$, and maximum hint weight $\omega$. Compile-time const generics monomorphize each variant with zero runtime overhead.

## Public API

### `MLDSA` Struct: Algorithms 1–3

`MLDSA` is the top-level entry point exposing only static methods. The parameter set is embedded in the key types, so it need not be specified separately at sign or verify time.

```rust
// Algorithm 1: ML-DSA.KeyGen
let mut rng = HashDRBGRng::new_from_os(None).unwrap();
let (pk, sk) = MLDSA::key_gen(MLDSAParameter::MLDSA44, &mut rng).unwrap();

// Algorithm 2: ML-DSA.Sign (hedged — rnd ← RNG)
let sig = MLDSA::sign(&sk, message, ctx, &mut rng).unwrap();

// Algorithm 3: ML-DSA.Verify
let ok = MLDSA::verify(&pk, message, &sig, ctx).unwrap();
assert!(ok);
```

**Message preprocessing**: The external interface constructs $M' = \texttt{0x00} \| \text{IntegerToBytes}(|ctx|, 1) \| ctx \| M$ per FIPS 204 Section 5.2 before passing it to internal algorithms. Returns `ContextTooLong` if `ctx.len() > 255`.

**Hedged signing**: `sign` draws 32 bytes of `rnd` from the RNG and passes them to the internal algorithm. Even if `rnd` is disclosed, the signing is not deterministic, making nonce-reuse attacks impossible.

### `MLDSAParameter` Enum

```rust
pub enum MLDSAParameter { MLDSA44, MLDSA65, MLDSA87 }
```

`pk_len()`, `sk_len()`, and `sig_len()` are provided as `const fn`.

## Key Types

### `MLDSAPublicKey`

Holds the encoded public key bytes ($\rho \| \text{SimpleBitPack}(t_1, 10)$) together with the parameter set. Can be reconstructed from an external byte slice via `from_bytes`; returns `InvalidLength` on a size mismatch.

> [!NOTE]
> **pkEncode layout**: $\rho$ (32 B) $\|$ SimpleBitPack$(t_1[0], 10)$ $\|$ $\cdots$ $\|$ SimpleBitPack$(t_1[k-1], 10)$
>
> Coefficients of $t_1$ are packed at 10 bits each, yielding 320 B per polynomial and $32 + 320k$ B in total.

### `MLDSAPrivateKey`

Stores the encoded private key bytes in a `SecureBuffer` (OS `mlock`). Memory is immediately zeroized on `Drop`. The slice is accessible via `as_bytes()`, but PKCS#8 encryption must be applied when persisting to disk.

> [!NOTE]
> **skEncode layout**: $\rho$ (32 B) $\|$ $K_{\text{seed}}$ (32 B) $\|$ $tr$ (64 B) $\|$ BitPack$(s_1, \eta, \eta)$ $\|$ BitPack$(s_2, \eta, \eta)$ $\|$ BitPack$(t_0, 4095, 4096)$
>
> $\eta = 2$ encodes 3 bits per coefficient; $\eta = 4$ encodes 4 bits per coefficient.

## RNG Abstraction

### `MLDSARng` Trait

```rust
pub trait MLDSARng {
    fn fill_random(&mut self, dest: &mut [u8]) -> Result<(), MLDSAError>;
}
```

Implementors must provide a DRBG with security strength ≥ 256-bit per NIST SP 800-90A Rev.1 or later.

### `HashDRBGRng`

Wrapper around NIST Hash_DRBG (SHA-512, Security Strength 256-bit). `new_from_os` is the only initialization path and accepts only OS entropy (`getrandom`/`getentropy`). Internal state V and C are held in `SecureBuffer` and zeroized on `Drop`. Call `reseed()` upon receiving `MLDSAError::RngError(ReseedRequired)`.

### `CtrDRBGRng`

Reserved struct for NIST CTR_DRBG (AES-256-CTR). All methods return `NotImplemented` until `entlib-native-aes` is complete.

## Internal Algorithm Structure

### Key Generation (Algorithm 4/6)

The seed $\xi \in \mathbb{B}^{32}$ is expanded via SHAKE256 to derive $(\rho, \rho', K_{\text{seed}})$.

$$A_{\hat{}} \leftarrow \text{ExpandA}(\rho), \quad (s_1, s_2) \leftarrow \text{ExpandS}(\rho')$$

$$t = \text{INTT}(A_{\hat{}} \circ \text{NTT}(s_1)) + s_2, \quad (t_1, t_0) \leftarrow \text{Power2Round}(t, d)$$

Power2Round splits coefficients as $a_1 = \lceil a / 2^{13} \rceil$, $a_0 = a - a_1 \cdot 2^{13}$. Converting negative $a_0$ to its $\mathbb{Z}_q$ representation uses `ct_is_negative` + `ct_select`.

The trace $tr = H(\text{pkEncode}(\rho, t_1), 64)$ is computed via incremental SHAKE256 hashing.

### Signing (Algorithm 5)

A rejection-sampling loop. On each attempt:

$$y \leftarrow \text{ExpandMask}(\rho'', \kappa), \quad w = \text{INTT}(A_{\hat{}} \circ \text{NTT}(y))$$

$$w_1 = \text{HighBits}(w, 2\gamma_2), \quad \tilde{c} \leftarrow H(\mu \| w_1, \lambda/4)$$

$$z = y + c \cdot s_1$$

The attempt is rejected and retried if $\|z\|_\infty \ge \gamma_1 - \beta$ or $\|\text{LowBits}(w - c \cdot s_2, 2\gamma_2)\|_\infty \ge \gamma_2 - \beta$. The hint $h = \text{MakeHint}(-c \cdot t_0,\, w - c \cdot s_2 + c \cdot t_0,\, 2\gamma_2)$ is produced and $\|h\|_1 \le \omega$ is checked. Exceeding the maximum attempt count returns `SigningFailed`.

### Verification (Algorithm 7)

Returns `false` immediately if $\|z\|_\infty \ge \gamma_1 - \beta$ or $\|h\|_1 > \omega$.

$$w_1' = \text{UseHint}(h,\; \text{INTT}(A_{\hat{}} \circ \text{NTT}(z)) - c \cdot t_1 \cdot 2^d,\; 2\gamma_2)$$

Compares $\tilde{c}$ against the recomputed $H(\mu \| w_1', \lambda/4)$.

> [!NOTE]
> **Constant-time challenge comparison**: The challenge hash comparison (`c_tilde` ↔ recomputed value) that determines signature validity involves no secret data, so a standard byte comparison is used. The norm check (`fq_to_signed`) likewise operates on public data (controlling retry decisions), so a timing-variable path is acceptable there.

### NTT / Finite Field Arithmetic

Operates over the polynomial ring $R_q = \mathbb{Z}_q[X]/(X^{256}+1)$, $q = 8{,}380{,}417$. The NTT uses a bit-reversed array of Montgomery-domain primitive roots of unity (`ZETAS[256]`). The Montgomery reduction constant is $q^{-1} \bmod 2^{32} = 58{,}728{,}449$; the INTT normalization constant is $N^{-1} \cdot R^2 \bmod q = 41{,}978$.

`Fq::add` and `Fq::sub` are branch-free constant-time implementations using `ct_is_negative` + `ct_select`.

## Error Types

| Error              | Meaning                                              |
|--------------------|------------------------------------------------------|
| `InvalidLength`    | Key or signature byte length mismatch                |
| `InternalError`    | Hash function error or memory allocation failure     |
| `RngError`         | RNG internal error or reseed required                |
| `ContextTooLong`   | `ctx` exceeds 255 bytes                              |
| `SigningFailed`    | Rejection sampling exceeded maximum attempts (rare)  |
| `InvalidSignature` | Signature verification failure                       |
| `NotImplemented`   | Unimplemented feature (e.g., CTR_DRBG)               |
