# AES-256 Crate (entlib-native-aes)

> Q. T. Felix (Modified: 26.03.22 UTC+9)
> 
> [Korean README](README.md)

`entlib-native-aes` is an AES-256 encryption module designed to meet the requirements of NIST FIPS 140-3 and Common Criteria EAL4+ certification. It **only supports 256-bit keys** and implements two approved modes of operation that provide both confidentiality and integrity.

- **AES-256-GCM** — AEAD (Authenticated Encryption with Associated Data) compliant with NIST SP 800-38D
- **AES-256-CBC-HMAC-SHA256** — Encrypt-then-MAC configuration with NIST SP 800-38A (CBC is not used alone)

**This algorithm intentionally does not support 128 and 192 key lengths.** FIPS 140-3 recommends the use of AES-256, and by exposing only a single key size, it prevents security weaknesses caused by incorrect key length selection in advance.

## Security Threat Model

### Cache-Timing Attack

Standard software implementations of AES use a 256-byte S-box lookup table for the SubBytes operation. This approach has a fatal vulnerability. An attacker in an environment that shares the same CPU cache (VPS, cloud) can statistically recover the accessed table index, i.e., the secret key byte, from the cache hit/miss pattern. Daniel Bernstein's (D. J. Bernstein) 2005 AES timing attack demonstrated this empirically.

This crate does not use any lookup tables. SubBytes performs the GF(2^8) inverse calculation and affine transformation as pure arithmetic bit operations, and the execution time of all operations is completely independent of the secret key and plaintext values.

### Padding Oracle Attack

In CBC mode, if the decryption error response depends on the validity of the padding, an attacker can completely decrypt an arbitrary ciphertext with an adaptive chosen-ciphertext attack (ACCA) (POODLE, Lucky 13 variants). This implementation fundamentally blocks this attack vector by forcing the **Encrypt-then-MAC** configuration. MAC verification is performed first, and if the MAC fails, the decryption operation itself is not performed.

### GCM Nonce Reuse

In GCM, if the same (key, nonce) pair is used even twice, the XOR of the plaintexts is exposed from the XOR of the two ciphertexts, completely breaking confidentiality. Furthermore, the authentication key H is recovered by solving the GHASH polynomial equation, which also threatens integrity. This crate delegates the nonce generation policy to the caller and attaches an explicit warning to the API documentation. In a production environment, generate the nonce with `HashDRBGSHA256` from `entlib-native-rng` or use a counter-based configuration that guarantees no collisions.

## Security Core: Constant-Time AES Core

### GF(2^8) Arithmetic

AES SubBytes calculates the inverse on the finite field GF(2^8) = GF(2)[x] / (x^8 + x^4 + x^3 + x + 1) and then applies an affine transformation.

#### xtime: Multiply by x in GF(2^8)

$$ \text{xtime}(a) = \begin{cases} a \ll 1 & \text{if MSB}(a) = 0 \\ (a \ll 1) \oplus \texttt{0x1b} & \text{if MSB}(a) = 1 \end{cases} $$

Implemented without a branch statement.

$$\text{mask} = -(a \gg 7), \quad \text{xtime}(a) = (a \ll 1) \oplus (\texttt{0x1b} \land \text{mask})$$

Since `mask` is `0xFF` if the MSB is 1 and `0x00` if it is 0, it is compiled into four instructions: a single `SHR`, `NEG`, `AND`, and `XOR`.

#### gmul: GF(2^8) Multiplication — Fixed 8 Iterations

$$\text{gmul}(a, b) = \bigoplus_{i=0}^{7} \left( a \cdot x^i \land -(b_i) \right)$$

Here, $b_i$ is the $i$-th bit of $b$. It performs a conditional XOR without branching by converting the bit to a mask with `-(b & 1).wrapping_neg()`. The number of iterations is a fixed value of 8, which is independent of the secret data, so the timing is constant.

#### gf_inv: GF(2^8) Inverse — Fermat's Little Theorem

In a finite field, if $a \ne 0$, then $a^{-1} = a^{2^8 - 2} = a^{254}$. If $a = 0$, then $0^{254} = 0$ is naturally returned, so no branch is needed.

> [!NOTE]
> **Square-and-Multiply Expansion**: Since $254 = \texttt{11111110}_2$,
>
> $$a^{254} = a^{128} \cdot a^{64} \cdot a^{32} \cdot a^{16} \cdot a^8 \cdot a^4 \cdot a^2$$
>
> It is calculated with a total of 13 `gmul` calls, with 7 squarings and 6 multiplications. Since there is no table access at all, there is no cache timing channel.

#### sub_byte: SubBytes Affine Transformation

Applies the affine transformation $M \cdot a^{-1} + c$ to the inverse $a^{-1}$.

$$b_i = a^{-1}_i \oplus a^{-1}_{(i+4) \bmod 8} \oplus a^{-1}_{(i+5) \bmod 8} \oplus a^{-1}_{(i+6) \bmod 8} \oplus a^{-1}_{(i+7) \bmod 8} \oplus c_i$$

Expressed equivalently by bit rotation ($c = \texttt{0x63}$).

```math
\text{sub\_byte}(a) = a^{-1} \oplus \text{ROL}(a^{-1}, 1) \oplus \text{ROL}(a^{-1}, 2) \oplus \text{ROL}(a^{-1}, 3) \oplus \text{ROL}(a^{-1}, 4) \oplus \texttt{0x63}
```

Inverse SubBytes (`inv_sub_byte`) calculates the inverse after the inverse affine transformation.

```math
\text{inv\_sub\_byte}(a) = \text{gf\_inv}\!\left(\text{ROL}(a,1) \oplus \text{ROL}(a,3) \oplus \text{ROL}(a,6) \oplus \texttt{0x05}\right)
```

### Key Schedule

AES-256 generates 15 round keys (16 bytes each) from a 32-byte master key. The intermediate array `w: [u32; 60]` used for key expansion is erased with `write_volatile` immediately after the round keys are extracted. The `KeySchedule` struct implements the `Drop` trait to automatically force the erasure of the entire 240-byte round key when it goes out of scope.

```rust
impl Drop for KeySchedule {
    fn drop(&mut self) {
        for rk in &mut self.round_keys {
            for b in rk {
                unsafe { write_volatile(b, 0) };
            }
        }
    }
}
```

## AES-256-GCM

Implementation according to NIST SP 800-38D §7.1. Only 96-bit (12 bytes) nonces are supported. The generalized path that allows for arbitrary length IVs (IV derivation using GHASH) is intentionally excluded as it increases the risk of nonce collisions.

### Internal Operation

1. **Hash Subkey Generation**
   - $H = E_K(0^{128})$
2. **Initial Counter Block**
   - $J_0 = \text{nonce}_{96} \| \texttt{0x00000001}_{32}$
3. **Encryption (GCTR)**
   - $C = \text{GCTR}_K(\text{inc}_{32}(J_0),\ P)$
   - $\text{inc}_{32}$ increments the lower 32 bits by 1 in big-endian.
4. **Authentication Tag**
   - $T = E_K(J_0) \oplus \text{GHASH}_H(A,\ C)$

Here, GHASH processes the AAD, the ciphertext, and the length block $[\text{len}(A)]_{64} \| [\text{len}(C)]_{64}$ in order.

### GHASH: GF(2^128) Multiplication — Constant-Time Guarantee

GCM authentication is performed over $\text{GF}(2^{128})$. The reduction polynomial is $f(x) = x^{128} + x^7 + x^2 + x + 1$, which is represented by the bit string `0xE1000...0` (128 bits, MSB first).

> [!NOTE]
> **Constant-Time GF(2^128) Multiplication**: The standard implementation of NIST SP 800-38D Algorithm 1 includes a conditional branch that depends on a secret value. This implementation removes it with a fixed 128 iterations and a bit mask trick.
>
> In each iteration, the $i$-th bit of $X$, $X_i$, is converted to a mask to accumulate without branching.
>
> $$\text{mask} = -(X_i), \quad Z \mathrel{⊕}= V \land \text{mask}$$
>
> The conditional reduction after the right shift of $V$ is also handled in the same way.
>
> ```math
> \text{lsb\_mask} = -(V_{127}), \quad V_{\text{high}} \mathrel{⊕}= \texttt{0xE100...00} \land \text{lsb\_mask}
> ```

`GHashState` implements the `Drop` trait to erase the internal state $Z$ and the hash subkey $H$ with `write_volatile`.

### Decryption Verification Principle

When decrypting, the tag is first recalculated, and the 16 bytes are compared in constant time using `ConstantTimeEq::ct_eq()`. If the verification fails, `AESError::AuthenticationFailed` is returned and no plaintext is output at all.

```rust
// Constant-time 16-byte comparison
let mut r = 0xFFu8;
for i in 0..16 {
r &= expected_tag[i].ct_eq(&received_tag[i]).unwrap_u8();
}
if r != 0xFF { return Err(AESError::AuthenticationFailed); }
// Decryption is performed only after verification passes
```

### API

```rust
AES256GCM::encrypt(
key: &SecureBuffer,           // 256-bit AES key
nonce: &[u8; 12],             // 96-bit nonce (must be unique)
aad: &[u8],                   // Additional authenticated data
plaintext: &[u8],
ciphertext_out: &mut [u8],    // plaintext.len() bytes
tag_out: &mut [u8; 16],       // Authentication tag output
) -> Result<(), AESError>

AES256GCM::decrypt(
key: &SecureBuffer,
nonce: &[u8; 12],
aad: &[u8],
ciphertext: &[u8],
tag: &[u8; 16],               // Received authentication tag
plaintext_out: &mut [u8],     // ciphertext.len() bytes
) -> Result<(), AESError>         // AuthenticationFailed if tag does not match
```

> [!WARNING]
> Using the same `(key, nonce)` pair more than once will destroy both confidentiality and integrity. Generate the nonce via `HashDRBGSHA256` from `entlib-native-rng` or manage it with a monotonically increasing counter.

## AES-256-CBC-HMAC-SHA256

The use of CBC mode alone in NIST SP 800-38A only guarantees confidentiality and does not provide integrity. This implementation forces the **Encrypt-then-MAC** configuration. After encryption, an HMAC-SHA256 tag is generated for `IV || ciphertext` and attached to the output.

### Output Format

```
┌─────────────────┬────────────────────────────────────────┬───────────────────────────────┐
│   IV  (16 B)    │  Ciphertext + PKCS7 Padding  (N×16 B)  │  HMAC-SHA256(IV||CT)  (32 B)  │
└─────────────────┴────────────────────────────────────────┴───────────────────────────────┘
```

PKCS7 padding is always added. Even if the plaintext fits exactly on a block boundary, a full padding block of 16 bytes (`0x10` × 16) is added, so the length of the output ciphertext is always $\lceil P / 16 \rceil + 1$ blocks.

> [!NOTE]
> **PKCS7 Constant-Time Verification**: When decrypting, the padding byte verification is performed with XOR and a bit mask.
>
> ```math
> \begin{align}
>     \text{diff}_i &= \text{data}[i] \oplus \text{pad\_byte}, \quad \text{not\_zero}_i = \frac{\text{diff}_i \mathbin{|} (-\text{diff}_i)}{2^7} \\
>     \text{valid} &= \bigwedge_{i} \overline{(\text{not\_zero}_i - 1)} \quad (\text{0xFF if valid})
> \end{align}
>```
>
> Since padding verification is performed only after MAC verification passes, it is impossible for an attacker to use a padding oracle without a valid MAC.

### Decryption Order

1. Verify input format (minimum 64 bytes, block size aligned)
2. Recalculate HMAC-SHA256 → constant-time comparison with `ct_eq_32` (`AESError::AuthenticationFailed` or pass)
3. Perform AES-256-CBC decryption only after MAC verification passes
4. Verify and remove PKCS7 padding

### API

```rust
AES256CBCHmac::encrypt(
    enc_key: &SecureBuffer,   // 256-bit AES encryption key
    mac_key: &SecureBuffer,   // HMAC-SHA256 key (minimum 14 bytes, recommended 32 bytes)
    iv: &[u8; 16],            // 128-bit IV (must be unique for each message)
    plaintext: &[u8],
    output: &mut [u8],        // minimum cbc_output_len(plaintext.len()) bytes
) -> Result<usize, AESError>  // Number of bytes written to output

AES256CBCHmac::decrypt(
    enc_key: &SecureBuffer,
    mac_key: &SecureBuffer,
    input: &[u8],             // IV(16) || CT || HMAC(32) format
    output: &mut [u8],
) -> Result<usize, AESError>  // Number of decrypted plaintext bytes

// Buffer size calculation helpers
cbc_output_len(plaintext_len: usize) -> usize
cbc_plaintext_max_len(input_len: usize) -> Option<usize>
```

> [!IMPORTANT]
> `enc_key` and `mac_key` must be independent and separate keys. Reusing the same key for both purposes invalidates the security proof of the cryptographic scheme. If key derivation is required, use `entlib-native-hkdf` to derive two independent subkeys from a master key.

## Key Management Requirements

| Parameter      | Requirement                         | Rationale                          |
|-----------|------------------------------|-----------------------------|
| AES Key     | Exactly 256 bits (32 bytes)         | FIPS 140-3, NIST SP 800-38D |
| GCM nonce | 96 bits (12 bytes), unique          | NIST SP 800-38D §8.2        |
| CBC IV    | 128 bits (16 bytes), unique for each message | NIST SP 800-38A §6.2        |
| CBC MAC Key | Independent of AES key, minimum 112 bits          | NIST SP 800-107r1           |

All keys must be managed with `SecureBuffer` from `entlib-native-secure-buffer` to ensure mlock-based memory locking and automatic erasure on Drop.

## Verification

### NIST CAVP Test Vectors

| Test                | Source                                    | Result |
|--------------------|---------------------------------------|----|
| AES-256 ECB Block Encryption | NIST FIPS 197 Appendix B              | O  |
| AES-256-GCM Encryption    | NIST CAVP (OpenSSL cross-validation)             | O  |
| AES-256-GCM Decryption    | Reverse roundtrip                             | O  |
| AES-256-CBC Ciphertext    | NIST SP 800-38A F.2.5 (OpenSSL cross-validation) | O  |
| GCM Tag 1-bit Tampering      | Manipulated tag → `AuthenticationFailed`       | O  |
| CBC MAC 1-bit Tampering     | Manipulated MAC → `AuthenticationFailed`      | O  |

```bash
cargo test -p entlib-native-aes
```

> [!WARNING]
> We are in the process of preparing to strictly pass the KAT (Known Answer Test) test vectors.
> 
> The basis for the table above is the `aes_test.rs` test module, which verifies the matching of individual test blocks of the test vectors.

## Summary of Design Principles

1. **Force 256-bit single key** — Blocks security weaknesses due to key size selection errors at the API level.
2. **Complete exclusion of lookup tables** — All operations, including the S-box, are performed as pure arithmetic bit operations, so there is no cache timing channel.
3. **Fixed number of iterations** — All internal loops, such as `gmul` (8 times) and `gf128_mul` (128 times), are fixed to constants that are independent of the secret data.
4. **Force Encrypt-then-MAC** — Structurally blocks padding oracle attacks by not exposing a CBC-only API.
5. **Decrypt after verification principle** — Does not output plaintext before passing the constant-time verification of both the GCM tag and the CBC HMAC.
6. **Immediate erasure of key material** — `KeySchedule`, `GHashState`, and block operation intermediate values are all erased immediately after use with `write_volatile`.
