# Hash_DRBG Crate (entlib-native-rng)

> Q. T. Felix (Modified: 26.03.21 UTC+9)
> 
> [Korean README](README.md)

`entlib-native-rng` is a `no_std` compatible crate that implements the Hash_DRBG (Hash-based Deterministic Random Bit Generator) specified in Section 10.1.1 of NIST SP 800-90A Rev. 1. This crate is designed based on the FIPS 140-3 approved algorithm requirements and has built-in defense against memory dump and cold boot attacks by managing its internal state with `SecureBuffer`.

## Security Threat Model

The security of a DRBG depends on three key properties.

**Unpredictability**: An attacker should not be able to predict the next output even if they have observed all previous outputs. Hash_DRBG ensures this by not directly exposing the internal states $V$ and $C$ in the output, but only deriving the output through a one-way hash function.

**State Recovery Resistance**: Even if the internal states $V$ and $C$ are exposed, it should not be possible to reverse-calculate the previous outputs. Both values are isolated in `SecureBuffer`, to which OS-level memory locking (`mlock`) and forced erasure at the time of Drop are applied.

**Mandatory Reseed**: If the reseed counter exceeds $2^{48}$, `generate` immediately returns `ReseedRequired`. This structurally blocks the generation of an excessive amount of output from the same state.

## Architecture

```
entlib-native-rng
├── os_entropy   (internal module)  — Platform-specific OS entropy extraction
└── hash_drbg    (internal module)  — NIST SP 800-90A Hash_DRBG implementation
    ├── HashDRBGSHA224   (security_strength = 112 bits)
    ├── HashDRBGSHA256   (security_strength = 128 bits)
    ├── HashDRBGSHA384   (security_strength = 192 bits)
    └── HashDRBGSHA512   (security_strength = 256 bits)
```

The only public initialization path is `new_from_os`. `instantiate`, which allows the user to inject entropy directly, is restricted to `pub(crate)` to fundamentally block the risk of predictable seed injection.

## OS Entropy Source

`extract_os_entropy` collects raw entropy through platform-specific direct syscalls or verified library functions. It does not depend on external crates such as `getrandom`.

| Target                     | Method                                                      |
|----------------------------|-------------------------------------------------------------|
| `linux + x86_64`           | `SYS_getrandom` (318), direct call to `syscall` instruction |
| `linux + aarch64`          | `SYS_getrandom` (278), direct call to `svc #0` instruction  |
| `macos` (x86_64 / aarch64) | `getentropy(2)` — libSystem FFI                             |

The Linux implementation always completely fills `size` bytes, including `EINTR` retries and partial read loops. macOS's `getentropy` guarantees a complete fill with a single call and has a maximum limit of 256 bytes, but the maximum size requested by `new_from_os` ($2 \times 32 = 64$ bytes for SHA-512) does not exceed this.

The collected entropy and nonce are returned as `SecureBuffer` and are automatically erased at the time of Drop after `instantiate` is complete.

## Hash_DRBG Specification

### NIST SP 800-90A Rev. 1, Table 2 Parameters

| Instance         | Hash    | outlen | seedlen | security_strength | Minimum Entropy |
|------------------|---------|--------|---------|-------------------|-----------------|
| `HashDRBGSHA224` | SHA-224 | 28 B   | 55 B    | 112 bits          | 14 B            |
| `HashDRBGSHA256` | SHA-256 | 32 B   | 55 B    | 128 bits          | 16 B            |
| `HashDRBGSHA384` | SHA-384 | 48 B   | 111 B   | 192 bits          | 24 B            |
| `HashDRBGSHA512` | SHA-512 | 64 B   | 111 B   | 256 bits          | 32 B            |

### Hash_df (Section 10.3.1)

The Hash Derivation Function derives exactly `no_of_bytes_to_return` bytes from a concatenation of inputs of arbitrary length.

```math
V = \text{Hash\_df}(\text{entropy\_input} \| \text{nonce} \| \text{personalization\_string} \text{seedlen})
```

Internally, it repeats $m = \lceil \text{seedlen} / \text{outlen} \rceil$ times, and in each iteration, it calculates the hash with a counter byte and the number of bits (big-endian 4 bytes) as a prefix.

```math
\text{Hash\_df}[i] = H(\text{counter}_i \| \text{no\_of\_bits\_to\_return} \| \text{input\_string})
```

### Instantiate (Section 10.1.1.2)

Initializes the internal states $V$ and $C$ with the entropy input, nonce, and personalization string.

```math
V = \text{Hash\_df}(\text{entropy\_input} \| \text{nonce} \| \text{personalization\_string},\ \text{seedlen})
```

```math
C = \text{Hash\_df}(\texttt{0x00} \| V,\ \text{seedlen})
```

`new_from_os` collects $2 \times \text{security\_strength}$ bytes for entropy_input and $\text{security\_strength}$ bytes for nonce with **two separate calls** to the OS to ensure nonce independence.

### Reseed (Section 10.1.1.3)

Updates the internal state with new entropy.

```math
V' = \text{Hash\_df}(\texttt{0x01} \| V \| \text{entropy\_input} \| \text{additional\_input},\ \text{seedlen})
```

```math
C' = \text{Hash\_df}(\texttt{0x00} \| V',\ \text{seedlen})
```

The intermediate stack buffers (`new_v`, `new_c`) are forcibly erased with `write_volatile` after the operation is complete.

### Generate (Section 10.1.1.4)

Generates up to $2^{19}$ bits (65,536 bytes) of pseudorandom numbers per request. If `additional_input` is given, the internal state is updated first.

**additional_input processing**:

```math
w = H(\texttt{0x02} \| V \| \text{additional\_input})
```
```math
V \leftarrow (V + w_{\text{padded}}) \bmod 2^{\text{seedlen} \times 8}
```

**Output generation (Hashgen)**:

Copies the internal counter $\text{data} = V$ and hashes it $\lceil \text{requested\_bytes} / \text{outlen} \rceil$ times.

```math
W_i = H(\text{data} + i - 1),\quad \text{starting value of data} = V
```

**State update**:

```math
H = H(\texttt{0x03} \| V)
```
```math
V \leftarrow (V + H_{\text{padded}} + C + \text{reseed\_counter}) \bmod 2^{\text{seedlen} \times 8}
```

### Modular Addition (add_mod / add_u64_mod)

The internal state $V$ is represented as a big-endian byte array. `add_mod` is implemented as a pure arithmetic operation that propagates the carry from the low index (high byte), so **there are no branches that depend on the value of the secret data**.

> [!NOTE]
> **Constant-Time Invariant**: The number of iterations is always fixed to `seedlen` (a public constant).
> 
> The carry is only handled by `u16` arithmetic masking and does not cause conditional branches.

## Memory Security

The internal states $V$ and $C$ are allocated as `SecureBuffer`. `SecureBuffer` pins the corresponding page to a non-swappable area with OS `mlock` and performs `write_volatile`-based erasure at the time of Drop. `reseed_counter` is separately erased with `write_volatile` within the `Drop` implementation.

Intermediate values copied to the stack (`new_v`, `new_c`, `c_copy`, `h_padded`, `w_padded`, `data`) are all erased with a `write_volatile` loop immediately after the operation is complete to prevent stack residue data attacks.

## Error Enum (DrbgError)

| Variant             | Condition of Occurrence                  |
|---------------------|------------------------------------------|
| `EntropyTooShort`   | entropy_input < security_strength bytes  |
| `EntropyTooLong`    | input length > $2^{32}$ bytes            |
| `NonceTooShort`     | nonce < security_strength / 2 bytes      |
| `InputTooLong`      | additional_input > $2^{32}$ bytes        |
| `InvalidArgument`   | no_of_bits calculation overflow          |
| `ReseedRequired`    | reseed_counter > $2^{48}$                |
| `AllocationFailed`  | SecureBuffer allocation or mlock failure |
| `InternalHashError` | Internal error in the hash function      |
| `RequestTooLarge`   | Request size > 65,536 bytes              |
| `OsEntropyFailed`   | Failed to access OS entropy source       |

## Usage Example

```rust
use entlib_native_rng::{HashDRBGSHA256, DrbgError};

fn generate_key() -> Result<[u8; 32], DrbgError> {
    // Initialize with OS entropy — the only allowed external initialization path
    let mut drbg = HashDRBGSHA256::new_from_os(Some(b"myapp-keygen-v1"))?;

    let mut key = [0u8; 32];
    drbg.generate(&mut key, None)?;
    Ok(key)
}
```

Reseed example

```rust
use entlib_native_rng::{HashDRBGSHA512, DrbgError};

fn generate_with_reseed() -> Result<(), DrbgError> {
    let mut drbg = HashDRBGSHA512::new_from_os(None)?;
    let mut buf = [0u8; 64];

    loop {
        match drbg.generate(&mut buf, None) {
            Ok(()) => break,
            Err(DrbgError::ReseedRequired) => {
                // Reseed with OS entropy and retry
                let entropy = [0u8; 32]; // In a real implementation, use OS entropy
                drbg.reseed(&entropy, None)?;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
```

## Summary of Design Principles

This crate applies a three-level security design.

1. **Standard Compliance**: It accurately implements the Hash_DRBG algorithm of NIST SP 800-90A Rev. 1 at each specification step and enforces the parameters of Table 2 at the macro level.
2. **Memory Isolation**: It isolates the secret internal states $V$ and $C$ in `SecureBuffer` and immediately erases stack copies with `write_volatile` to minimize the memory residue attack surface.
3. **Entropy Integrity**: It restricts the only initialization path to `new_from_os` and collects entropy_input and nonce with separate OS calls to prevent external attackers from controlling the seed.
