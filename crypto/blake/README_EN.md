# BLAKE2b / BLAKE3 Hash Functions (entlib-native-blake)

> Q. T. Felix (Modified: 26.03.23 UTC+9)
>
> [Korean README](README.md)

`entlib-native-blake` is a `no_std` compatible hash crate that complies with RFC 7693 (BLAKE2b) and the official BLAKE3 specification. Sensitive data is stored in `SecureBuffer` (mlock), and the internal state is forcibly erased with `write_volatile` on Drop.

## Configuration

| Module    | Algorithm          | Standard                      |
|-----------|--------------------|-------------------------------|
| `blake2b` | BLAKE2b            | RFC 7693                      |
| `blake3`  | BLAKE3             | BLAKE3 Official Specification |
| `lib`     | H'(`blake2b_long`) | RFC 9106 Section 3.2          |

---

## BLAKE2b

A cryptographic hash function optimized for 64-bit platforms. It generates a digest of up to 512 bits (64 bytes) and supports a keyed MAC mode.

### Struct

```rust
pub struct Blake2b {
    h: [u64; 8],          // Chaining values (8 × 64-bit)
    t: [u64; 2],          // Byte counter
    buf: SecureBuffer,    // 128-byte input buffer (mlock)
    buf_len: usize,
    hash_len: usize,      // 1..=64
}
```

### Initialization Vector and Parameter Block

The IV is derived from the SHA-512 initial hash values (fractional parts of the square roots of the first eight primes).

$$h_0 = \text{IV}[0] \oplus (\text{hash\_len} \mathbin{|} (\text{key\_len} \mathbin{\ll} 8) \mathbin{|} (1 \mathbin{\ll} 16) \mathbin{|} (1 \mathbin{\ll} 24))$$

In keyed mode, the key is zero-padded to a 128-byte block and processed as the first block by setting `buf_len = 128`.

### Compression Function

It uses a 12-round Feistel structure, and each round applies the G function to the message words sorted according to the SIGMA permutation.

**G Function (Rotations: 32 / 24 / 16 / 63)**

$$a \mathrel{+}= b + x, \quad d = (d \oplus a) \ggg 32$$
$$c \mathrel{+}= d, \quad b = (b \oplus c) \ggg 24$$
$$a \mathrel{+}= b + y, \quad d = (d \oplus a) \ggg 16$$
$$c \mathrel{+}= d, \quad b = (b \oplus c) \ggg 63$$

The 16-word working vector $v$ is initialized with the chaining values $h[0..8]$, the IV, the counter $t$, and the finalization flag $f$.

$$v[12] = \text{IV}[4] \oplus t[0], \quad v[13] = \text{IV}[5] \oplus t[1]$$
$$v[14] = \text{IV}[6] \oplus f[0], \quad v[15] = \text{IV}[7] \oplus f[1]$$

After 12 rounds, the chaining values are updated.

$$h[i] \mathrel{\oplus}= v[i] \oplus v[i+8], \quad i \in [0, 7]$$

### Finalization

When processing the last block, $f[0] = \texttt{0xFFFF\_FFFF\_FFFF\_FFFF}$ is set. The counter is incremented by `buf_len`, and the rest of the buffer is zero-padded. The result is extracted from $h$ in LE byte order.

### Memory Security

On Drop, `h[0..8]`, `t[0..2]`, and `buf_len` are erased with `write_volatile`, and `compiler_fence(SeqCst)` prevents reordering.

---

## blake2b_long (H')

A variable-output hash function defined in RFC 9106 Section 3.2. It is used for Argon2id block initialization and final tag generation.

**Input**: `LE32(T) || input`, **Output**: T bytes

$$A_1 = \text{BLAKE2b-64}(\mathtt{LE32}(T) \mathbin{\|} \text{input})$$

- $T \le 64$: Single `BLAKE2b-T` call

- $T > 64$: $r = \lceil T/32 \rceil - 2$, $\text{last\_len} = T - 32r$

$$A_i = \text{BLAKE2b-64}(A_{i-1}), \quad i = 2, \ldots, r$$
$$A_{r+1} = \text{BLAKE2b-last\_len}(A_r)$$

$$\text{output} = A_1[0..32] \mathbin{\|} A_2[0..32] \mathbin{\|} \cdots \mathbin{\|} A_r[0..32] \mathbin{\|} A_{r+1}$$

The intermediate values of each step are stored in `SecureBuffer`.

---

## BLAKE3

A modern hash function based on a Merkle tree structure. Its design goals are parallel processing through SIMD and multi-threading, and it supports an arbitrary-length XOF in addition to a 32-byte fixed output.

### Struct

```rust
pub struct Blake3 {
    chunk_state: ChunkState,      // Current chunk state
    key_words: [u32; 8],          // IV or key words
    cv_stack: [[u32; 8]; 54],     // Chaining value stack (max 54 levels)
    cv_stack_len: usize,
    flags: u32,
}
```

The chunk size is 1024 bytes, and the maximum depth of the CV stack, 54, covers an input size of $2^{54}$ KiB (about 18 EiB).

### Domain Separation Flags

| Flag          | Value    | Purpose                 |
|---------------|----------|-------------------------|
| `CHUNK_START` | `1 << 0` | First block of a chunk  |
| `CHUNK_END`   | `1 << 1` | Last block of a chunk   |
| `PARENT`      | `1 << 2` | Parent node compression |
| `ROOT`        | `1 << 3` | Root output generation  |
| `KEYED_HASH`  | `1 << 4` | Keyed mode              |

### Compression Function

Performs a 32-bit word-based, 7-round compression. It initializes a 16-word state vector and applies the G function and message permutation in each round.

$$\text{state} = [cv[0..8], \text{IV}[0..4], \text{ctr\_lo}, \text{ctr\_hi}, \text{block\_len}, \text{flags}]$$

**G Function (Rotations: 16 / 12 / 8 / 7)**

$$a \mathrel{+}= b + x, \quad d = (d \oplus a) \ggg 16$$
$$c \mathrel{+}= d, \quad b = (b \oplus c) \ggg 12$$
$$a \mathrel{+}= b + y, \quad d = (d \oplus a) \ggg 8$$
$$c \mathrel{+}= d, \quad b = (b \oplus c) \ggg 7$$

After each round, the message words are rearranged according to `MSG_PERMUTATION`. After 7 rounds are complete:

$$\text{state}[i] \mathrel{\oplus}= \text{state}[i+8], \quad \text{state}[i+8] \mathrel{\oplus}= cv[i]$$

### Tree Hashing and CV Stack

The input is processed in 1024-byte chunks, and the chaining value (CV) of each chunk is accumulated on the stack. `merge_cv_stack` maintains the popcount invariant of the number of accumulated chunks (`total_chunks`) and generates parent nodes.

```
When total_chunks = 4 (binary: 100):
  Stack: [CV_0, CV_1, CV_2, CV_3]
  → merge: parent(CV_2, CV_3) → P_23
  → merge: parent(CV_0, CV_1) → P_01
  → merge: parent(P_01, P_23) → root
```

This design allows the construction of a Merkle tree in a single pass without knowing the message length in advance.

### XOF (eXtendable-Output Function)

Generates an arbitrary-length output by setting the `ROOT` flag on the root node and incrementing the counter.

$$\text{output}[64k .. 64k+64] = \text{compress}(cv_\text{root}, bw, k, bl, \text{flags} \mathbin{|} \text{ROOT}), \quad k = 0, 1, 2, \ldots$$

### Memory Security

On Drop, the entire `key_words` and `cv_stack` are erased with `write_volatile`. On `ChunkState` Drop, `buf` and `chaining_value` are also erased.

---

## Usage Example

```rust
use entlib_native_blake::{Blake2b, Blake3, blake2b_long};

// BLAKE2b-32
let mut h = Blake2b::new(32);
h.update(b"hello world");
let digest = h.finalize().unwrap();
assert_eq!(digest.as_slice().len(), 32);

// BLAKE3 (32 bytes)
let mut h = Blake3::new();
h.update(b"hello world");
let digest = h.finalize().unwrap();
assert_eq!(digest.as_slice().len(), 32);

// H' — for Argon2id block initialization (1024 bytes)
let out = blake2b_long(b"input", 1024).unwrap();
assert_eq!(out.as_slice().len(), 1024);
```

## Dependencies

| Crate                         | Purpose                          |
|-------------------------------|----------------------------------|
| `entlib-native-secure-buffer` | mlock storage for sensitive data |
| `entlib-native-constant-time` | Constant-time operations         |
