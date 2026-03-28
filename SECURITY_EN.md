# Security Policy

> [Korean SECURITY](SECURITY.md)

`entlib-native` strictly adheres to the Zero-Trust principle.

We take your security vulnerability reports very seriously, and any issues found will be treated as a top priority.

## Reporting a Vulnerability

If you discover a complex security vulnerability, data residue issue, or memory-related problem, **NEVER post it publicly on GitHub Issues!** Instead, please report it privately by following the procedure below.

### How to Report

1. Contact me directly via email at <qtfelix@qu4nt.space>.
2. Please include `[SECURITY] entlib-native Vulnerability Report [GITHUB USERNAME]` in the email subject line.
3. If possible, please include the following information:
   * The type of vulnerability (constant-time issue, timing issue, memory data residue, FFI boundary check bypass, cryptographic algorithm implementation error, etc.)
   * How to reproduce it (PoC code or step-by-step description)
   * Detailed information about the affected version and environment (OS, computer hardware information, Java, Rust version, etc.)

> [!NOTE]
> If you need a PGP key for secure communication, please check the [KEYS](KEYS) file in the repository or request it.

## Security Focus Areas

This project places particular importance on security in the following areas:

* **Memory Erasure:** Whether sensitive data (keys, plaintext, seeds, etc.) is immediately and reliably erased from memory after use. The integrity of the erasure logic through the `Drop` trait and `write_volatile`.
* **Constant-Time Operations:** Whether operations that depend on secret keys or data are performed in a constant time regardless of the input value. Resistance to timing attacks.
* **Random Number Generation:** The correct use and safety of OS hardware entropy.
* **FFI Boundaries:** Issues that can occur during data exchange between Java and Rust, such as memory corruption, `null` pointer dereferencing, buffer overflows, and lack of filtering.
* **Cryptographic Correctness:** Whether the implemented cryptographic algorithms accurately comply with standard specifications (`NIST FIPS`, `SP`, etc.).
* **Cryptographic Correctness (Cryptographic Module):** Whether the Entanglement Library (Java), `entlib-native` (Rust), individually or as a mixed cryptographic module, accurately complies with `FIPS 140-2/3`.

## Out of Scope

The following items are generally excluded from security vulnerability reports, but may be reviewed in serious cases:

* **Simple Performance Issues:** Simple performance degradation that does not affect security (except in cases that could lead to a `DoS` attack).
* **Typos in Documentation:** Simple typos or grammatical errors that do not cause technical misunderstandings.
* **Experimental Features:** Bugs in features explicitly marked as "Experimental".
* **User Environment Issues:** Problems caused by defects in the user's OS or hardware itself.

> [!TIP]
> You can find more details in the [Contribution Document](CONTRIBUTION_EN.md).

## Acknowledgments

If the issue is confirmed as a vulnerability, we will issue a security advisory and include your contribution in the list of contributors. If you wish, we can also include your name and contact information in the list of contributors.

We would like to thank in advance all security researchers and developers who have contributed to strengthening the security of the Entanglement Library.