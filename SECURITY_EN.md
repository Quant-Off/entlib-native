# Security Policy

> [Korean SECURITY](SECURITY.md)

The native library of this EntanglementLib has "military-grade security" and "Anti-Data Remanence" as its core philosophies. We take your security vulnerability reports very seriously, and discovered issues are handled with the highest priority.

## Reporting a Vulnerability

If you have discovered a security vulnerability, sensitive data remanence issue, or memory-related problem in this native library, **please DO NOT post it publicly on GitHub Issues!** Instead, please report it privately according to the procedure below.

### How to Report

1. Contact me directly via email at <qtfelix@qu4nt.space>.
2. Please include `[SECURITY] entlib-native Vulnerability Report [GITHUB USERNAME]` in the email subject.
3. If possible, please include the following information:
    * Type of vulnerability (timing issue, key remanence in memory dump, FFI boundary check bypass, PQC algorithm implementation error, etc.)
    * Reproduction method (PoC code or step-by-step description)
    * Detailed information of the affected version and environment (OS, computer hardware information, Java version, etc.)

> [!NOTE]
> If a PGP key is required for secure communication, please check the `KEYS` file in the repository or request it.

### Handling Procedure

Reported vulnerabilities are handled according to the following procedure:

1. **Receipt Confirmation:** A receipt confirmation email is sent to the reporter within 48 hours.
2. **Analysis and Verification:** The Quant team internally analyzes the impact and reproducibility of the vulnerability in detail.
3. **Patch Development:** If the issue is confirmed, a hotfix for `entlib-native` or `entanglementlib` is developed.
4. **Disclosure and Deployment:** After the patch is completed and released, the vulnerability information is disclosed at an appropriate time in consultation with the reporter.

## Security Focus Areas

This project particularly considers security in the following areas important:

* **Memory Erasure:** Whether sensitive data (keys, plaintexts, random seeds, etc.) are immediately and certainly erased from memory after use. Integrity of erasure logic through `Drop` trait and `write_volatile`.
* **Constant-Time Operations:** Whether operations dependent on secret keys or data are performed in constant time regardless of input values. Resistance to Timing Attacks.
* **Random Number Generation:** Correct use of hardware entropy (`rdseed`, `rdrand`, `rndr`) and safety of non-linear mixing logic of `MixedRng`.
* **FFI Boundaries:** Problems such as memory corruption, null pointer dereference, and buffer overflow that may occur during data exchange between Java and Rust.
* **Cryptographic Correctness:** Whether implemented algorithms (`SHA-2`, `SHA-3`, `Base64`, etc.) accurately comply with standard specifications (`NIST FIPS`, `SP`, etc.).

## Out of Scope

The following items are generally excluded from security vulnerability reports, but may be reviewed in serious cases:

* **Simple Performance Issues:** Simple performance degradation that does not affect security (except when it can lead to `DoS` attacks).
* **Typos in Documentation:** Simple typos or grammatical errors that do not cause technical misunderstandings.
* **Experimental Features:** Bugs in features explicitly marked as "Experimental".
* **User Environment Issues:** Problems caused by defects in the user's OS or hardware itself.

## Acknowledgements

If the issue is confirmed as a vulnerability, we will publish a security advisory and include your contribution in the contributors list. If you wish, we can also list your name and contact information in the contributors list.

We thank in advance all security researchers and developers who have contributed to enhancing the security of the Entanglement Library.