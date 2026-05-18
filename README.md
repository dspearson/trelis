# Trelis

An experimental Rust implementation of a hybrid post-quantum cryptographic protocol for end-to-end encrypted messaging.

## Warning

This software is unaudited and should not be used in production systems. The cryptographic constructions have not been formally verified. Use at your own risk.

## Overview

Trelis combines classical elliptic curve cryptography with post-quantum lattice-based algorithms. The intent is to provide security against both classical and potential future quantum computing attacks by requiring an attacker to break both cryptographic schemes.

The protocol specification is available at: https://trelis.technoanimal.net/trelis.pdf

## Crate Structure

| Crate | Description |
|-------|-------------|
| `trelis-primitives` | Low-level cryptographic operations (AEAD, KDF, sntrup761) |
| `trelis-hybrid` | Hybrid signature and KEM combining classical and PQ algorithms |
| `trelis-wire` | Wire format encoding/decoding |
| `trelis-x3dh-pq` | Post-quantum extended triple Diffie-Hellman key agreement |
| `trelis-ratchet` | Per-message KEM ratchet for forward secrecy |
| `trelis-cocoa` | CoCoA-SA group key agreement protocol |
| `trelis-multidevice` | Multi-device key synchronisation and history sharing |
| `trelis-wasm` | WebAssembly bindings |
| `trelis-error` | Error types |

## Cryptographic Primitives

| Purpose | Classical | Post-Quantum |
|---------|-----------|--------------|
| Signatures | Ed448 (RFC 8032) | ML-DSA-65 (FIPS 204) |
| Key Exchange | X448 (RFC 7748) | sntrup761 (NTRU Prime) |
| AEAD | XChaCha20-Poly1305 | - |
| KDF | BLAKE3 | - |

Hybrid operations combine both classical and post-quantum components. Security depends on the stronger of the two schemes remaining unbroken.

## Features

- **Hybrid post-quantum cryptography**: every signature and KEM operation
  combines a classical primitive (Ed448 or X448) with a post-quantum
  primitive (ML-DSA-65 or sntrup761). An attacker must break both.
- **Hedged ML-DSA-65 signing**: combines the deterministic FIPS 204 nonce
  with fresh randomness as defence-in-depth against PRNG failure.
- **X3DH-PQ** for session establishment, with a typed-state builder that
  prevents mixing signed and unsigned prekey bundles at the API level.
- **KEM ratchet** providing per-message forward secrecy via a fresh hybrid
  encapsulation on every send.
- **CoCoA-SA group messaging** with per-sender message chains and
  sender-bound AAD — two members at the same `(epoch, counter)` derive
  disjoint keys, eliminating the cross-sender nonce-reuse risk.
- **Multi-device support**: self-verifying `DeviceApprovalCertificate` (the
  approving device's public key is embedded in the cert body), wrapped
  key delivery to new devices, history-key synchronisation, and signed
  revocation certificates.
- **Identity certificates and recovery**: issuer-signed `IdentityCertificate`,
  `CertifiedSafetyNumber`, and `RecoveryKeyAttestation` for offline
  identity verification and account recovery.
- **Hardware-attested identity**: seeded keypair derivation for callers
  that obtain entropy from an HSM, secure element, or other attested
  source.
- **Memory hygiene**: `ZeroizeOnDrop` on every secret type, `Zeroizing<>`
  wrappers around all KDF outputs, and optional `mlock`-backed
  `LockedBox` / `GuardedBox` containers behind the `mlock` feature.
- **`no_std` support** for embedded and WASM environments; `wasm-bindgen`
  bindings published as the `trelis-wasm` crate.

## Building

Requires Rust 2024 edition.

```
cargo build --release
cargo test --workspace
```

For WASM builds:

```
cargo build --target wasm32-unknown-unknown -p trelis-wasm
```

### Development Environment

A Nix flake is provided for reproducible development environments. With Nix installed:

```
nix develop
```

This automatically provides all required dependencies and tooling.

## Limitations

- No formal security proof
- No side-channel analysis performed
- sntrup761 uses either C FFI or pure Rust backend depending on target
- Not suitable for production use without audit

## Licence

ISC License. See [LICENCE](LICENCE) for details.

Third-party dependency licences are listed in [3RD-PARTY-LICENCES.md](3RD-PARTY-LICENCES.md).

## References

- [Trelis Protocol Specification](https://trelis.technoanimal.net/trelis.pdf)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
- [RFC 7748 - Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
- [FIPS 204 - Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NTRU Prime](https://ntruprime.cr.yp.to/)
- [CoCoA: Concurrent Continuous Group Key Agreement](https://eprint.iacr.org/2022/251)
