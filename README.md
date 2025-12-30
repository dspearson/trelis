# Trelis

A Rust implementation of the Trelis hybrid post-quantum cryptographic protocol.

## Overview

Trelis is a hybrid cryptographic protocol designed for secure end-to-end encrypted messaging. It combines classical elliptic curve cryptography with post-quantum lattice-based algorithms to provide security against both current and future quantum computing threats.

The protocol specification is available at: https://trelis.technoanimal.net/trelis.pdf

## Design Goals

- **Hybrid Post-Quantum Security**: Pair classical algorithms (Ed448, X448) with post-quantum alternatives (ML-DSA-65, sntrup761) so that security is maintained even if one class is broken
- **Forward Secrecy**: Session keys are ephemeral and regularly rotated via the Double Ratchet protocol
- **Group Messaging**: Efficient group encryption using CoCoA-SA (Continuous Group Key Agreement with Server Assist)
- **Multi-Device Support**: Seamless key synchronisation across user devices
- **no_std Compatible**: Core cryptographic primitives work in embedded and WASM environments
- **Memory Safety**: Pure Rust implementation with automatic zeroisation of secret material

## Cryptographic Primitives

| Purpose | Classical | Post-Quantum |
|---------|-----------|--------------|
| Signatures | Ed448 (RFC 8032) | ML-DSA-65 (FIPS 204) |
| Key Exchange | X448 (RFC 7748) | sntrup761 (NTRU Prime) |
| AEAD | XChaCha20-Poly1305 | |
| KDF | BLAKE3 | |

## Licence

ISC License. See [LICENCE](LICENCE) for details.

## References

- [Trelis Protocol Specification](https://trelis.technoanimal.net/trelis.pdf)
- [RFC 8032 - Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
- [RFC 7748 - Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
- [FIPS 204 - Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [NTRU Prime](https://ntruprime.cr.yp.to/)
