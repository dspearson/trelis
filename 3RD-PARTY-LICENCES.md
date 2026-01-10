# Third-Party Licences

This file lists the licences of all third-party dependencies used by Trelis,
including inlined code and protocol designs that influenced this project.

Generated: 

---

## Inlined and Adapted Code

The following projects have been inlined, adapted, or substantially influenced
the implementation of Trelis. These are not external crate dependencies but
are credited here for their contributions.

### ML-DSA Implementation (MIT)

The `mldsa_core` module is derived from the RustCrypto ML-DSA implementation.
The code has been modified to support pluggable hash functions (SHAKE and BLAKE3).

- **Source**: https://github.com/RustCrypto/signatures/tree/master/ml-dsa
- **Licence**: MIT
- **Copyright**: Copyright (c) 2024-2025 RustCrypto Developers

### Memory Protection (MIT)

The `memlock` module is derived from dryoc's protected memory implementation.
The code has been adapted for Trelis's memory protection requirements.

- **Source**: https://github.com/brndnmtthws/dryoc/blob/main/src/protected.rs
- **Licence**: MIT
- **Copyright**: Copyright (c) 2024 Brenden Matthews

### MIT Licence Text (applies to above)

```
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Protocol Designs and Academic References

The following protocols and academic works have influenced the design of Trelis.
No code was directly copied, but the protocol structures are derived from or
inspired by these works.

### CoCoA: Concurrent Continuous Group Key Agreement

The `trelis-cocoa` crate implements a server-assisted variant of the CoCoA
protocol for group key agreement.

- **Paper**: "CoCoA: Concurrent Continuous Group Key Agreement"
- **Authors**: Joël Alwen, Benedikt Auerbach, Miguel Cueto Noval,
  Karen Klein, Guillermo Pascual-Perez, Krzysztof Pietrzak
- **Published**: EUROCRYPT 2022
- **Link**: https://eprint.iacr.org/2022/251

### X3DH: Extended Triple Diffie-Hellman

The `trelis-x3dh-pq` crate extends the X3DH protocol with post-quantum security.

- **Specification**: "The X3DH Key Agreement Protocol"
- **Author**: Moxie Marlinspike, Trevor Perrin (Open Whisper Systems)
- **Version**: Revision 1, 2016-11-04
- **Link**: https://signal.org/docs/specifications/x3dh/

### Signal Double Ratchet (Design Influence)

The `trelis-ratchet` crate uses a per-message KEM ratchet design that differs
from Signal's double ratchet, but was informed by Signal's security analysis.

- **Specification**: "The Double Ratchet Algorithm"
- **Author**: Trevor Perrin, Moxie Marlinspike (Open Whisper Systems)
- **Version**: Revision 1, 2016-11-20
- **Link**: https://signal.org/docs/specifications/doubleratchet/

---

## Cargo Dependency Licence Summary

| Licence | Crates |
|---------|--------|
| Apache License 2.0 | ciborium-io, ciborium-ll, ciborium |
| Apache License 2.0 | blake3, constant_time_eq, dunce |
| BSD 2-Clause &quot;Simplified&quot; License | arrayref |
| BSD 3-Clause &quot;New&quot; or &quot;Revised&quot; License | subtle |
| BSD 3-Clause &quot;New&quot; or &quot;Revised&quot; License | ed448-goldilocks-plus |
| ISC License | ntrulp |
| ISC License | trelis-cocoa, trelis-error, trelis-hybrid, trelis-integration-tests, trelis-multidevice, trelis-primitives, trelis-ratchet, trelis-wasm, trelis-wire, trelis-x3dh-pq |
| MIT License | sha3 |
| MIT License | sha2 |
| MIT License | rayon-core, rayon |
| MIT License | hex |
| MIT License | cc, cfg-if, find-msvc-tools, jobserver, js-sys, wait-timeout, wasm-bindgen-futures, wasm-bindgen-macro-support, wasm-bindgen-macro, wasm-bindgen-shared, wasm-bindgen-test-macro, wasm-bindgen-test, wasm-bindgen, web-sys |
| MIT License | errno |
| MIT License | criterion-plot, criterion |
| MIT License | base64ct |
| MIT License | base16ct |
| MIT License | bitflags, glob, num-traits, regex-automata, regex-syntax, regex |
| MIT License | cast |
| MIT License | libc |
| MIT License | either, itertools |
| MIT License | tempfile |
| MIT License | quick-error |
| MIT License | poly1305 |
| MIT License | minicov |
| MIT License | proptest, rusty-fork |
| MIT License | cipher |
| MIT License | digest |
| MIT License | fnv |
| MIT License | digest |
| MIT License | autocfg |
| MIT License | block-buffer |
| MIT License | keccak, keccak |
| MIT License | signature |
| MIT License | opaque-debug |
| MIT License | getrandom |
| MIT License | signature |
| MIT License | rand_core |
| MIT License | block-buffer |
| MIT License | hex-literal |
| MIT License | getrandom |
| MIT License | tinytemplate |
| MIT License | bumpalo |
| MIT License | ppv-lite86 |
| MIT License | chacha20poly1305 |
| MIT License | aead |
| MIT License | universal-hash |
| MIT License | chacha20 |
| MIT License | elliptic-curve, fips204 |
| MIT License | const-oid |
| MIT License | der, pkcs8 |
| MIT License | cpufeatures |
| MIT License | sha3 |
| MIT License | crypto-common |
| MIT License | crypto-bigint, pem-rfc7468 |
| MIT License | sec1 |
| MIT License | spki |
| MIT License | crypto-common |
| MIT License | inout |
| MIT License | hybrid-array |
| MIT License | bit-set, bit-vec |
| MIT License | anstyle, clap, clap_builder, clap_lex |
| MIT License | arrayvec |
| MIT License | rand, rand, rand_chacha, rand_chacha, rand_core, rand_core, rand_xorshift |
| MIT License | zerocopy-derive, zerocopy |
| MIT License | tap |
| MIT License | bitvec, wyz |
| MIT License | zeroize |
| MIT License | radium |
| MIT License | zeroize_derive |
| MIT License | funty |
| MIT License | serdect, serdect |
| MIT License | anes, libm, plotters-backend, plotters-svg, plotters, pqcrypto-internals, pqcrypto-traits, r-efi, wasip2, windows-link, windows-sys |
| MIT License | pqcrypto-ntruprime |
| MIT License | unarray |
| MIT License | half |
| MIT License | async-trait, fastrand, group, hermit-abi, is-terminal, itoa, linux-raw-sys, once_cell, proc-macro2, quote, rustix, rustversion, serde, serde_core, serde_derive, serde_json, syn, unicode-ident, wasi, wit-bindgen, zmij |
| MIT License | typenum |
| MIT License | memchr, walkdir |
| MIT License | shlex |
| MIT License | same-file, winapi-util |
| MIT License | ff |
| MIT License | oorandom |
| MIT License | crossbeam-deque, crossbeam-epoch, crossbeam-utils |
| MIT License | crunchy |
| MIT License | version_check |
| MIT License | nu-ansi-term |
| MIT License | generic-array |
| Unicode License v3 | unicode-ident |

---

## Crate Details

### Apache License 2.0

- **ciborium-io** (0.2.2) - [source](https://github.com/enarx/ciborium)
- **ciborium-ll** (0.2.2) - [source](https://github.com/enarx/ciborium)
- **ciborium** (0.2.2) - [source](https://github.com/enarx/ciborium)

### Apache License 2.0

- **blake3** (1.8.3) - [source](https://github.com/BLAKE3-team/BLAKE3)
- **constant_time_eq** (0.4.2) - [source](https://github.com/cesarb/constant_time_eq)
- **dunce** (1.0.5) - [source](https://gitlab.com/kornelski/dunce)

### BSD 2-Clause &quot;Simplified&quot; License

- **arrayref** (0.3.9) - [source](https://github.com/droundy/arrayref)

### BSD 3-Clause &quot;New&quot; or &quot;Revised&quot; License

- **subtle** (2.6.1) - [source](https://github.com/dalek-cryptography/subtle)

### BSD 3-Clause &quot;New&quot; or &quot;Revised&quot; License

- **ed448-goldilocks-plus** (0.16.0) - [source](https://github.com/mikelodder7/Ed448-Goldilocks)

### ISC License

- **ntrulp** (0.2.3) - [source](https://github.com/openzebra/ntrulp)

### ISC License

- **trelis-cocoa** (0.1.0) - [source](https://github.com/dspearson/trelis)
- **trelis-error** (0.1.0)
- **trelis-hybrid** (0.1.0)
- **trelis-integration-tests** (0.1.0)
- **trelis-multidevice** (0.1.0) - [source](https://github.com/dspearson/trelis)
- **trelis-primitives** (0.1.0)
- **trelis-ratchet** (0.1.0)
- **trelis-wasm** (0.1.0)
- **trelis-wire** (0.1.0)
- **trelis-x3dh-pq** (0.1.0)

### MIT License

- **sha3** (0.10.8) - [source](https://github.com/RustCrypto/hashes)

### MIT License

- **sha2** (0.10.9) - [source](https://github.com/RustCrypto/hashes)

### MIT License

- **rayon-core** (1.13.0) - [source](https://github.com/rayon-rs/rayon)
- **rayon** (1.11.0) - [source](https://github.com/rayon-rs/rayon)

### MIT License

- **hex** (0.4.3) - [source](https://github.com/KokaKiwi/rust-hex)

### MIT License

- **cc** (1.2.52) - [source](https://github.com/rust-lang/cc-rs)
- **cfg-if** (1.0.4) - [source](https://github.com/rust-lang/cfg-if)
- **find-msvc-tools** (0.1.7) - [source](https://github.com/rust-lang/cc-rs)
- **jobserver** (0.1.34) - [source](https://github.com/rust-lang/jobserver-rs)
- **js-sys** (0.3.83) - [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys)
- **wait-timeout** (0.2.1) - [source](https://github.com/alexcrichton/wait-timeout)
- **wasm-bindgen-futures** (0.4.56) - [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures)
- **wasm-bindgen-macro-support** (0.2.106) - [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro-support)
- **wasm-bindgen-macro** (0.2.106) - [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro)
- **wasm-bindgen-shared** (0.2.106) - [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared)
- **wasm-bindgen-test-macro** (0.3.56) - [source](https://github.com/wasm-bindgen/wasm-bindgen)
- **wasm-bindgen-test** (0.3.56) - [source](https://github.com/wasm-bindgen/wasm-bindgen)
- **wasm-bindgen** (0.2.106) - [source](https://github.com/wasm-bindgen/wasm-bindgen)
- **web-sys** (0.3.83) - [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys)

### MIT License

- **errno** (0.3.14) - [source](https://github.com/lambda-fairy/rust-errno)

### MIT License

- **criterion-plot** (0.5.0) - [source](https://github.com/bheisler/criterion.rs)
- **criterion** (0.5.1) - [source](https://github.com/bheisler/criterion.rs)

### MIT License

- **base64ct** (1.8.2) - [source](https://github.com/RustCrypto/formats)

### MIT License

- **base16ct** (0.2.0) - [source](https://github.com/RustCrypto/formats/tree/master/base16ct)

### MIT License

- **bitflags** (2.10.0) - [source](https://github.com/bitflags/bitflags)
- **glob** (0.3.3) - [source](https://github.com/rust-lang/glob)
- **num-traits** (0.2.19) - [source](https://github.com/rust-num/num-traits)
- **regex-automata** (0.4.13) - [source](https://github.com/rust-lang/regex)
- **regex-syntax** (0.8.8) - [source](https://github.com/rust-lang/regex)
- **regex** (1.12.2) - [source](https://github.com/rust-lang/regex)

### MIT License

- **cast** (0.3.0) - [source](https://github.com/japaric/cast.rs)

### MIT License

- **libc** (0.2.180) - [source](https://github.com/rust-lang/libc)

### MIT License

- **either** (1.15.0) - [source](https://github.com/rayon-rs/either)
- **itertools** (0.10.5) - [source](https://github.com/rust-itertools/itertools)

### MIT License

- **tempfile** (3.24.0) - [source](https://github.com/Stebalien/tempfile)

### MIT License

- **quick-error** (1.2.3) - [source](http://github.com/tailhook/quick-error)

### MIT License

- **poly1305** (0.8.0) - [source](https://github.com/RustCrypto/universal-hashes)

### MIT License

- **minicov** (0.3.8) - [source](https://github.com/Amanieu/minicov)

### MIT License

- **proptest** (1.9.0) - [source](https://github.com/proptest-rs/proptest)
- **rusty-fork** (0.3.1) - [source](https://github.com/altsysrq/rusty-fork)

### MIT License

- **cipher** (0.4.4) - [source](https://github.com/RustCrypto/traits)

### MIT License

- **digest** (0.10.7) - [source](https://github.com/RustCrypto/traits)

### MIT License

- **fnv** (1.0.7) - [source](https://github.com/servo/rust-fnv)

### MIT License

- **digest** (0.11.0-rc.5) - [source](https://github.com/RustCrypto/traits)

### MIT License

- **autocfg** (1.5.0) - [source](https://github.com/cuviper/autocfg)

### MIT License

- **block-buffer** (0.10.4) - [source](https://github.com/RustCrypto/utils)

### MIT License

- **keccak** (0.1.5) - [source](https://github.com/RustCrypto/sponges/tree/master/keccak)
- **keccak** (0.2.0-rc.0) - [source](https://github.com/RustCrypto/sponges)

### MIT License

- **signature** (2.2.0) - [source](https://github.com/RustCrypto/traits/tree/master/signature)

### MIT License

- **opaque-debug** (0.3.1) - [source](https://github.com/RustCrypto/utils)

### MIT License

- **getrandom** (0.2.16) - [source](https://github.com/rust-random/getrandom)

### MIT License

- **signature** (3.0.0-rc.6) - [source](https://github.com/RustCrypto/traits)

### MIT License

- **rand_core** (0.10.0-rc-3) - [source](https://github.com/rust-random/rand_core)

### MIT License

- **block-buffer** (0.11.0) - [source](https://github.com/RustCrypto/utils)

### MIT License

- **hex-literal** (1.1.0) - [source](https://github.com/RustCrypto/utils)

### MIT License

- **getrandom** (0.3.4) - [source](https://github.com/rust-random/getrandom)

### MIT License

- **tinytemplate** (1.2.1) - [source](https://github.com/bheisler/TinyTemplate)

### MIT License

- **bumpalo** (3.19.1) - [source](https://github.com/fitzgen/bumpalo)

### MIT License

- **ppv-lite86** (0.2.21) - [source](https://github.com/cryptocorrosion/cryptocorrosion)

### MIT License

- **chacha20poly1305** (0.10.1) - [source](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305)

### MIT License

- **aead** (0.5.2) - [source](https://github.com/RustCrypto/traits)

### MIT License

- **universal-hash** (0.5.1) - [source](https://github.com/RustCrypto/traits)

### MIT License

- **chacha20** (0.9.1) - [source](https://github.com/RustCrypto/stream-ciphers)

### MIT License

- **elliptic-curve** (0.13.8) - [source](https://github.com/RustCrypto/traits/tree/master/elliptic-curve)
- **fips204** (0.4.6) - [source](https://github.com/integritychain/fips204)

### MIT License

- **const-oid** (0.9.6) - [source](https://github.com/RustCrypto/formats/tree/master/const-oid)

### MIT License

- **der** (0.7.10) - [source](https://github.com/RustCrypto/formats/tree/master/der)
- **pkcs8** (0.10.2) - [source](https://github.com/RustCrypto/formats/tree/master/pkcs8)

### MIT License

- **cpufeatures** (0.2.17) - [source](https://github.com/RustCrypto/utils)

### MIT License

- **sha3** (0.11.0-rc.3) - [source](https://github.com/RustCrypto/hashes)

### MIT License

- **crypto-common** (0.1.7) - [source](https://github.com/RustCrypto/traits)

### MIT License

- **crypto-bigint** (0.5.5) - [source](https://github.com/RustCrypto/crypto-bigint)
- **pem-rfc7468** (0.7.0) - [source](https://github.com/RustCrypto/formats/tree/master/pem-rfc7468)

### MIT License

- **sec1** (0.7.3) - [source](https://github.com/RustCrypto/formats/tree/master/sec1)

### MIT License

- **spki** (0.7.3) - [source](https://github.com/RustCrypto/formats/tree/master/spki)

### MIT License

- **crypto-common** (0.2.0-rc.9) - [source](https://github.com/RustCrypto/traits)

### MIT License

- **inout** (0.1.4) - [source](https://github.com/RustCrypto/utils)

### MIT License

- **hybrid-array** (0.4.5) - [source](https://github.com/RustCrypto/hybrid-array)

### MIT License

- **bit-set** (0.8.0) - [source](https://github.com/contain-rs/bit-set)
- **bit-vec** (0.8.0) - [source](https://github.com/contain-rs/bit-vec)

### MIT License

- **anstyle** (1.0.13) - [source](https://github.com/rust-cli/anstyle.git)
- **clap** (4.5.54) - [source](https://github.com/clap-rs/clap)
- **clap_builder** (4.5.54) - [source](https://github.com/clap-rs/clap)
- **clap_lex** (0.7.6) - [source](https://github.com/clap-rs/clap)

### MIT License

- **arrayvec** (0.7.6) - [source](https://github.com/bluss/arrayvec)

### MIT License

- **rand** (0.8.5) - [source](https://github.com/rust-random/rand)
- **rand** (0.9.2) - [source](https://github.com/rust-random/rand)
- **rand_chacha** (0.3.1) - [source](https://github.com/rust-random/rand)
- **rand_chacha** (0.9.0) - [source](https://github.com/rust-random/rand)
- **rand_core** (0.6.4) - [source](https://github.com/rust-random/rand)
- **rand_core** (0.9.3) - [source](https://github.com/rust-random/rand)
- **rand_xorshift** (0.4.0) - [source](https://github.com/rust-random/rngs)

### MIT License

- **zerocopy-derive** (0.8.33) - [source](https://github.com/google/zerocopy)
- **zerocopy** (0.8.33) - [source](https://github.com/google/zerocopy)

### MIT License

- **tap** (1.0.1) - [source](https://github.com/myrrlyn/tap)

### MIT License

- **bitvec** (1.0.1) - [source](https://github.com/bitvecto-rs/bitvec)
- **wyz** (0.5.1) - [source](https://github.com/myrrlyn/wyz)

### MIT License

- **zeroize** (1.8.2) - [source](https://github.com/RustCrypto/utils)

### MIT License

- **radium** (0.7.0) - [source](https://github.com/bitvecto-rs/radium)

### MIT License

- **zeroize_derive** (1.4.3) - [source](https://github.com/RustCrypto/utils/tree/master/zeroize/derive)

### MIT License

- **funty** (2.0.0) - [source](https://github.com/myrrlyn/funty)

### MIT License

- **serdect** (0.2.0) - [source](https://github.com/RustCrypto/formats/tree/master/serdect)
- **serdect** (0.3.0) - [source](https://github.com/RustCrypto/formats)

### MIT License

- **anes** (0.1.6) - [source](https://github.com/zrzka/anes-rs)
- **libm** (0.2.15) - [source](https://github.com/rust-lang/compiler-builtins)
- **plotters-backend** (0.3.7) - [source](https://github.com/plotters-rs/plotters)
- **plotters-svg** (0.3.7) - [source](https://github.com/plotters-rs/plotters.git)
- **plotters** (0.3.7) - [source](https://github.com/plotters-rs/plotters)
- **pqcrypto-internals** (0.2.11) - [source](https://github.com/rustpq/pqcrypto)
- **pqcrypto-traits** (0.3.5) - [source](https://github.com/rustpq/pqclean/)
- **r-efi** (5.3.0) - [source](https://github.com/r-efi/r-efi)
- **wasip2** (1.0.1+wasi-0.2.4) - [source](https://github.com/bytecodealliance/wasi-rs)
- **windows-link** (0.2.1) - [source](https://github.com/microsoft/windows-rs)
- **windows-sys** (0.61.2) - [source](https://github.com/microsoft/windows-rs)

### MIT License

- **pqcrypto-ntruprime** (0.1.6) - [source](https://github.com/rustpq/pqcrypto/)

### MIT License

- **unarray** (0.1.4) - [source](https://github.com/cameron1024/unarray)

### MIT License

- **half** (2.7.1) - [source](https://github.com/VoidStarKat/half-rs)

### MIT License

- **async-trait** (0.1.89) - [source](https://github.com/dtolnay/async-trait)
- **fastrand** (2.3.0) - [source](https://github.com/smol-rs/fastrand)
- **group** (0.13.0) - [source](https://github.com/zkcrypto/group)
- **hermit-abi** (0.5.2) - [source](https://github.com/hermit-os/hermit-rs)
- **is-terminal** (0.4.17) - [source](https://github.com/sunfishcode/is-terminal)
- **itoa** (1.0.17) - [source](https://github.com/dtolnay/itoa)
- **linux-raw-sys** (0.11.0) - [source](https://github.com/sunfishcode/linux-raw-sys)
- **once_cell** (1.21.3) - [source](https://github.com/matklad/once_cell)
- **proc-macro2** (1.0.105) - [source](https://github.com/dtolnay/proc-macro2)
- **quote** (1.0.43) - [source](https://github.com/dtolnay/quote)
- **rustix** (1.1.3) - [source](https://github.com/bytecodealliance/rustix)
- **rustversion** (1.0.22) - [source](https://github.com/dtolnay/rustversion)
- **serde** (1.0.228) - [source](https://github.com/serde-rs/serde)
- **serde_core** (1.0.228) - [source](https://github.com/serde-rs/serde)
- **serde_derive** (1.0.228) - [source](https://github.com/serde-rs/serde)
- **serde_json** (1.0.149) - [source](https://github.com/serde-rs/json)
- **syn** (2.0.114) - [source](https://github.com/dtolnay/syn)
- **unicode-ident** (1.0.22) - [source](https://github.com/dtolnay/unicode-ident)
- **wasi** (0.11.1+wasi-snapshot-preview1) - [source](https://github.com/bytecodealliance/wasi)
- **wit-bindgen** (0.46.0) - [source](https://github.com/bytecodealliance/wit-bindgen)
- **zmij** (1.0.12) - [source](https://github.com/dtolnay/zmij)

### MIT License

- **typenum** (1.19.0) - [source](https://github.com/paholg/typenum)

### MIT License

- **memchr** (2.7.6) - [source](https://github.com/BurntSushi/memchr)
- **walkdir** (2.5.0) - [source](https://github.com/BurntSushi/walkdir)

### MIT License

- **shlex** (1.3.0) - [source](https://github.com/comex/rust-shlex)

### MIT License

- **same-file** (1.0.6) - [source](https://github.com/BurntSushi/same-file)
- **winapi-util** (0.1.11) - [source](https://github.com/BurntSushi/winapi-util)

### MIT License

- **ff** (0.13.1) - [source](https://github.com/zkcrypto/ff)

### MIT License

- **oorandom** (11.1.5) - [source](https://hg.sr.ht/~icefox/oorandom)

### MIT License

- **crossbeam-deque** (0.8.6) - [source](https://github.com/crossbeam-rs/crossbeam)
- **crossbeam-epoch** (0.9.18) - [source](https://github.com/crossbeam-rs/crossbeam)
- **crossbeam-utils** (0.8.21) - [source](https://github.com/crossbeam-rs/crossbeam)

### MIT License

- **crunchy** (0.2.4) - [source](https://github.com/eira-fransham/crunchy)

### MIT License

- **version_check** (0.9.5) - [source](https://github.com/SergioBenitez/version_check)

### MIT License

- **nu-ansi-term** (0.50.3) - [source](https://github.com/nushell/nu-ansi-term)

### MIT License

- **generic-array** (0.14.7) - [source](https://github.com/fizyk20/generic-array.git)

### Unicode License v3

- **unicode-ident** (1.0.22) - [source](https://github.com/dtolnay/unicode-ident)


---

## Full Licence Texts

For the full text of each licence:

- **Apache-2.0**: https://www.apache.org/licenses/LICENSE-2.0
- **MIT**: https://opensource.org/licenses/MIT
- **BSD-2-Clause**: https://opensource.org/licenses/BSD-2-Clause
- **BSD-3-Clause**: https://opensource.org/licenses/BSD-3-Clause
- **ISC**: https://opensource.org/licenses/ISC
- **Zlib**: https://opensource.org/licenses/Zlib
- **CC0-1.0**: https://creativecommons.org/publicdomain/zero/1.0/
- **MPL-2.0**: https://www.mozilla.org/en-US/MPL/2.0/
- **Unicode-DFS-2016**: https://www.unicode.org/license.html
- **BSL-1.0**: https://www.boost.org/LICENSE_1_0.txt
- **OpenSSL**: https://www.openssl.org/source/license.html
