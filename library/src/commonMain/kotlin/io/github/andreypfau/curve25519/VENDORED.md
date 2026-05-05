# Vendored: curve25519-kotlin

The 25 source files under this package
(`io.github.andreypfau.curve25519.*`) are vendored from
[andreypfau/curve25519-kotlin](https://github.com/andreypfau/curve25519-kotlin)
at commit `2893ba75b3498f9add3b2dc80dc1204cc492dd5e` (tag `v0.0.8`,
2025-01-14). MIT-licensed; copyright © Andrey Pfau.

We vendor (rather than depend via Maven) because:

1. Upstream is effectively unmaintained — last source change 2024-05-04, with
   only a README tweak since.
2. The published v0.0.8 has a real bug in
   `constants/tables/ProjectiveNielsPointLookupTable.kt` (the radix-16
   variable-base scalar mult lookup table mistakenly builds odd multiples
   `[P, 3P, ..., 15P]` instead of sequential `[P, 2P, ..., 8P]`, copy-pasted
   from the sister NAF table). The bug doesn't fire in the upstream library's
   own tests because nothing internal calls `EdwardsPoint.mul(point, scalar)`
   — RFC 8032 sign uses the basepoint table, verify uses NAF — so it's a
   latent bug the maintainer hasn't tripped. Our blind-Schnorr protocol
   needs variable-base mul on arbitrary points and trips it directly.
3. Vendoring lets us patch in place and ship today.

## Modifications from upstream

- **`constants/tables/ProjectiveNielsPointLookupTable.kt`** — fixed the
  copy-paste bug. Changed `tmp.add(a2, ai[i])` to `tmp.add(ep, ai[i])` and
  removed the `a2 = double(ep)` line. The lookup table now correctly holds
  `[P, 2P, 3P, …, 8P]` matching what `lookup(x)` indexes.
- **`ed25519/Ed25519.kt`** — replaced `kotlinx.crypto.sha512` calls with our
  internal [`Sha512`](../../../../org/gossamr/crypto/blind/internal/Sha512.kt)
  (which goes through cryptography-kotlin). Dropped `sharedKey` (X25519
  conversion) since this library does not need ECDH.
- **`ed25519/Ed25519PrivateKey.kt`** — same SHA-512 swap, same `sharedKey`
  removal.
- **`ed25519/Ed25519PublicKey.kt`** — same SHA-512 swap, same `sharedKey`
  removal.

## Modules NOT vendored

- `ed25519/Ed25519VerifyOptions.kt`, `scalar/scMinimal.kt` — verify-options
  surface unused by our library.
- `montgomery/*`, `x25519/*` — ECDH/Montgomery code path unused.

## Remaining external dep

- `io.github.andreypfau:kotlinx-crypto-subtle:0.0.4` — 36 lines of
  constant-time `Byte.constantTimeEquals`, `Int.constantTimeSelect`, and
  `Int.constantTimeSwap` helpers. Tiny, separate Maven artifact.

## Upstream license

```
MIT License

Copyright (c) 2022 Andrey Pfau

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
