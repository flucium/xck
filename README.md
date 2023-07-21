# XCK
In a nutshell, XCK is a high-layer cryptographic framework.

XCK is both a wrapper for cryptographic libraries and an application that performs cryptographic operations.

It runs on many platforms and is intended to simplify and commonize the use(call) of cryptographic libraries.

## Backend
Use the following libraries as backend.

- Rust Crypto<br>
<small>[https://github.com/RustCrypto/](https://github.com/RustCrypto/)</small>

- BLAKE3https://github.com/BLAKE3-team/BLAKE3/<br>
<small>[https://github.com/BLAKE3-team/BLAKE3/](https://github.com/BLAKE3-team/BLAKE3/)</small>

# ...
## Symmetric
AES-128-GCM

AES-192-GCM

AES-256-GCM

ChaCha20-Poly1305

XChaCha20-Poly1305

## Asymmetric
Ed25519


## Hash
SHA256

SHA512

SHA512/256

BLAKE3 Regular hash

BLAKE3 XOF

BLAKE3 KDF

BLAKE3 MAC

## Format
Base64 (constant time)

Hex

## Random (CSPRNG)
Rand has internalized ChaCha20Rng.

## Compress
...