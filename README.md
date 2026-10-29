# Deterministic Public IDs from Integer Keys

Specification v1 — approved on 2026-10-30. A bilingual proposal and Node.js reference implementation.

[日本語](README.ja.md)

## Purpose

Keep database-assigned integers as internal keys and expose their AES-transformed values as 32-character hexadecimal IDs. Within a fixed scope, distinct integers produce distinct public IDs. No per-record randomness or mapping table is required, and primary keys, foreign keys and joins continue to use integers.

This is obfuscation of visibly sequential numbers. Anyone who knows the algorithm, public constants and scope can reverse the transformation. It does not provide confidentiality or authorization.

## Why this design instead of UUIDs?

The starting point is an integer that PostgreSQL already manages uniquely. The requirement is to preserve that uniqueness while avoiding a direct sequential representation outside the application. There is no need to generate a new identifier independently, so this design deterministically transforms the existing integer.

First, it makes the basis of uniqueness explicit. For random UUID v4, the expectation that generated values will not collide rests on randomness and probability. A database uniqueness constraint can reject duplicates, but it does not make the generator collision-free. Here, an injective transformation carries database-established uniqueness into the public representation within the same scope. Uniqueness follows from allocation and transformation properties rather than an additional probabilistic assumption.

Second, it removes randomness from ID generation. Randomized schemes depend on both the random source and correct generator state management. RFC 9562 discusses reseeding following state changes such as process forks. This proposal reproduces each ID from the allocated integer, public constants and scope. It does not claim that virtual machines necessarily make UUID collisions likely; it removes random-source quality and generator state from this design's uniqueness argument. [RFC 9562 §6.9](sources/rfc9562.txt)

Third, it avoids storing and managing a second identifier for the same record. A UUID used as an internal key occupies 16 bytes. Retaining an integer internally and separately assigning an external UUID typically means keeping an additional column and unique index. Here, the internal key remains an 8-byte integer, and the external ID can be computed when needed. An incoming ID can be decoded to the integer without a mapping lookup.

This choice suits systems that can allocate keys through a database. UUIDs offer distributed generation when identifiers must be created before contacting a database or at independently operating locations. This design instead prioritizes **database-established uniqueness with a deterministic change of external representation**. It does not claim smaller binary IDs or inherently faster generation than UUIDs; measured costs appear below.

## Specification

### Integer encoding and public ID

| Item | Definition |
|---|---|
| Input | JavaScript `bigint`, from `0n` to `9223372036854775807n`, inclusive |
| AES input | 16 bytes: eight zero bytes followed by the integer as eight unsigned big-endian bytes |
| Transformation | One AES-128 block, without padding |
| Output | Exactly 32 lowercase hexadecimal characters, preserving leading zeros |
| Decoding | Decode hex, apply the AES inverse with the same key, require eight leading zero bytes and a trailing integer in range, then return `bigint` |

PostgreSQL `bigint` is an 8-byte signed integer. This design uses its nonnegative range. Allocation may normally start at 1; the codec also accepts 0. [PostgreSQL 16 numeric types](https://www.postgresql.org/docs/16/datatype-numeric.html)

These examples are plaintext blocks, before AES:

| Integer | Plaintext block in hex |
|---|---|
| `0n` | `00000000000000000000000000000000` |
| `1n` | `00000000000000000000000000000001` |
| `9223372036854775807n` | `00000000000000007fffffffffffffff` |

### Public constants and scope-specific derivation

The caller supplies only one setting: `info`.

| Item | Definition |
|---|---|
| Derivation | RFC 5869 HKDF, both Extract and Expand, using SHA-256 |
| Input keying material | UTF-8 bytes of `rainfrog-public-id-v1`, without newline or terminating NUL |
| Salt | 32 zero bytes, fixed by the specification; not a caller setting |
| Info | Exact UTF-8 bytes of a nonempty string, at most 1024 bytes |
| Derived key | 16 bytes for AES-128 |
| Timing | Derive once when initializing a codec; reuse for encoding and decoding |

RFC 5869 defines the omitted salt as a zero string of the hash output length, and `info` binds derivation to a context or purpose. Here these mechanisms reproduce a scope-specific transformation from public information. [RFC 5869 §2.2 and §3.2](https://www.rfc-editor.org/rfc/rfc5869.html), [archived text](sources/rfc5869.txt).

Use a stable scope identifier such as `creator-1/roster/customer`. Do not trim whitespace, change case or normalize Unicode. Reject unpaired surrogates to prevent replacement during UTF-8 encoding.

Configure this name explicitly rather than deriving it dynamically from a physical table name. Renaming a table must not change `info`. Where separate databases or tables allocate integers independently, distinguish their scopes accordingly.

### API and validation

```js
import { createPublicIdCodec } from './reference/public-id.js';

const codec = createPublicIdCodec('creator-1/roster/customer');
const publicId = codec.encode(123n);
const id = codec.decode(publicId); // 123n
```

The codec retains its derived key. There are no additional salt, secret-key or algorithm-selection arguments.

- `encode` accepts only `bigint`, without implicit conversion from `Number` or numeric strings.
- `decode` accepts exactly 32 lowercase hex characters. Uppercase, `0x`, hyphens and whitespace are rejected.
- Wrong argument types throw `TypeError`. Invalid lengths, ranges or formats throw `RangeError`, including invalid decoded blocks.
- A decodable ID does not establish that a record exists or that access is authorized. The application performs those checks.

The Node.js implementation uses `node:crypto`'s `hkdfSync`, `createCipheriv` and `createDecipheriv`. AES is called as `aes-128-ecb`, with a `null` IV and `setAutoPadding(false)`, processing exactly one block. This construction is not extended to encrypt multi-block business data. [Node.js Crypto API](https://nodejs.org/docs/latest-v24.x/api/crypto.html)

The specification fixes AES-128 and SHA-256. Because the key material is public, longer keys are not presented as a confidentiality benefit.

## Why uniqueness holds

For a fixed scope:

```text
K = HKDF-SHA-256(public constant, fixed salt, UTF-8(info), 16 bytes)
E(n) = eight zero bytes || eight-byte big-endian integer n
publicId(n) = hex(AES-K(E(n)))
```

Distinct integers have distinct encodings `E(n)`. AES under a fixed key is invertible, so distinct input blocks cannot produce the same output block. Canonical hexadecimal encoding also preserves distinctness. Their composition therefore maps distinct integers to distinct public IDs within a scope, without relying on collision probability. [FIPS 197 §5.1 and §5.3](https://doi.org/10.6028/NIST.FIPS.197-upd1), [archived document](sources/nist-fips197-upd1.pdf).

The database establishes uniqueness of allocated integers. Reusing an integer reproduces its ID. There is no collision-free guarantee across different `info` values. Across scopes, identify a record by the pair of scope and ID, with the scope expressed, for example, by a URL path.

## Comparison

| Aspect | Expose integers directly | Random UUID v4 | This proposal |
|---|---|---|---|
| Basis of uniqueness | Unique database allocation | Randomness and a large space; strict duplicate rejection needs checking | Unique database allocation and an injective transformation |
| Central allocation | Required | Distributed generation possible | Required |
| Internal key size | 8 bytes for `bigint` | 16 bytes if UUID is the internal key | 8-byte integer |
| External representation | Up to 19 decimal digits | 36 characters in standard hyphenated form | 32 lowercase hex characters |
| Mapping to an original integer | Unnecessary | Retained if UUID is separately assigned to an integer | Unnecessary; reversible |
| Generation cost | Decimal formatting | Random generation and formatting | HKDF at initialization; one AES operation per ID |
| Visible sequence | Directly visible | Not sequential | Not visibly sequential, but recoverable and enumerable with knowledge of the scheme |

The AES output is 16 bytes, not a smaller binary value than UUID. The internal integer's storage benefit is separate from the length of the public representation. UUID has several versions; this comparison concerns random UUID v4. [RFC 9562 §4 and §5.4](https://www.rfc-editor.org/rfc/rfc9562.html), [archived text](sources/rfc9562.txt).

## Design choices and prior work

**Why AES?** Its invertible permutation gives a collision-free transformation of fixed-size blocks. This is not a new cryptographic algorithm. With public constants, there is no secret cryptographic key to administer.

**Why not preserve the integer's original width?** This design accepts a 128-bit output. Prior work on arbitrary finite domains includes repeated transformations to keep outputs inside a target domain. That restriction is unnecessary here, so a single AES application suffices. This comparison establishes context, not a novelty claim. [Black and Rogaway, Ciphers with Arbitrary Finite Domains, §4, 2002](https://web.cs.ucdavis.edu/~rogaway/papers/subset.pdf).

**Why HKDF?** It specifies a reproducible conversion of a scope name into a fixed-size AES key. It does not turn public information into secret information.

**How do existing IDs remain stable?** Keep the public constant, encoding, algorithms and `info` fixed as one specification. No version field is embedded in the ID. Library updates must preserve the mapping for existing scopes. A future alternative must retain a way to read existing IDs.

## Running the reference implementation

Node.js 24 or later; no external packages or install step. From this proposal's directory:

```sh
cd reference
npm test
npm run benchmark
```

Convert a database driver's integer string explicitly with `BigInt(value)`. Do not route values through `Number`. The codec needs no database connection.

## Validation

All eight Node test cases pass, covering:

- A known AES-128 example and its inverse, plus RFC 5869 SHA-256 vectors A.1 and A.3.
- 36 fixed vectors for four scopes, including Japanese and whitespace, checked in both directions. Expected values were generated separately with Python standard-library HMAC and the OpenSSL 3.6.3 CLI. Tests also construct HKDF explicitly and use WebCrypto's AES-CBC first block with a zero IV to cross-check the AES result. These paths can share underlying cryptographic libraries; they are not claimed as wholly independent AES implementations.
- Integer limits, bit and byte boundaries, precise values beyond `2^53`, and preservation of leading hex zeros.
- A sweep of 10,000 sequential integers, checking decoding, reproducibility and duplicate outputs.
- Wrong types, out-of-range integers, noncanonical hex, invalid decoded blocks, malformed Unicode and UTF-8 byte limits.

[Fixed vectors](reference/vectors.json) include the public derived keys, plaintext blocks and outputs. [Tests](reference/public-id.test.js) can be rerun. The finite sweep checks the implementation; the uniqueness argument is the injectivity proof above. Rejection under an incorrect scope is not an authentication guarantee.

### Local performance measurement

2026-10-30 JST; Apple M1, macOS/Darwin 25.3.0 arm64, Node.js v24.22.1, bundled OpenSSL 3.5.9. Each case has 2,000 warmup operations followed by five timed rounds; the table reports the median.

| Operation | Operations per round | Time per operation |
|---|---:|---:|
| Initialize codec, including HKDF | 10,000 | 3.40 µs |
| Encode integer | 100,000 | 2.26 µs |
| Decode public ID | 100,000 | 2.16 µs |

Encoding and decoding include validation, cipher creation, buffers and hex conversion. These are local measurements without database or network work, not service throughput or a comparison against UUID generation. [Raw measurements and environment](reference/benchmark-result.json), [benchmark code](reference/benchmark.js).

## Sources and publication status

[Source index](SOURCES.md) records editions, original URLs, archived copies, checksums and reuse terms. The public repository is [public-id-js](https://github.com/yukihiro-asami/public-id-js). The original proposal documents, reference implementation and verification data are available under the [MIT License](LICENSE). Archived source documents retain their own terms.
