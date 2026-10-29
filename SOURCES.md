# Sources / 一次資料

This index covers only the public-ID proposal. Archived documents are complete, unmodified copies with their original notices. The MIT License for this proposal does not replace the source documents' own terms.

本提案で使う原資料を記録する。保存資料は原文の完全なコピーであり、本文・権利表示を変更していない。提案・参照実装の公開ライセンスと、原資料の利用条件は別に扱う。

## Archived documents / 保存資料

| Document | Edition and retrieval date | Original | Local copy |
|---|---|---|---|
| NIST FIPS 197, Advanced Encryption Standard (AES) | Updated 2023-05-09; retrieved 2026-10-30 | [PDF](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf) | [FIPS 197 upd1](sources/nist-fips197-upd1.pdf) |
| RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF) | Informational, May 2010; retrieved 2026-10-25 | [RFC Editor](https://www.rfc-editor.org/rfc/rfc5869.txt) | [RFC 5869](sources/rfc5869.txt) |
| RFC 9562, Universally Unique IDentifiers (UUIDs) | Standards Track, May 2024; retrieved 2026-10-30 | [RFC Editor](https://www.rfc-editor.org/rfc/rfc9562.txt) | [RFC 9562](sources/rfc9562.txt) |

FIPS 197: **Republished courtesy of the National Institute of Standards and Technology.** See [NIST's Technical Series reprinting policy](https://www.nist.gov/open/copyright-fair-use-and-licensing-statements-srd-data-software-and-technical-series-publications).

RFC files retain all copyright and legal notices. Full unmodified redistribution follows the applicable IETF Trust Legal Provisions, [§3(c)(i)](https://trustee.ietf.org/documents/trust-legal-provisions/tlp-5/), and the terms identified in each document.

SHA-256 identifies the archived bytes, not the correctness of this proposal:

| File | SHA-256 |
|---|---|
| `nist-fips197-upd1.pdf` | `62c86eb567f13edb8f71826e985da870b04ef6381634f303cdb16e84d47becd1` |
| `rfc5869.txt` | `7a40eb3835b35fc947eb12a2ed614db079d43b26e50dbc537c31fba16397089c` |
| `rfc9562.txt` | `041870106b8701d9fa9261dcbc1679a6b7ab18cb179b37b69d7232431eac8042` |

## Linked primary sources / リンクのみの一次資料

Consulted on 2026-10-30; not redistributed here.

- [Node.js Crypto API](https://nodejs.org/docs/latest-v24.x/api/crypto.html): `hkdfSync`, cipher/decipher creation and disabling padding. The rolling page displayed v24.22.2 when consulted; the reference implementation was tested on v24.22.1.
- [PostgreSQL 16 numeric types](https://www.postgresql.org/docs/16/datatype-numeric.html): 8-byte signed `bigint` and its range.
- [John Black and Phillip Rogaway, Ciphers with Arbitrary Finite Domains, 2002](https://web.cs.ucdavis.edu/~rogaway/papers/subset.pdf): §4, cycle walking. Used to contrast domain-preserving schemes with this proposal's acceptance of a 128-bit output, not to claim that the paper proposes this exact construction.

## Verification data / 検証データ

[Project vectors](reference/vectors.json) were generated for this specification using Python's standard-library HMAC-SHA-256 for HKDF Extract and the first Expand block, then OpenSSL CLI 3.6.3 for AES-128-ECB without padding. The tests cross-check them through explicit HMAC derivation and the first block of WebCrypto AES-CBC with a zero IV. These are separate calculation paths, not a claim of independently authored underlying AES implementations.

Primitive tests use the AES-128 example with key `000102030405060708090a0b0c0d0e0f` and plaintext `00112233445566778899aabbccddeeff`, and RFC 5869 Appendix A.1 and A.3. Fixed project vectors are original test data for this proposal.
