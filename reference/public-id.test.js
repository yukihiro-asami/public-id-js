import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFileSync } from 'node:fs';
import { createCipheriv, createDecipheriv, createHmac, hkdfSync, webcrypto } from 'node:crypto';
import { createPublicIdCodec } from './public-id.js';

const { vectors } = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url)));
const maxId = (1n << 63n) - 1n;
const info = 'creator-1/roster/customer';

function encryptBlock(key, block) {
  const cipher = createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

// Independent HKDF construction for a 16-byte output: one Expand block.
function deriveWithHmac(context) {
  const prk = createHmac('sha256', Buffer.alloc(32)).update('rainfrog-public-id-v1').digest();
  return createHmac('sha256', prk).update(context).update(Buffer.from([1])).digest().subarray(0, 16);
}

test('AES-128 FIPS 197 example and inverse with padding disabled', () => {
  const key = Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex');
  const plain = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const encrypted = encryptBlock(key, plain);
  assert.equal(encrypted.toString('hex'), '69c4e0d86a7b0430d8cdb78070b4c55a');
  const decipher = createDecipheriv('aes-128-ecb', key, null);
  decipher.setAutoPadding(false);
  assert.deepEqual(Buffer.concat([decipher.update(encrypted), decipher.final()]), plain);
});

test('HKDF-SHA-256 RFC 5869 A.1 and A.3 (zero salt)', () => {
  const ikm = Buffer.alloc(22, 0x0b);
  const actual = hkdfSync('sha256', ikm, Buffer.from('000102030405060708090a0b0c', 'hex'),
    Buffer.from('f0f1f2f3f4f5f6f7f8f9', 'hex'), 42);
  assert.equal(Buffer.from(actual).toString('hex'),
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  assert.equal(Buffer.from(hkdfSync('sha256', ikm, Buffer.alloc(32), Buffer.alloc(0), 42)).toString('hex'),
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8');
});

test('36 fixed vectors: codec, explicit HKDF and WebCrypto CBC first block agree', async () => {
  for (const vector of vectors) {
    const key = deriveWithHmac(vector.info);
    assert.equal(key.toString('hex'), vector.keyHex);
    const codec = createPublicIdCodec(vector.info);
    assert.equal(codec.encode(BigInt(vector.id)), vector.publicId);
    assert.equal(codec.decode(vector.publicId), BigInt(vector.id));
    // CBC first block with IV=0 is AES(K, plaintext); discard the padding block.
    const cryptoKey = await webcrypto.subtle.importKey('raw', key, 'AES-CBC', false, ['encrypt']);
    const encrypted = await webcrypto.subtle.encrypt(
      { name: 'AES-CBC', iv: new Uint8Array(16) }, cryptoKey, Buffer.from(vector.blockHex, 'hex'));
    assert.equal(Buffer.from(encrypted).subarray(0, 16).toString('hex'), vector.publicId);
  }
});

test('bit boundaries, exact values above 2^53 and leading-zero output', () => {
  const codec = createPublicIdCodec(info);
  const values = new Set([0n, maxId, 2n ** 53n - 1n, 2n ** 53n, 2n ** 53n + 1n]);
  for (let bit = 1n; bit < 63n; bit += 1n) {
    for (const delta of [-1n, 0n, 1n]) values.add((1n << bit) + delta);
  }
  for (const value of values) assert.equal(codec.decode(codec.encode(value)), value);
  let found = false;
  for (let value = 0n; value < 1024n; value += 1n) {
    const encoded = codec.encode(value);
    if (encoded.startsWith('0')) {
      assert.equal(encoded.length, 32);
      assert.equal(codec.decode(encoded), value);
      found = true;
      break;
    }
  }
  assert.ok(found);
});

test('10,000 sequential IDs round-trip, reproduce and have no duplicate outputs', () => {
  const first = createPublicIdCodec(info);
  const second = createPublicIdCodec(info);
  const outputs = new Set();
  for (let value = 0n; value < 10000n; value += 1n) {
    const encoded = first.encode(value);
    assert.match(encoded, /^[0-9a-f]{32}$/);
    assert.equal(second.encode(value), encoded);
    assert.equal(second.decode(encoded), value);
    outputs.add(encoded);
  }
  assert.equal(outputs.size, 10000);
});

test('info validates type, UTF-8 byte limit, Unicode and preserves exact text', () => {
  for (const value of [undefined, null, 1, 1n, {}, Buffer.from('x')]) {
    assert.throws(() => createPublicIdCodec(value), TypeError);
  }
  for (const value of ['', 'a'.repeat(1025), 'あ'.repeat(342), '\ud800', '\udc00', 'x\ud800x']) {
    assert.throws(() => createPublicIdCodec(value), RangeError);
  }
  for (const value of ['a'.repeat(1024), 'あ'.repeat(341) + 'a', '😀', ' ']) {
    const codec = createPublicIdCodec(value);
    assert.equal(codec.decode(codec.encode(1n)), 1n);
  }
  for (const [left, right] of [['x', ' x'], ['x', 'X'], ['é', 'e\u0301']]) {
    // Examples only: not a cross-info collision guarantee.
    assert.notEqual(createPublicIdCodec(left).encode(1n), createPublicIdCodec(right).encode(1n));
  }
});

test('encode/decode reject wrong types, out-of-range integers and noncanonical hex', () => {
  const codec = createPublicIdCodec(info);
  for (const value of [0, 123, Number.MAX_SAFE_INTEGER + 1, '1', null, undefined, {}]) {
    assert.throws(() => codec.encode(value), TypeError);
  }
  for (const value of [-1n, maxId + 1n, 1n << 128n]) assert.throws(() => codec.encode(value), RangeError);
  for (const value of [0, 0n, null, undefined, {}, Buffer.alloc(16)]) {
    assert.throws(() => codec.decode(value), TypeError);
  }
  const valid = codec.encode(1n);
  for (const value of ['', '0'.repeat(31), '0'.repeat(33), 'A'.repeat(32), 'g'.repeat(32),
    `0x${valid}`, `${valid}\n`, ` ${valid}`, `${valid} `, `${valid.slice(0, 16)}-${valid.slice(16)}`]) {
    assert.throws(() => codec.decode(value), RangeError);
  }
});

test('decode rejects invalid plaintext prefix and range; it does not establish record existence', () => {
  const codec = createPublicIdCodec(info);
  const key = deriveWithHmac(info);
  for (const hex of ['00000000000000010000000000000001', '00000000000000008000000000000000',
    'ffffffffffffffffffffffffffffffff']) {
    assert.throws(() => codec.decode(encryptBlock(key, Buffer.from(hex, 'hex')).toString('hex')), RangeError);
  }
  assert.equal(codec.decode(codec.encode(999999999n)), 999999999n);
});
