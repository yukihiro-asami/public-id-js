import { createCipheriv, createDecipheriv, hkdfSync } from 'node:crypto';

const maxId = (1n << 63n) - 1n;
const ikm = Buffer.from('rainfrog-public-id-v1', 'utf8');
const salt = Buffer.alloc(32);

export function createPublicIdCodec(info) {
  if (typeof info !== 'string') {
    throw new TypeError('info must be a string');
  }
  if (!info.isWellFormed()) {
    throw new RangeError('info must contain well-formed Unicode');
  }
  const context = Buffer.from(info, 'utf8');
  if (context.length === 0 || context.length > 1024) {
    throw new RangeError('info must be 1 to 1024 UTF-8 bytes');
  }
  const key = Buffer.from(hkdfSync('sha256', ikm, salt, context, 16));

  function encode(id) {
    if (typeof id !== 'bigint') {
      throw new TypeError('id must be a bigint');
    }
    if (id < 0n || id > maxId) {
      throw new RangeError('id must be between 0 and 2^63 - 1');
    }
    const block = Buffer.alloc(16);
    block.writeBigUInt64BE(id, 8);
    const cipher = createCipheriv('aes-128-ecb', key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(block), cipher.final()]).toString('hex');
  }

  function decode(publicId) {
    if (typeof publicId !== 'string') {
      throw new TypeError('publicId must be a string');
    }
    if (publicId.length !== 32 || !/^[0-9a-f]{32}$/.test(publicId)) {
      throw new RangeError('publicId must be exactly 32 lowercase hex characters');
    }
    const decipher = createDecipheriv('aes-128-ecb', key, null);
    decipher.setAutoPadding(false);
    const block = Buffer.concat([
      decipher.update(Buffer.from(publicId, 'hex')),
      decipher.final(),
    ]);
    const id = block.readBigUInt64BE(8);
    if (block.readBigUInt64BE(0) !== 0n || id > maxId) {
      throw new RangeError('decoded block is outside the integer encoding');
    }
    return id;
  }

  return { encode, decode };
}
