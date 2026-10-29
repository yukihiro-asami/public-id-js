import { performance } from 'node:perf_hooks';
import { cpus, platform, arch, release } from 'node:os';
import { createPublicIdCodec } from './public-id.js';

const info = 'creator-1/roster/customer';
const codec = createPublicIdCodec(info);
const ids = Array.from({ length: 1024 }, (_, index) => BigInt(index));
const encoded = ids.map(id => codec.encode(id));
let sink;

function measure(iterations, operation) {
  for (let index = 0; index < 2000; index += 1) sink = operation(index);
  const milliseconds = [];
  for (let round = 0; round < 5; round += 1) {
    const start = performance.now();
    for (let index = 0; index < iterations; index += 1) sink = operation(index);
    milliseconds.push(performance.now() - start);
  }
  const medianMs = [...milliseconds].sort((a, b) => a - b)[2];
  return { iterations, rounds: 5, milliseconds, medianMs,
    microsecondsPerOperation: medianMs * 1000 / iterations,
    operationsPerSecond: iterations * 1000 / medianMs };
}

const result = {
  measuredAt: new Date().toISOString(),
  environment: { node: process.version, openssl: process.versions.openssl,
    platform: platform(), arch: arch(), osRelease: release(), cpu: cpus()[0]?.model },
  method: '2000 warmup operations per case; median of 5 rounds; encode/decode include validation, cipher creation and byte/hex conversion; no DB or network; sequential local microbenchmark.',
  initialization: measure(10000, () => createPublicIdCodec(info)),
  encode: measure(100000, index => codec.encode(ids[index % ids.length])),
  decode: measure(100000, index => codec.decode(encoded[index % encoded.length])),
};
if (sink === undefined) {
  throw new Error('Benchmark produced no result');
}
console.log(JSON.stringify(result, null, 2));
