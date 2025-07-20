// @ts-check
import { encrypt, decrypt, generateKey } from './xaes.js';

/**
 * Simple benchmark utility
 */
class Benchmark {
    constructor(name) {
        this.name = name;
        this.results = [];
    }

    async run(fn, iterations = 1000) {
        // Warm up
        for (let i = 0; i < 10; i++) {
            await fn();
        }

        const times = [];
        for (let i = 0; i < iterations; i++) {
            const start = performance.now();
            await fn();
            const end = performance.now();
            times.push(end - start);
        }

        const total = times.reduce((a, b) => a + b, 0);
        const avg = total / times.length;
        const min = Math.min(...times);
        const max = Math.max(...times);

        times.sort((a, b) => a - b);
        const median = times[Math.floor(times.length / 2)];

        this.results.push({
            iterations,
            total: total.toFixed(2),
            avg: avg.toFixed(3),
            median: median.toFixed(3),
            min: min.toFixed(3),
            max: max.toFixed(3),
            opsPerSec: (1000 / avg).toFixed(0)
        });

        return this.results[this.results.length - 1];
    }

    report() {
        console.log(`\n=== ${this.name} ===`);
        this.results.forEach((result, i) => {
            console.log(`Test ${i + 1} (${result.iterations} iterations):`);
            console.log(`  Total: ${result.total}ms`);
            console.log(`  Average: ${result.avg}ms`);
            console.log(`  Median: ${result.median}ms`);
            console.log(`  Min: ${result.min}ms`);
            console.log(`  Max: ${result.max}ms`);
            console.log(`  Ops/sec: ${result.opsPerSec}`);
        });
    }
}

/**
 * Generate random data of specified size
 */
function genData(size) {
    return Uint8Array.from({ length: size }, (_, i) => i & 0xff);
}

/**
 * Generate random IV (24 bytes for XAES)
 */
function randomIV() {
    const iv = new Uint8Array(24);
    crypto.getRandomValues(iv);
    return iv;
}

/**
 * Run XAES benchmarks
 */
async function runBenchmarks() {
    console.log('XAES-256-GCM Benchmark');
    console.log('======================');

    // Generate a test key
    const key = await generateKey(false);

    // Generate an AES-GCM key for comparison
    const aesGcmKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );

    // Test data sizes
    const dataSizes = [
        { name: '1KB', size: 1024 },
        { name: '10KB', size: 10 * 1024 },
        { name: '100KB', size: 100 * 1024 },
        { name: '1MB', size: 1024 * 1024 }
    ];

    for (const { name, size } of dataSizes) {
        const data = genData(size);
        const iv = randomIV();
        const additionalData = genData(32); // 32 bytes of AAD

        // Encryption benchmark
        const encryptBench = new Benchmark(`XAES-GCM Encrypt ${name}`);
        const encryptResult = await encryptBench.run(async () => {
            await encrypt({ iv, additionalData }, key, data);
        }, 10000);

        // Compare with AES-GCM
        const aesGcmBench = new Benchmark(`AES-GCM Encrypt ${name}`);
        const aesGcmResult = await aesGcmBench.run(async () => {
            await crypto.subtle.encrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    tagLength: 128,
                    additionalData
                },
                aesGcmKey,
                data
            );
        }, 10000);

        // Pre-encrypt data for decryption benchmark
        const encryptedData = await encrypt({ iv, additionalData }, key, data);
        // Compare with AES-GCM decryption
        const gcmEncryptedData = await crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv,
                tagLength: 128,
                additionalData
            },
            aesGcmKey,
            data
        );

        // Decryption benchmark
        const decryptBench = new Benchmark(`XAES-GCM Decrypt ${name}`);
        const decryptResult = await decryptBench.run(async () => {
            await decrypt({ iv, additionalData }, key, encryptedData);
        }, 10000);

        // AES-GCM decryption benchmark
        const aesGcmDecryptBench = new Benchmark(`AES-GCM Decrypt ${name}`);
        const aesGcmDecryptResult = await aesGcmDecryptBench.run(async () => {
            await crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv,
                    tagLength: 128,
                    additionalData
                },
                aesGcmKey,
                gcmEncryptedData
            );
        }, 10000);

        // Calculate throughput
        const encryptThroughput = ((size / 1024 / 1024) * 1000 / parseFloat(encryptResult.avg)).toFixed(2);
        const decryptThroughput = ((size / 1024 / 1024) * 1000 / parseFloat(decryptResult.avg)).toFixed(2);
        const aesGcmEncryptThroughput = ((size / 1024 / 1024) * 1000 / parseFloat(aesGcmResult.avg)).toFixed(2);
        const aesGcmDecryptThroughput = ((size / 1024 / 1024) * 1000 / parseFloat(aesGcmDecryptResult.avg)).toFixed(2);

        console.log(`\n${name} (${size.toLocaleString()} bytes):`);
        console.log(`  XAES-GCM Encrypt: ${encryptResult.avg}ms avg, ${encryptThroughput} MB/s`);
        console.log(`  XAES-GCM Decrypt: ${decryptResult.avg}ms avg, ${decryptThroughput} MB/s`);
        console.log(`   AES-GCM Encrypt: ${aesGcmResult.avg}ms avg, ${aesGcmEncryptThroughput} MB/s`);
        console.log(`   AES-GCM Decrypt: ${aesGcmDecryptResult.avg}ms avg, ${aesGcmDecryptThroughput} MB/s`);
        // Difference:
        console.log('');
        console.log(`  XAES-GCM Encrypt is ${((parseFloat(encryptResult.avg) - parseFloat(aesGcmResult.avg)) / parseFloat(aesGcmResult.avg) * 100).toFixed(2)}% slower`);
        console.log(`  XAES-GCM Decrypt is ${((parseFloat(decryptResult.avg) - parseFloat(aesGcmDecryptResult.avg)) / parseFloat(aesGcmDecryptResult.avg) * 100).toFixed(2)}% slower`);
    }
}

if (typeof window !== 'undefined') {
    window.onload = runBenchmarks;
    console.log('Call runXAESBenchmarks() to start benchmarks');
} else {
    runBenchmarks().catch(console.error);
}
