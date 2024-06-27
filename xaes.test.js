import { expect, test } from 'vitest';
import { encrypt, decrypt, generateKey, importKey, exportKey } from "./xaes.js";
import { SHAKE128 } from "@stablelib/sha3";

test("xaes generateKey/encrypt/decrypt", async () => {
    const key = await generateKey();
    const iv = new Uint8Array(24).fill(1);
    const data = new Uint8Array(122).fill(2);
    const additionalData = new Uint8Array(16).fill(3);
    const params = { iv, additionalData };
    const encrypted = await encrypt(params, key, data);
    const decrypted = await decrypt(params, key, encrypted);
    expect(decrypted).toEqual(data.buffer);
});

test("xaes importKey, exportKey", async () => {
    const key = new Uint8Array(32).fill(0x04);
    const imported = await importKey("raw", key, true);
    const exported = await exportKey("raw", imported);
    expect(exported).toEqual(key.buffer);
});


test("xaes test vector", async () => {
    const nonce = new TextEncoder().encode("ABCDEFGHIJKLMNOPQRSTUVWX");
    const plaintext = new TextEncoder().encode("XAES-256-GCM");
    const key = await importKey(
        "raw",
        new Uint8Array(32).fill(0x01),
        false
    );
    const ciphertext = await encrypt({ iv: nonce }, key, plaintext);
    const got = Array.from(new Uint8Array(ciphertext), byte => byte.toString(16).padStart(2, "0")).join("");
    const expected = "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271";
    expect(got).toEqual(expected);

    const decrypted = await decrypt({ iv: nonce }, key, ciphertext);
    expect(new Uint8Array(decrypted)).toEqual(plaintext);
});

test("xaes test vector with additional data", async () => {
    const key = await importKey(
        "raw",
        new Uint8Array(32).fill(0x03),
        false
    );
    const aad = new TextEncoder().encode("c2sp.org/XAES-256-GCM");
    const nonce = new TextEncoder().encode("ABCDEFGHIJKLMNOPQRSTUVWX");
    const plaintext = new TextEncoder().encode("XAES-256-GCM");
    const ciphertext = await encrypt({ iv: nonce, additionalData: aad }, key, plaintext);
    const got = Array.from(new Uint8Array(ciphertext), byte => byte.toString(16).padStart(2, "0")).join("");
    const expected = "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d";
    expect(got).toEqual(expected);

    const decrypted = await decrypt({ iv: nonce, additionalData: aad }, key, ciphertext);
    expect(new Uint8Array(decrypted)).toEqual(plaintext);
});

test("xaes test vector, accumulated", async () => {
    const hash = new SHAKE128();
    const rng = new SHAKE128();

    const key = new Uint8Array(32);
    const nonce = new Uint8Array(24);
    const length = new Uint8Array(1);

    for (let i = 0; i < 10000; i++) {
        rng.stream(key);
        rng.stream(nonce);
        rng.stream(length);
        const plaintext = new Uint8Array(length[0]);
        rng.stream(plaintext);
        rng.stream(length);
        const aad = new Uint8Array(length[0]);
        rng.stream(aad);

        const cryptoKey = await importKey("raw", key, false);
        const ciphertext = await encrypt({ iv: nonce, additionalData: aad }, cryptoKey, plaintext);
        const decrypted = await decrypt({ iv: nonce, additionalData: aad }, cryptoKey, ciphertext);
        expect(new Uint8Array(decrypted)).toEqual(plaintext);
        hash.update(new Uint8Array(ciphertext));
    }
    const digest = new Uint8Array(32);
    hash.stream(digest);
    const hashHex = Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
    expect(hashHex).toEqual("e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939");
});
