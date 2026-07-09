// @ts-check

/**
 * Implementation of XAES-256-GCM as defined in https://c2sp.org/XAES-256-GCM
 * based on the Web Cryptography API (https://www.w3.org/TR/WebCryptoAPI/).
 *
 * It uses a 256-bit AES-CBC CryptoKey and a 192-bit nonce to derive
 * a 256-bit key and a 96-bit nonce for AES-GCM.
 *
 * Due to the use of the standard CryptoKey and Web Cryptography API operations,
 * this implementation is fully compatible with other parts of the Web Cryptography API.
 * For example, keys can be stored in IndexedDB and be non-extractable. The only
 * additional requirement is that the key must have 'encrypt' usage even for decryption,
 * however, there's no real distinction between encryption and decryption operations
 * for AES-GCM anyway (you can simulate decryption by encrypting the ciphertext).
 */

/**
 * Generates an AES block using the given key and data xored with the given xor.
 *
 * @param {CryptoKey} key
 * @param {BufferSource} data
 * @param {BufferSource} xor
 * @returns {Promise<Uint8Array>}
 */
async function aesBlock(key, data, xor) {
    const block = await crypto.subtle.encrypt(
        { name: "AES-CBC", iv: xor }, key, data
    );
    return new Uint8Array(block, 0, 16);
}

/**
 * Derives a half key.
 *
 * @param {number} index
 * @param {CryptoKey} key
 * @param {Uint8Array} iv
 * @param {Uint8Array} k1
 * @returns {Promise<Uint8Array>}
 */
async function halfKey(index, key, iv, k1) {
    const m = new Uint8Array(16);
    m[1] = index;
    m[2] = 0x58; // 'X'
    m.set(iv.subarray(0, 12), 4);
    return await aesBlock(key, m, k1);
}

/**
 * Derives a 256-bit key and 96-bit nonce from the given 256-bit key and a 192-bit nonce.
 *
 * @param {CryptoKey} key
 * @param {BufferSource} iv
 * @param {boolean} keyCommitment
 * @returns {Promise<{key: CryptoKey, iv: Uint8Array, kc?: Uint8Array}>}
 */
async function deriveKeyNonce(key, iv, keyCommitment) {
    if (key.algorithm.name != "AES-CBC") {
        throw new Error("key must be for AES-CBC");
    }
    if (!key.usages.includes("encrypt")) {
        throw new Error("key must have 'encrypt' usage");
    }
    // @ts-ignore-next-line
    if (key.algorithm.length != 256) {
        throw new Error("key must be 256 bits");
    }
    if (iv == null || iv.byteLength != 24) {
        throw new Error("iv must be 24 bytes");
    }
    const ivBytes = ArrayBuffer.isView(iv)
        ? new Uint8Array(iv.buffer, iv.byteOffset, iv.byteLength)
        : new Uint8Array(iv);
    const k1 = await aesBlock(key, new Uint8Array(16), new Uint8Array(16));

    let msb = k1[0] >> 7;
    for (let i = 0; i < 15; i++) {
        k1[i] = k1[i] << 1 | k1[i + 1] >> 7;
    }
    k1[15] = k1[15] << 1;
    k1[15] ^= 0x87 & ~(msb - 1);

    const dkBytes = new Uint8Array(32);
    dkBytes.set(await halfKey(0x01, key, ivBytes, k1), 0);
    dkBytes.set(await halfKey(0x02, key, ivBytes, k1), 16);

    const dk = await crypto.subtle.importKey(
        "raw",
        dkBytes,
        { name: "AES-GCM", length: 256 },
        false,
        [...key.usages]
    );
    if (!keyCommitment) {
        return {
            key: dk,
            iv: ivBytes.subarray(12)
        };
    }

    const c3 = new Uint8Array([0x58, 0x43, 0x4D, 0x54, ...ivBytes.subarray(0, 12)]);
    const c4 = new Uint8Array([...ivBytes.subarray(12),  0x00, 0x01, 0x00, 0x01]);
    const c5 = new Uint8Array([...ivBytes.subarray(12),  0x00, 0x01, 0x00, 0x02]);
    let x1 = await aesBlock(key, c3, new Uint8Array(16));
    let x1xc4 = x1.map((x, i) => x ^ c4[i]);
    let x1xc5 = x1.map((x, i) => x ^ c5[i]);
    const kc = new Uint8Array(32);
    kc.set(await aesBlock(key, x1xc4, k1), 0);
    kc.set(await aesBlock(key, x1xc5, k1), 16);

    return {
        key: dk,
        iv: ivBytes.subarray(12),
        kc,
    };
}

/**
 * Compares two arrays of equal length in constant time.
 *
 * @param {Uint8Array} a
 * @param {Uint8Array} b
 * @returns {boolean}
 */
function bytesEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) {
        diff |= a[i] ^ b[i];
    }
    return diff === 0;
}

/**
 * Encrypts data using XAES-256-GCM with the given key and iv.
 * Key must be a 256-bit AES-CBC CryptoKey with 'encrypt' usage.
 *
 * @param {{iv: BufferSource, additionalData?: BufferSource, keyCommitment?: boolean}} params
 *          - encryption parameters, containing the 24-byte iv (nonce)
 *            and optional additional data to authenticate.
 *            If keyCommitment is true, appends 32-byte key commitment.
 * @param {CryptoKey} key - 256-bit AES-CBC CryptoKey.
 * @param {BufferSource} data - Data to encrypt.
 * @returns {Promise<ArrayBuffer>} - Encrypted data.
 */
export async function encrypt(params, key, data) {
    const derived = await deriveKeyNonce(key, params.iv, !!params.keyCommitment);
    const result = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: derived.iv,
            tagLength: 128,
            additionalData: params.additionalData ?? new Uint8Array()
        },
        derived.key,
        data
    );
    if (!derived.kc) {
        return result;
    }
    const ct = new Uint8Array(result);
    const out = new Uint8Array(ct.length + derived.kc.length);
    out.set(ct);
    out.set(derived.kc, ct.length);
    return out;
}

/**
 * Decrypts data using XAES-256-GCM with the given key and iv.
 * Key must be a 256-bit AES-CBC CryptoKey with 'encrypt' and 'decrypt' usages.
 *
 * @param {{iv: BufferSource, additionalData?: BufferSource, keyCommitment?: boolean}} params
 *           - decryption parameters, containing the 24-byte iv (nonce)
 *             and optional additional data to authenticate.
 *            If keyCommitment is true, verifies key commitment.
 * @param {CryptoKey} key - 256-bit AES-CBC CryptoKey.
 * @param {BufferSource} data - Data to decrypt.
 * @returns {Promise<ArrayBuffer>} - Decrypted data.
 */
export async function decrypt(params, key, data) {
    const derived = await deriveKeyNonce(key, params.iv, !!params.keyCommitment);
    if (derived.kc) {
        const dataBytes = ArrayBuffer.isView(data)
            ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
            : new Uint8Array(data);

        if (dataBytes.length < 48 || !bytesEqual(derived.kc, dataBytes.subarray(dataBytes.length - 32))) {
            throw new Error();
        }
        data = dataBytes.subarray(0, dataBytes.length - 32);
    }
    return await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: derived.iv,
            tagLength: 128,
            additionalData: params.additionalData ?? new Uint8Array()
        },
        derived.key,
        data
    );
}


/**
 * Generate a random key suitable for XAES-256-GCM.
 * The actual key is an AES-CBC CryptoKey with 256-bit length.
 *
 * This function is not necessary, as you can use crypto.subtle.generateKey with AES-CBC directly.
 *
 * @param {boolean} extractable
 * @returns Promise<CryptoKey>
 */
export async function generateKey(extractable = false) {
    return await crypto.subtle.generateKey(
        {
            name: "AES-CBC",
            length: 256
        },
        extractable,
        ["encrypt", "decrypt"]
    );
}

/**
 * Import a key suitable for XAES-256-GCM.
 * The actual key must be an AES-CBC CryptoKey with 256-bit length.
 *
 * This function is not necessary, as you can use crypto.subtle.importKey with AES-CBC directly.
 *
 * @param {"jwk" | "raw" | "pkcs8" | "spki"} format
 * @param {BufferSource | JsonWebKey} keyData
 * @param {boolean} extractable
 * @returns {Promise<CryptoKey>}
 */
export async function importKey(format, keyData, extractable = false) {
    return await crypto.subtle.importKey(  // @ts-ignore-next-line
        format,
        keyData,
        { name: "AES-CBC", length: 256 },
        extractable,
        ["encrypt", "decrypt"]
    );
}

/**
 * Export a key.
 * The resulting export will have AES-CBC algorithm specified.
 *
 * This function is not necessary, as you can use crypto.subtle.exportKey directly.
 *
 * @param {"jwk" | "pkcs8" | "raw" | "spki"} format
 * @param {CryptoKey} key
 * @returns {Promise<ArrayBuffer | JsonWebKey>}
 */
export async function exportKey(format, key) {
    return await crypto.subtle.exportKey(format, key);
}
