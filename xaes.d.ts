/**
 * Encrypts data using XAES-256-GCM with the given key and iv.
 * Key must be a 256-bit AES-CBC CryptoKey with 'encrypt' usage.
 *
 * @param {{iv: BufferSource, additionalData?: BufferSource}} params
 *          - encryption parameters, containing the 24-byte iv (nonce)
 *            and optional additional data to authenticate.
 * @param {CryptoKey} key - 256-bit AES-CBC CryptoKey.
 * @param {BufferSource} data - Data to encrypt.
 * @returns {Promise<ArrayBuffer>} - Encrypted data.
 */
export function encrypt(params: {
    iv: BufferSource;
    additionalData?: BufferSource;
}, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer>;
/**
 * Decrypts data using XAES-256-GCM with the given key and iv.
 * Key must be a 256-bit AES-CBC CryptoKey with 'encrypt' and 'decrypt' usages.
 *
 * @param {{iv: BufferSource, additionalData?: BufferSource}} params
 *           - decryption parameters, containing the 24-byte iv (nonce)
 *             and optional additional data to authenticate.
 * @param {CryptoKey} key - 256-bit AES-CBC CryptoKey.
 * @param {BufferSource} data - Data to decrypt.
 * @returns {Promise<ArrayBuffer>} - Decrypted data.
 */
export function decrypt(params: {
    iv: BufferSource;
    additionalData?: BufferSource;
}, key: CryptoKey, data: BufferSource): Promise<ArrayBuffer>;
/**
 * Generate a random key suitable for XAES-256-GCM.
 * The actual key is an AES-CBC CryptoKey with 256-bit length.
 *
 * This function is not necessary, as you can use crypto.subtle.generateKey with AES-CBC directly.
 *
 * @param {boolean} extractable
 * @returns Promise<CryptoKey>
 */
export function generateKey(extractable?: boolean): Promise<CryptoKey>;
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
export function importKey(format: "jwk" | "raw" | "pkcs8" | "spki", keyData: BufferSource | JsonWebKey, extractable?: boolean): Promise<CryptoKey>;
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
export function exportKey(format: "jwk" | "pkcs8" | "raw" | "spki", key: CryptoKey): Promise<ArrayBuffer | JsonWebKey>;
