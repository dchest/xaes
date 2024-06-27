# xaes

Implementation of XAES-256-GCM as defined in <https://c2sp.org/XAES-256-GCM>
based on the Web Cryptography API <https://www.w3.org/TR/WebCryptoAPI/>.

It uses a 256-bit AES-CBC CryptoKey and a 192-bit nonce to derive
a 256-bit key and a 96-bit nonce for AES-GCM.

Due to the use of the standard CryptoKey and Web Cryptography API operations,
this implementation is fully compatible with other parts of the Web Cryptography API.
For example, keys can be stored in IndexedDB and be non-extractable. The only
additional requirement is that the key must have 'encrypt' usage even for decryption,
however, there's no real distinction between encryption and decryption operations
for AES-GCM anyway (you can simulate decryption by encrypting the ciphertext).

## Installation

```
npm install xaes
```

## Example

```javascript
import { encrypt, decrypt, importKey } from 'xaes';

(async () => {
  const keyBytes = new Uint8Array(32).fill(0x1);
  const key = await importKey('raw', keyBytes, true);

  const iv = new Uint8Array(24).fill(0x2);
  const plaintext = new TextEncoder().encode('Hello, World!');
  const additionalData = new TextEncoder().encode('Additional Data');

  const ciphertext = await encrypt({ iv, additionalData }, key, plaintext);
  const decrypted = await decrypt({ iv, additionalData }, key, ciphertext);
  console.log(new TextDecoder().decode(decrypted)); // Hello, World!
})();
```
