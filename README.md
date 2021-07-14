# cryptic-js

The cryptic library is a cryptography library for Node.js created on-top of Node.js' Crypto module.

It provides a standardized API to access encryption/decryption of data/strings and files utilizing AES-256-CBC with HMAC-SHA-256 and support for CCM Mode and AAD authorization with AES-256-CCM, and hashing/salting with PBKDF2S and SHA512.

```
npm install --save cryptic-js
```

## Table of contents

### Stand-alone encryption

- [encrypt](#encrypt) | AES-256-CBC with HMAC-SHA256 encryption
- [decrypt](#decrypt) | AES-256-CBC with HMAC-SHA256 decryption
- [encryptCCM](#encryptCCM) | AES-256-CCM encryption with optional AAD
- [decryptCCM](#decryptCCM) | AES-256-CCM decryption with optional AAD

### Encryption classes

- [AES Class](#AES-Class) | AES-256-CBC with HMAC-SHA-256
  - [encrypt](#AES.encrypt)
  - [decrypt](#AES.decrypt)
- [AES CCM Class](#AES-CCM-Class) | AES-256-CCM with optional AAD
  - [encrypt](#AES_CCM.encrypt)
  - [decrypt](#AES_CCM.decrypt)

### File encryption

- [encryptFile](#encryptFile) | AES-256-CBC with HMAC-SHA256 file encryption
- [decryptFile](#decryptFile) | AES-256-CBC with HMAC-SHA256 file decryption
- [encryptFileCCM](#encryptFileCCM) | AES-256-CCM file encryption with optional AAD
- [decryptFileCCM](#decryptFileCCM) | AES-256-CCM file decryption with optional AAD

### <b>encrypt (data, key, [ options])</b>

---

- <b>data</b>: Data/string/object/array to encrypt
- <b>key</b>: Secret key for encryption ( 16 Bytes )

* <b>options</b>:
  - <b>inE</b>: encoding of the inputed data (default: "utf-8")
  - <b>outE</b>: encoding of the encrypted string (default: "hex")
  - <b>iv</b> (Optional): Initial vector for encryption, by default will generate a random Buffer of 16 bytes for you

Encrypts data with provided key, and returns the encrypted string as well as the IV (Initial Vector) from encryption.

Note: Will accept Objects / Arrays but will JSON.stringify them

<b>Example Usage</b>:

```
const { encrypt, secretKey } = require('cryptic-js');

const data = '1337';
const key = secretKey(16);

const { encrypted, iv } = encrypt(data, key);

console.log(encrypted);
// output: fe7bdf15e0dc7377bf2c0b9a34f3b7ed
```

### <b>decrypt (encrypted, key, iv, [ options])</b>

---

Decrypts encrypted string, using the same key and iv from encryption of that string. Will return the decrypted data in the encoding of choice (default: "utf-8")

- <b>encrypted</b>: Encrypted string to decrypt
- <b>key</b>: Secret key that was used in encryption
- <b>iv</b>: Initial vector used in encryption

* <b>options</b>:
  - <b>inE</b>: encoding of the encrypted string (default: "hex")
  - <b>outE</b>: encoding of the encrypted string (default: "utf-8")

<b>Example usage</b>:

```
const {
  encrypt,
  decrypt,
  secretKey,
} = require('cryptic-js');

const data = '1337';
const key = secretKey(16);

const { encrypted, iv } = encrypt(data, key);

console.log(encrypted);
// output: fe7bdf15e0dc7377bf2c0b9a34f3b7ed

const decrypted = decrypt(encrypted, key, iv);

console.log(decrypted);
// output: 1337
```
