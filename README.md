# cryptic-js

The cryptic library is a cryptography library for Node.js created on-top of Node.js' Crypto module.

It provides a standardized API to access encryption/decryption of data/strings and files utilizing AES-256-CBC with HMAC-SHA-256 and support for CCM Mode and AAD authorization with AES-256-CCM, and hashing/salting with PBKDF2S and SHA512. The stand-alone functions offer more/easier customization while the classes are designed for repetitive

```
npm install --save cryptic-js
```

## Table of contents

### Stand-alone encryption

- [encrypt](#encrypt-data-key--options) | AES-256-CBC with HMAC-SHA256 encryption

- [decrypt](#decrypt-encrypted-key-iv--options) | AES-256-CBC with HMAC-SHA256 decryption

- [encryptCCM](#encryptccm-data-key--options) | AES-256-CCM encryption with optional AAD

- [decryptCCM](#decryptccm-encrypted-key-iv-tag--options) | AES-256-CCM decryption with optional AAD

### Encryption classes

- [AES Class](#AES-Class) | AES-256-CBC with HMAC-SHA-256
  - [encrypt](#AES.encrypt)
  - [decrypt](#AES.decrypt)
- [AES CCM Class](#AES-CCM-Class) | AES-256-CCM with optional AAD
  - [encrypt](#AES_CCM.encrypt)
  - [decrypt](#AES_CCM.decrypt)

### File encryption

- [encryptFile](#) | AES-256-CBC with HMAC-SHA256 file encryption

- [decryptFile](#) | AES-256-CBC with HMAC-SHA256 file decryption

- [encryptFileCCM](#) | AES-256-CCM file encryption with optional AAD

- [decryptFileCCM](#) | AES-256-CCM file decryption with optional AAD

### <b>encrypt (data, key, [ options])</b>

---

- <b>data</b>: Data/string/object/array to encrypt

- <b>key</b>: Secret key for encryption ( 16 Bytes )

* <b>options</b>:

  - <b>inE</b>: encoding of the inputed data (default: "utf-8")
  - <b>outE</b>: encoding of the encrypted string (default: "hex")

  - <b>iv</b>: Initial vector for encryption (default: 16 random byte Buffer )

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypts data with provided key via AES-256-CBC-HMAC-SHA-256, and returns the encrypted string as well as the IV (Initial Vector) from encryption, defaults encoding for the input to UTF-8 and the output encrypted string to Hex.

Note: Will accept Objects / Arrays as data param but will JSON.stringify them

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

- <b>encrypted</b>: Encrypted string to decrypt

- <b>key</b>: Secret key that was used in encryption

- <b>iv</b>: Initial vector used in encryption

* <b>options</b>:
  - <b>inE</b>: encoding of the encrypted string (default: "hex")
  - <b>outE</b>: encoding of the encrypted string (default: "utf-8")
    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

<br/>

Decrypts encrypted string via AES-256-CBC-HMAC-SHA-256, using the same key and iv from encryption of that string. Will return the decrypted data in the encoding of choice (default: "utf-8")

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

### <b>encryptCCM (data, key, [ options])</b>

---

- <b>data</b>: Data/string/object/array to encrypt

- <b>key</b>: Secret key for encryption ( 16 Bytes )

* <b>options</b>:

  - <b>inE</b>: encoding of the inputed data (default: "utf-8")
  - <b>outE</b>: encoding of the encrypted string (default: "hex")

  - <b>iv</b>: Initial vector for encryption (default: 13 random byte Buffer )
  - <b>tagLength</b>: Length of the authorization tag in bytes (default: 16)

  - <b>aad</b> (Optional): Additional authenticated data ( string or buffer )

    - <b>(Valid tag lengths)</b>: 4, 6, 8, 10, 12, 14 or 16

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypts data with provided key via AES-256-CCM, and returns the encrypted string as well as the IV (Initial Vector) from encryption and the tag (Authorization tag) that is required for decryption, defaults encoding for the input to UTF-8 and the output encrypted string to Hex.

Note: Will accept Objects / Arrays as data param but will JSON.stringify them

<b>Example usage</b>:

```
// const { encryptCCM, secretKey } = require('cryptic-js');

const key = secretKey(16);
const data = 'important message';
const aad = 'someSpecialPass';

const { encrypted, tag, iv } = encryptCCM(data, key, { aad });

// OR Without AAD
// const { encrypted, tag, iv } = encryptCCM(data, key);

console.log(tag);
// output: <Buffer 48 dd ab 41 ab 2d 1a 9b 7d d6 44 a0 7d f9 49 c5>

console.log(encrypted);
// output: ee7672dbeb0158d077da760976b361a302
```

### <b>decryptCCM (encrypted, key, iv, tag, [ options])</b>

---

Decrypts encrypted string via AES-256-CCM using the same key, iv, and tag from encryption of that string. Will return the decrypted data in the encoding of choice (default: "utf-8"), if the 'aad' option was used in encryption, it is required for decryption.

- <b>encrypted</b>: Encrypted string to decrypt

- <b>key</b>: Secret key that was used in encryption

- <b>tag</b>: Authorization tag generated from encryptCCM

- <b>iv</b>: Initial vector used in encryption

* <b>options</b>:

  - <b>inE</b>: encoding of the encrypted string (default: "hex")

  - <b>outE</b>: encoding of the encrypted string (default: "utf-8")

  - <b>tagLength</b>: Length of the authorization tag in bytes (default: 16)

  - <b>aad</b> (Optional): Additional authenticated data ( string or buffer )

    - <b>(Valid tag lengths)</b>: 4, 6, 8, 10, 12, 14 or 16

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

<b>Example usage</b>:

```
const {
  encryptCCM,
  decryptCCM,
  secretKey,
} = require('cryptic-js');


const key = secretKey(16);
const data = 'important message';
const aad = 'someSpecialPass';

const { encrypted, tag, iv } = encryptCCM(data, key, { aad });

// Without AAD: const { encrypted, tag, iv } = encryptCCM(data, key);

console.log(tag);
// output: <Buffer 48 dd ab 41 ab 2d 1a 9b 7d d6 44 a0 7d f9 49 c5>

console.log(encrypted);
// output: ee7672dbeb0158d077da760976b361a302

const decrypted = decryptCCM(encrypted, key, iv, tag, { aad });

// Without AAD: const decrypted = decryptCCM(encrypted, key, iv, tag)

console.log(decrypted);
// output: important message
```

### <b> Class: AES(key) </b>

---

- <b>key</b>: Secret key to use for encryption ( 16 Bytes )

The AES Class implements encryption and decryption via AES-256-CBC w/ HMAC-SHA-256. The class has one other property:

- <b>AES.ivTable</b>: A object that is populated with key value pairs of encrypted strings matched with their Initial Vector, this simplifies use, and will automatically clear the string with it's IV on decryption, or load it on encryption. This object can be used to access the IV for a specific encrypted string.

```
const { secretKey, AES } = require('cryptic-js');

const key = secretKey(16);
const aes = new AES(key);
```

### <b> AES.encrypt(data, [ inEncoding], [ outEncoding]) </b>

---

- <b>data</b>: Data/string/object/array to encrypt

- <b>inEncoding</b>: encoding of the inputed data (default: "utf-8")
- <b>outEncoding</b>: encoding of the encrypted string (default: "hex")

  - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypt data with the key from the instance, using AES-256-CBC with HMAC-SHA-256, returns the encrypted string, defaults encoding for the input to UTF-8 and the output encrypted string to Hex.

Note: if you need access to the IV from the encryption for transmission, access it through the AES.ivTable

```
AES.ivTable[encryptedString] === encrypted strings IV
```

<b> Example usage</b>:

```
const { secretKey, AES } = require('cryptic-js');

const key = secretKey(16);
const aes = new AES(key);

const data = 'important message';

const encrypted = aes.encrypt(data);

console.log(encrypted);
// outputs: 2fa6002ba81918c6....4fa0fda029a2e715cf5
```
