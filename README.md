# cryptic-js

The cryptic library is a cryptography library for Node.js created on-top of Node.js' Crypto module.

It provides a standardized API to functions or classes for encryption/decryption of strings, data, and files utilizing AES-256-CBC with HMAC-SHA-256 and AES with CCM Mode and AAD authorization with AES-256-CCM, and hashing/salting with PBKDF2S and SHA512.

If you need more information than what this documentation provides, just reach out and I will reply as soon as I can.

```
npm install --save cryptic-js
```

## Table of contents

### Stand-alone encryption / decryption

- <b>[encrypt](#encrypt-data-key--options)</b> | AES-256-CBC with HMAC-SHA256 encryption

- <b>[decrypt](#decrypt-encrypted-key-iv--options)</b> | AES-256-CBC with HMAC-SHA256 decryption

- <b>[encryptCCM](#encryptccm-data-key--options)</b> | AES-256-CCM encryption with optional AAD

- <b>[decryptCCM](#decryptccm-encrypted-key-iv-tag--options)</b> | AES-256-CCM decryption with optional AAD

### Encryption classes

- <b>[AES Class](#AES-Class)</b> | AES-256-CBC with HMAC-SHA-256
  - [encrypt](#AES.encrypt)
  - [decrypt](#AES.decrypt)
- <b>[AES CCM Class](#AES-CCM-Class)</b> | AES-256-CCM with optional AAD
  - [encrypt](#AES_CCM.encrypt)
  - [decrypt](#AES_CCM.decrypt)

### File encryption

- <b>[encryptFile](#)</b> | AES-256-CBC with HMAC-SHA256 file encryption

- <b>[decryptFile](#)</b> | AES-256-CBC with HMAC-SHA256 file decryption

- <b>[encryptFileCCM](#)</b> | AES-256-CCM file encryption with optional AAD

- <b>[decryptFileCCM](#)</b> | AES-256-CCM file decryption with optional AAD

### <b>encrypt (data, key, [ options])</b>

---

- <b>data</b>: string/data to encrypt

- <b>key</b>: secret key for encryption ( 16 Bytes )

* <b>options</b>:

  - <b>inE</b>: encoding of the inputed data (<b>default:</b> "utf-8")
  - <b>outE</b>: encoding of the encrypted string (<b>default:</b> "hex")

  - <b>iv</b>: Initial vector for encryption (<b>default:</b> 16 random byte Buffer )

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypts data with provided key via AES-256-CBC-HMAC-SHA-256, and returns the encrypted string as well as the IV (Initial Vector) from encryption, defaults encoding for the input to UTF-8 and the output encrypted string to Hex.

<b>Example Usage</b>:

```
const { encrypt, secretKey } = require('cryptic-js');

const data = '1337';
const key = secretKey(16);

const { encrypted, iv } = encrypt(data, key);

console.log(encrypted);
// output: fe7bdf15e0dc7377bf2c0b9a34f3b7ed

/*
  Example with custom options:

  encrypt(data, key, {
    inE: *some valid encoding*,
    outE: *some valid encoding*,
    iv: *something of 16 bytes*,
  });

*/
```

### <b>decrypt (encrypted, key, iv, [ options])</b>

---

- <b>encrypted</b>: Encrypted string to decrypt

- <b>key</b>: Secret key that was used in encryption

- <b>iv</b>: Initial vector used in encryption

* <b>options</b>:
  - <b>inE</b>: encoding of the encrypted string (<b>default:</b> "hex")
  - <b>outE</b>: encoding of the output string/data (<b>default:</b> "utf-8")
    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

<br/>

Decrypts encrypted string via AES-256-CBC-HMAC-SHA-256, using the same key and iv from encryption of that string. Will return the decrypted data in the encoding of choice (<b>default:</b> "utf-8")

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

/*
  Example with custom encodings:

  decrypt(data, key, iv, {
    inE: *some valid encoding*,
    outE: *some valid encoding*,
  });

*/
```

### <b>encryptCCM (data, key, [ options])</b>

---

- <b>data</b>: string/data to encrypt

- <b>key</b>: secret key for encryption ( 16 Bytes )

* <b>options</b>:

  - <b>inE</b>: encoding of the inputed data (<b>default:</b> "utf-8")
  - <b>outE</b>: encoding of the encrypted string (<b>default:</b> "hex")

  - <b>iv</b>: Initial vector for encryption (<b>default:</b> 13 random byte Buffer )
  - <b>tagLength</b>: Length of the authorization tag in bytes (<b>default:</b> 16)

  - <b>aad</b> (Optional): Additional authenticated data ( string or buffer )

    - <b>(Valid tag lengths)</b>: 4, 6, 8, 10, 12, 14 or 16

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypts data with provided key via AES-256-CCM, and returns the encrypted string as well as the IV (Initial Vector) from encryption and the tag (Authorization tag) that is required for decryption, defaults encoding for the input to UTF-8 and the output encrypted string to Hex.

<b>Example usage</b>:

```
// const { encryptCCM, secretKey } = require('cryptic-js');

const key = secretKey(16);
const data = 'important message';
const aad = 'someSpecialPass';

const { encrypted, tag, iv } = encryptCCM(data, key, { aad });

// Without AAD: const { encrypted, tag, iv } = encryptCCM(data, key);

console.log(tag);
// output: <Buffer 48 dd ab 41 ab 2d 1a 9b 7d d6 44 a0 7d f9 49 c5>

console.log(encrypted);
// output: ee7672dbeb0158d077da760976b361a302

/*
  Example with custom options:

  encryptCCM(data, key, {
    inE: *some valid encoding*,
    outE: *some valid encoding*,
    aad: *some Buffer or string*,
    tagLength: *some valid tag length*,
  });

*/
```

### <b>decryptCCM (encrypted, key, iv, tag, [ options])</b>

---

Decrypts encrypted string via AES-256-CCM using the same key, iv, and tag from encryption of that string. Will return the decrypted data in the encoding of choice (<b>default:</b> "utf-8"), if the 'aad' option was used in encryption, it is required for decryption.

- <b>encrypted</b>: Encrypted string to decrypt

- <b>key</b>: Secret key that was used in encryption

- <b>tag</b>: Authorization tag generated from encryptCCM

- <b>iv</b>: Initial vector used in encryption

* <b>options</b>:

  - <b>inE</b>: encoding of the encrypted string (<b>default:</b> "hex")

  - <b>outE</b>: encoding of the decrypted string/data (<b>default:</b> "utf-8")

  - <b>tagLength</b>: Length of the authorization tag in bytes (<b>default:</b> 16)

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


/*
  Example with custom options:

  decryptCCM(data, key, iv, {
    inE: *some valid encoding*,
    outE: *some valid encoding*,
    aad: *some Buffer or string*,
    tagLength: *some valid tag length*,
  });

*/
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

/*
  aes.ivTable[encryptedString] === encrypted strings IV
*/
```

### <b> AES.encrypt(data, [ inEncoding], [ outEncoding]) </b>

---

- <b>data</b>: string/data/object/array to encrypt

- <b>inEncoding</b>: encoding of the inputed string/data (<b><b>default:</b></b> "utf-8")

- <b>outEncoding</b>: encoding of the encrypted string (<b><b>default:</b></b> "hex")

  - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypt data with the key from the instance, using AES-256-CBC with HMAC-SHA-256, returns the encrypted string, defaults encoding for the input to UTF-8 and the output encrypted string to Hex.

<b> Example usage</b>:

```
const { secretKey, AES } = require('cryptic-js');

const key = secretKey(16);
const aes = new AES(key);

const data = 'important message';
const encrypted = aes.encrypt(data);

console.log(encrypted);
// outputs: 2fa6002ba81918c6....4fa0fda029a2e715cf5

/*
  To change the encoding on the input / output:

  aes.encrypt(data, *some valid encoding*, *some valid encoding*);
*/
```

### <b> AES.decrypt(encrypted, [ inEncoding], [ outEncoding]) </b>

---

- <b>encrypted</b>: encrypted string to decrypt

- <b>inEncoding</b>: encoding of the encrypted string (<b><b>default:</b></b> "hex")

- <b>outEncoding</b>: encoding of decrypted string/data (<b><b>default:</b></b> "utf-8")

  - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

```
const { secretKey, AES } = require('cryptic-js');

const key = secretKey(16);
const aes = new AES(key);

const data = 'important message';
const encrypted = aes.encrypt(data);

console.log(encrypted);
// outputs: 2fa6002ba81918c6....4fa0fda029a2e715cf5

const decrypted = aes.decrypt(encrypted);

console.log(decrypted);
// outputs: important message

/*
  Ex. of changing the encoding on the input / output:

  aes.decrypt(data, *some valid encoding*, *some valid encoding*);
*/
```
