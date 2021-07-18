# z-crypt

The z-crypt library is a cryptography library for Node.js created on-top of Node.js' Crypto module.

It provides a standardized library to functions or classes for encryption/decryption of strings, buffers, and files utilizing AES-256-CBC with HMAC-SHA-256 and AES with CCM Mode and AAD (Additional authenticated data) via AES-256-CCM, and hashing/salting via PBKDF2S and SHA512.

If you need more information than what this documentation provides, just reach out and I will reply as soon as I can.

```
npm install --save z-crypt
```

## Table of contents

### Encryption / decryption

- <b>[encrypt](#encrypt-data-key--options)</b> | AES-256-CBC with HMAC-SHA256 encryption

- <b>[decrypt](#decrypt-encrypted-key-iv--options)</b> | AES-256-CBC with HMAC-SHA256 decryption

- <b>[encryptCCM](#encryptccm-data-key--options)</b> | AES-256-CCM encryption with optional AAD

- <b>[decryptCCM](#decryptccm-encrypted-key-iv-tag--options)</b> | AES-256-CCM decryption with optional AAD

### Encryption / decryption classes

- <b>[AES Class](#-class-aes-key-)</b> | AES-256-CBC with HMAC-SHA-256
  - <b>[encrypt](#-aesencrypt-data--inencoding--outencoding-)</b>
  - <b>[decrypt](#-aesencrypt-data--inencoding--outencoding-)</b>
- <b>[AES CCM Class](#-aesencrypt-data--inencoding--outencoding-)</b> | AES-256-CCM with optional AAD
  - <b>[encrypt](#-aes_ccmencrypt-data--options-)</b>
  - <b>[decrypt](#-aes_ccmdecrypt-encrypted-tag--options-)</b>

### File encryption / decryption

- <b>[encryptFile](#encryptfile-file-key)</b> | AES-256-CBC with HMAC-SHA256 file encryption

- <b>[decryptFile](#decryptfile-file-key-iv--encoding)</b> | AES-256-CBC with HMAC-SHA256 file decryption

- <b>[encryptFileCCM](#encryptfileccm-file-key--aad)</b> | AES-256-CCM file encryption with optional AAD

- <b>[decryptFileCCM](#decryptfileccm-file-key-iv-tag--options)</b> | AES-256-CCM file decryption with optional AAD

### Hashing

- <b>[hashSHA](#-hashsha-data--salt-)</b> | Hash via SHA-512 with option to add salt

- <b>[hashPBK](#-hashpbk-data--options-)</b> | Hash and salt via PBKDF2

### Util

- <b>[secretKey](#-secretkey--bytes-)</b> Obtain a key of N-Bytes in a hex string for a secretKey or a random hex of N Byte length

### <b>encrypt (data, key, [ options])</b>

---

- <b>data</b> ( String | Buffer ): data to encrypt

- <b>key</b> ( String | Buffer ): secret key for encryption ( 16 Bytes )

* <b>options</b> ( Object ):

  - <b>inE</b> ( String ) ( String ): encoding of the inputed data (<b>default:</b> "utf-8")
  - <b>outE</b> ( String ) ( String ): encoding of the encrypted string (<b>default:</b> "hex")

  - <b>iv</b> ( 16 Byte Buffer | String ): Initial vector for encryption (<b>default:</b> 16 random byte Buffer )

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypts data with provided key via AES-256-CBC-HMAC-SHA-256, and returns the encrypted string as well as the IV (Initial Vector) from encryption, defaults encoding for the input to UTF-8 and the output encrypted string to Hex.

<b>Example Usage:</b>

```
const { encrypt, secretKey } = require('z-crypt');

const data = '1337';
const key = secretKey();

const { encrypted, iv } = encrypt(data, key);

console.log(encrypted);
// output: fe7bdf15e0dc7377bf2c0b9a34f3b7ed
```

### <b>decrypt (encrypted, key, iv, [ options])</b>

---

- <b>encrypted</b> ( String | Buffer ): Encrypted string to decrypt

- <b>key</b> ( 16 Byte Buffer | String ) : Secret key that was used in encryption

- <b>iv</b> ( 16 Byte Buffer | String ): Initial vector used in encryption

* <b>options</b> ( Object ):
  - <b>inE</b> ( String ): encoding of the encrypted string (<b>default:</b> "hex")
  - ( String ): encoding of the output string/data (<b>default:</b> "utf-8")
  - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

<br/>

Decrypts encrypted string via AES-256-CBC-HMAC-SHA-256, using the same key and iv from encryption of that string. Will return the decrypted data in the encoding of choice (<b>default:</b> "utf-8")

<b>Example usage:</b>

```
const {
  encrypt,
  decrypt,
  secretKey,
} = require('z-crypt');

const data = '1337';
const key = secretKey();

const { encrypted, iv } = encrypt(data, key);

console.log(encrypted);
// output: fe7bdf15e0dc7377bf2c0b9a34f3b7ed

const decrypted = decrypt(encrypted, key, iv);

console.log(decrypted);
// output: 1337
```

### <b>encryptCCM (data, key, [ options])</b>

---

- <b>data</b> ( String | Buffer ): data to encrypt

- <b>key</b> ( 16 Byte Buffer | String ) : secret key for encryption ( 16 Bytes )

* <b>options</b> ( Object ):

  - <b>inE</b> ( String ): encoding of the inputed data (<b>default:</b> "utf-8")
  - <b>outE</b> ( String ): encoding of the encrypted string (<b>default:</b> "hex")

  - <b>iv</b> ( 13 Byte Buffer | String ): Initial vector for encryption (<b>default:</b> 13 random byte Buffer )

  - <b>tagLength</b> ( Number ): Length of the authorization tag in bytes (<b>default:</b> 16)

  - <b>aad</b> ( String | Buffer ): Additional authenticated data

    - <b>(Valid tag lengths)</b>: 4, 6, 8, 10, 12, 14 or 16

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypts data with provided key via AES-256-CCM, and returns the encrypted string as well as the IV (Initial Vector) from encryption and the tag (Authorization tag) that is required for decryption, defaults encoding for the input to UTF-8 and the output encrypted string to Hex. Adding in an AAD (Additional authenticated data) can be particulary useful when a secret key is shared and there needs to be limitations / authorization.

<b>Example usage:</b>

```
const { encryptCCM, secretKey } = require('z-crypt');

const key = secretKey();
const aad = 'superPassword';

const data = JSON.stringify({ test: 'hello' });
const { encrypted: e1, tag: t1 } = encryptCCM(data, key);
const { encrypted: e2, tag: t2 } = encryptCCM(data, key, { aad });

console.log(e1);
// outputs: 1494ec89011cf5f8c1215bd61df96444
console.log(e2);
// outputs: 7ada7a33e64483ea43c3ab35ad46c552

console.log(t1);
// outputs: <Buffer d7 88 93 20 9a e3 f2 ec 45 70 22 c7 a4 e4 cc 2c>
console.log(t2);
// outputs: <Buffer 47 e4 a9 38 55 d4 fc 93 5b 90 c7 5c 1f d1 3f 01>
```

### <b>decryptCCM (encrypted, key, iv, tag, [ options])</b>

---

Decrypts encrypted string via AES-256-CCM using the same key, iv, and tag from encryption of that string. Will return the decrypted data in the encoding of choice (<b>default:</b> "utf-8"), if the 'aad' option was used in encryption, it is required for decryption.

- <b>encrypted</b> ( String | Buffer ): Encrypted string to decrypt

- <b>key</b> ( 16 Byte Buffer | String ) : Secret key that was used in encryption

- <b>tag</b> ( String | Buffer ): Authorization tag generated from encryption

- <b>iv</b> ( 16 Byte Buffer | String ): Initial vector used in encryption

* <b>options</b> ( Object ):

  - <b>inE</b> ( String ): encoding of the encrypted string (<b>default:</b> "hex")

  - <b>outE</b> ( String ): encoding of the decrypted string/data (<b>default:</b> "utf-8")

  - <b>tagLength</b> ( Number ): Length of the authorization tag in bytes (<b>default:</b> 16)

  - <b>aad</b> ( String | Buffer ): Additional authenticated data

    - <b>(Valid tag lengths)</b>: 4, 6, 8, 10, 12, 14 or 16

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

<b>Example usage:</b>

```
const {
  encryptCCM,
  decryptCCM,
  secretKey,
} = require('z-crypt');


const key = secretKey();
const data = 'important message';
const aad = 'someSpecialPass';

const { encrypted, tag, iv } = encryptCCM(data, key, { aad });

console.log(tag);
// output: <Buffer 48 dd ab 41 ab 2d 1a 9b 7d d6 44 a0 7d f9 49 c5>

console.log(encrypted);
// output: ee7672dbeb0158d077da760976b361a302

const decrypted = decryptCCM(encrypted, key, iv, tag, { aad });

// Without AAD: const decrypted = decryptCCM(encrypted, key, iv, tag)

console.log(decrypted);
// output: important message
```

### <b> Class: AES (key) </b>

---

- <b>key</b> ( 16 Byte Buffer | String ) : Secret key to use for encryption ( 16 Bytes )

The AES Class implements encryption and decryption via AES-256-CBC w/ HMAC-SHA-256. The class has one other property:

- <b>AES.ivTable</b>: A object that is populated with key value pairs of encrypted strings matched with their Initial Vector, the string will automatically clear the string with it's IV on decryption, or load it on encryption. This object can be used to access the IV for a specific encrypted string.

```
const { secretKey, AES } = require('z-crypt');

const key = secretKey();
const aes = new AES(key);

/*
  aes.ivTable[encryptedString] === encrypted strings IV
*/
```

### <b> AES.encrypt (data, [ inEncoding], [ outEncoding]) </b>

---

- <b>data</b> ( String | Buffer ): data to encrypt

- <b>inEncoding</b> ( String ): encoding of the inputed string/data (<b>default:</b> "utf-8")

- <b>outEncoding</b> ( String ): encoding of the encrypted string (<b>default:</b> "hex")

  - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypt data with the key from the instance, using AES-256-CBC with HMAC-SHA-256, returns the encrypted string, defaults encoding for the input to UTF-8 and the output encrypted string to Hex.

<b> Example usage</b>:

```
const { secretKey, AES } = require('z-crypt');

const key = secretKey();
const aes = new AES(key);

const data = 'important message';
const encrypted = aes.encrypt(data);

console.log(encrypted);
// outputs: 2fa6002ba81918c6....4fa0fda029a2e715cf5
```

### <b> AES.decrypt (encrypted, [ inEncoding], [ outEncoding]) </b>

---

- <b>encrypted</b> ( String | Buffer ): encrypted string to decrypt

- <b>inEncoding</b> ( String ): encoding of the encrypted string (<b>default:</b> "hex")

- <b>outEncoding</b> ( String ): encoding of decrypted string/data (<b>default:</b> "utf-8")

  - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Decrypt encrypted string with the key from the instance, using AES-256-CBC with HMAC-SHA-256, returns the decrypted string, defaults encoding for the input to Hex and the decrypted output to UTF-8.

```
const { secretKey, AES } = require('z-crypt');

const key = secretKey();
const aes = new AES(key);

const data = 'important message';
const encrypted = aes.encrypt(data);

console.log(encrypted);
// outputs: 2fa6002ba81918c6....4fa0fda029a2e715cf5

const decrypted = aes.decrypt(encrypted);

console.log(decrypted);
// outputs: important message
```

### <b> Class: AES_CCM (key) </b>

- <b>key</b> ( 16 Byte Buffer | String ) : Secret key to use for encryption ( 16 Bytes )

The AES_CCM Class implements encryption and decryption via AES-256-CCM Mode with optional AAD (Additional authenticated data). The class has one other property:

- <b>AES_CCM.ivTable</b>: A object that is populated with key value pairs of encrypted strings matched with their Initial Vector, the string will automatically clear the string with it's IV on decryption, or load it on encryption. This object can be used to access the IV for a specific encrypted string.

```
const { secretKey, AES_CCM } = require('z-crypt');

const key = secretKey();
const aesCCM = new AES_CCM(key);

/*
  aesCCM.ivTable[encryptedString] === encrypted strings IV
*/
```

### <b> AES_CCM.encrypt (data, [ options]) </b>

---

- <b>data</b> ( String | Buffer ): data to encrypt

- <b>options</b> ( Object ):

  - <b>inE</b> ( String ): encoding of the inputed data (<b>default:</b> "utf-8")

  - <b>outE</b> ( String ): encoding of the encrypted string (<b>default:</b> "hex")

  - <b>tagLength</b> ( Number ): Length of the authorization tag in bytes (<b>default:</b> 16)

  - <b>aad</b> ( String | Buffer ): Additional authenticated data

    - <b>(Valid tag lengths)</b>: 4, 6, 8, 10, 12, 14 or 16

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Encrypts data with provided key via AES-256-CCM, and returns the encrypted string as well as the IV (Initial Vector) from encryption and the tag (Authorization tag) that is required for decryption, defaults encoding for the input to UTF-8 and the output encrypted stsring to Hex. Adding in an AAD can be particulary useful when a secret key is shared and there needs to be limitations / authorization.

<b>Example usage</b>:

```
const { secretKey, AES_CCM } = require('z-crypt');

const key = secretKey();
const aesCCM = new AES_CCM(key);
const aad = 'superPassword';

const data = JSON.stringify({ test: 'hello' });
const { encrypted: e1, tag: t1 } = aesCCM.encrypt(data);
const { encrypted: e2, tag: t2 } = aesCCM.encrypt(data, { aad });

console.log(e1);
// outputs: fe8531ed330d404533a91e1db3d592f4
console.log(e2);
// outputs: 810ad787ce608236dc5fb10ad25ee409

console.log(t1);
// outputs: <Buffer 07 78 39 4b 77 36 fe 2e f0 3c 37 fd 43 ba c9 fe>
console.log(t2);
// outputs: <Buffer 83 ef 07 e6 92 43 2e d4 26 36 f4 9b c2 71 be 9e>
```

### <b> AES_CCM.decrypt (encrypted, tag, [ options]) </b>

---

- <b>encrypted</b> ( String | Buffer ): Encrypted string to decrypt

- <b>tag</b> ( String | Buffer ): Authorization tag generated from encryption

* <b>options</b> ( Object ):

  - <b>inE</b> ( String ): encoding of the encrypted string (<b>default:</b> "hex")

  - <b>outE</b> ( String ): encoding of the decrypted string/data (<b>default:</b> "utf-8")

  - <b>tagLength</b> ( Number ): Length of the authorization tag in bytes (<b>default:</b> 16)

  - <b>aad</b> ( String | Buffer ): Additional authenticated data

    - <b>(Valid tag lengths)</b>: 4, 6, 8, 10, 12, 14 or 16

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Decrypt encrypted string with the key from the instance, using AES-256-CCM, requiring the authTag and the AAD if one was provided in encryption, returns the decrypted string, defaults encoding for the input to Hex and the decrypted output to UTF-8.

<b>Example usage:</b>

```
const { secretKey, AES_CCM } = require('z-crypt');

const key = secretKey();
const aesCCM = new AES_CCM(key);
const aad = 'superPassword';

const data = JSON.stringify({ test: 'hello' });
const { encrypted: e1, tag: t1 } = aesCCM.encrypt(data);
const { encrypted: e2, tag: t2 } = aesCCM.encrypt(data, { aad });

console.log(e1);
// outputs: fe8531ed330d404533a91e1db3d592f4
console.log(e2);
// outputs: 810ad787ce608236dc5fb10ad25ee409

console.log(t1);
// outputs: <Buffer 07 78 39 4b 77 36 fe 2e f0 3c 37 fd 43 ba c9 fe>
console.log(t2);
// outputs: <Buffer 83 ef 07 e6 92 43 2e d4 26 36 f4 9b c2 71 be 9e>

const decrypted1 = aesCCM.decrypt(e1, t1);
const decrypted2 = aesCCM.decrypt(e2, t2, { aad });

console.log(decrypted1);
// outputs: {"test":"hello"}
console.log(decrypted2);
// outputs: {"test":"hello"}
```

### <b>encryptFile (file, key)</b>

---

- <b>file</b>: Relative path to file to encrypt

- <b>key</b> ( 16 Byte Buffer | String ) : Secret key to encrypt the file with ( 16 Bytes )

Encrypts a file via AES-256-CBC w/ HMAC-SHA-256, and returns the IV required for decryption of the file, will encrypt file data into binary encoding.

<b>Example usage</b>:

```
const { secretKey, encryptFile } = require('z-crypt');

const key = secretKey();
const file = './passwords.txt';

const iv = encryptFile(file, key);
```

### <b>decryptFile (file, key, iv, [ encoding])</b>

---

- <b>file</b>: Relative path to file to encrypt

- <b>key</b> ( 16 Byte Buffer | String ): Secret key to encrypt the file with

- <b>iv</b> ( 16 Byte Buffer | String ): Initial vector from encryption

- <b>encoding</b> ( String ): encoding of the output data written to the file (<b>default</b>: "utf-8")

  - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Decrypts a file via AES-256-CBC w/ HMAC-SHA-256, and will write to the file in the provided encoding but will default to "utf-8".

<b>Example usage</b>:

```
const {
  secretKey,
  encryptFile,
  decryptFile,
} = require('z-crypt');

const key = secretKey();
const file = './passwords.txt';

const iv = encryptFile(file, key);

decryptFile(file, key, iv);
```

### <b>encryptFileCCM (file, key, [ aad])</b>

---

- <b>file</b>: Relative path to file to encrypt

- <b>key</b> ( 16 Byte Buffer | String ) : Secret key to encrypt the file with ( 16 Bytes )

Encrypts a file via AES-256-CBC with the option for AAD, and returns the IV and authorization tag required for decryption of the file, will encrypt file data into binary encoding.

<b>Example usage</b>:

```
const { secretKey, encryptFileCCM } = require('z-crypt');

const key = secretKey();
const file = './passwords.txt';
const aad = 'secretPassword';

const { iv, tag } = encryptFileCCM(file, key, aad);

console.log(iv);
// outputs: <Buffer 17 a2 6b eb ea 39 1b 3d 0e cd e6 ea 55>
console.log(tag);
// outputs: <Buffer ec 6c d7 07 f4 50 e2 eb 97 b8 83 38 48 15 70 a3>
```

### <b>decryptFileCCM (file, key, iv, tag, [ options])</b>

---

- <b>file</b>: Relative path to file to encrypt

- <b>key</b> ( 16 Byte Buffer | String ): Secret key to encrypt the file with

- <b>iv</b> ( 16 Byte Buffer | String ): Initial vector from encryption

* <b>options</b> ( Object ):

  - <b>encoding</b> ( String ): encoding of the output data written to the file (<b>default</b>: "utf-8")

  - <b>aad</b> ( String | Buffer ): Additional authenticated data

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

Decrypts a file via AES-256-CCM, and will write to the file in the provided encoding but will default to "utf-8".

<b>Example usage</b>:

```
const {
  secretKey,
  encryptFileCCM,
  decryptFileCCM,
} = require('z-crypt');

const key = secretKey();
const file = './passwords.txt';
const aad = 'secretPassword';

const { iv, tag } = encryptFileCCM(file, key, aad);

console.log(iv);
// outputs: <Buffer 17 a2 6b eb ea 39 1b 3d 0e cd e6 ea 55>
console.log(tag);
// outputs: <Buffer ec 6c d7 07 f4 50 e2 eb 97 b8 83 38 48 15 70 a3>

decryptFileCCM(file, key, iv, tag, { aad });
```

### <b> hashSHA (data, [ salt]) </b>

---

- <b>data</b> ( String | Buffer ): Data to hash

- <b>salt</b> ( String | Buffer ): Salt to add to the hash

Return a hash from data via SHA-512 with the option of adding a salt.

<b> Example usage: </b>

```
const { hashSHA } = require('z-crypt');

const data = 'myPassword';
const salt = 'salty';

const unsalted = hashSHA(data);
const salted = hashSHA(data, salt);

console.log(unsalted);
// outputs: 450ad03db9395d2...
console.log(salted);
// outputs: d98dd23ac326054...
```

### <b> hashPBK (data, [ options]) </b>

---

- <b>data</b> ( String | Buffer ): Data to hash

* <b> options </b> (Object):

  - <b> salt </b> ( String | Buffer ): Salt to add to the hash (<b>default</b>: 116-10116 random bytes)

  - <b> iters </b> ( Number ): Number of iterations, the more the better the hash, but the longer it will take (<b>default</b>: 100000)

  - <b> keyLen </b> ( Number ): Length of the output key (<b>default</b>: 64)

  - <b> digest </b> ( String ): Digest algorithim for the hash (<b>default</b>: "sha512")

  - <b> encoding </b> ( String ): Encoding of the output hash (<b>default</b>: "hex")

    - <b>(Valid encodings)</b>: utf-8, ascii, base64, hex, ucs-2, binary, latin1

    - <b>(Valid digests)</b>: sha1, sha256, sha512, md5

Return a salted hash from data via PBKDF2, will default the digest to use SHA-512 and the encoding will be defaulted to Hex.

<b> Example usage</b>:

```
const { hashPBK } = require('z-crypt');

const data = 'myPassword';

const hash = hashPBK(data);

console.log(hash);
// outputs: 167620e0e3e44d73....
```

### <b> secretKey ([ bytes]) </b>

---

- <b> bytes </b> ( Number ): Amount of bytes for the hex key (<b>default</b>: 16)

Returns a hex key from a amount of random bytes.

<b> Example usage </b>:

```
const { secretKey } = require('z-crypt');

const key = secretKey();

console.log(key);
// outputs: 33acac780481ac9341df3528a3b1e7fb
```
