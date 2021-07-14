# cryptic-js

Node-JS Cryptography Library implementing the following

- AES-256-CBC with HMAC-SHA256 encryption and decryption

- AES-256-CCM Mode(and AAD) encrpytion and decryption

- Hashing + Salting via PBKDF2S/SHA512

- File encryption and decrpytion via AES-256-CBC-HMAC-SHA256 or AES-256-CCM

The Library is split into Classes, that take on a key and use re-use it, and core functions that either add utility or achieve similiar things with more options avaliable.

---

Layout

- <b>AES Class</b> | AES-256-CBC-HMAC-SHA256 encryption/decryption
- <b> AES_CCM Class </b> | AES-256-CCM with AAD encryption/decryption

- <b> encrypt/decrypt </b> | AES-256-CBC-HMAC-SHA256 encryption decryption with optional param to provide custom IV ( Initial Vector )

- <b> encryptCCM/decryptCCM</b> | AES-256-CCM encryption/decryption with optional params to provide custom IV or AAD ( Additional authenticated data )

- <b> hashPBK </b> | Hash and then salt data/string, using PBKDF2S

- <b> hashSHA </b> | Hash with optional salt, using SHA512

- <b> encryptFile/decrpytFile </b> | File encryption and decryption, utilizing AES-256-CBC with HMAC-SHA256

- <b> encryptFileCCM/decryptFileCCM </b> | File encryption and decryption, utilizing AES-256-CCM

- <b> secretKey </b> | Util function to generate a hex key of N bytes

---

## <b>AES Class</b>

### <b>constructor:</b> AES(key)

### <b>key</b>: Secret key ( 16 Bytes string or buffer )

```
  const { AES } = require('cryptic-js');

  const key = '2ba4ac21202c7619bc16e359e84fdc70';
  const aes = new AES(key);
```

The AES Class has a property called 'ivTable', here the IV's of the encrypted strings are stored and will be removed on decryption and a property called 'key' where the secret key is stored.

---

### <b>AES.encrypt:</b> (data, inEncoding, outEncoding)

<br>
Encrypt data/string via AES-256-CBC with key from instance, returns the encrypted string in the encoding of your choice via outEncoding. Note: If passed an Object or array, will convert to a JSON string in utf-8 encoding, but is reccomended only to pass strings.
<br></br>
This function will store the initial vector inside the instance via the ivTable, for lookup on decryption later, you can also obtain it via property access of the 'ivTable'
<br></br>

```
  aes.ivTable[encryptedString] === IV for the encrypted string
```

<b>data:</b> String/Data to be encrypted
<br><br>
<b>inEncoding</b>: Encoding of the inputed Data/String Ex. hex, utf-8, binary
<br><br>
<b>outEncoding</b>: Encoding of the returned encrypted string
<br><br>
Valid encodings include:
<br><br>
hex, binary, base64, utf-8, usc2, utf16le, latin1, ascii
<br><br>

```
  Example Usage:

      const { AES } = require('cryptic-js');

      const key = '2ba4ac21202c7619bc16e359e84fdc70';
      const aes = new AES(key);

      const data = JSON.stringify({ hello: 'world' });

      const encrypted = aes.encrypt(data, 'utf-8', 'hex');

      console.log(encrypted);
      // cf05edcfa2....d83da6101349db0f4df46c078f73d2cc90823d8e26
```

---

### <b>AES.decrypt:</b> (encrypted, inEncoding, outEncoding)

<br>
Decrypt encrypted string via AES-256-CBC with key from instance, returns the decrypted data/string in the encoding of your choice via outEncoding.
<br><br>
<b>data:</b> String/Data to be encrypted
<br><br>
<b>inEncoding</b>: Encoding of the inputed Data/String Ex. hex, utf-8, binary
<br><br>
<b>outEncoding</b>: Encoding of the returned encrypted string
<br><br>
Valid encodings include:
<br><br>
hex, binary, base64, utf-8, usc2, utf16le, latin1, ascii
<br><br>

```
  Example Usage:

      const { AES } = require('cryptic-js');

      const key = '2ba4ac21202c7619bc16e359e84fdc70';
      const aes = new AES(key);

      const data = JSON.stringify({ hello: 'world' });

      const encrypted = aes.encrypt(data, 'utf-8', 'hex');

      console.log(encrypted);
      // cf05edcfa2....d83da6101349db0f4df46c078f73d2cc90823d8e26

      const decrypted = aes.decrypt(encrypted, 'hex', 'utf-8');

      console.log(decrypted);
      // {"hello":"world"}
```

### In the case you need to provide a IV not on the table

If the IV is not from a previous encryption, you can simply set it to the IV table, and use the function as noraml by doing something like this (example below).

```
  const myIv = randomBytes(16);

  aes.ivTable[encryptedString] = myIv;
```

---
