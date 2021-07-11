# cryptic-js

Node-JS Cryptography Library implementing the following

- AES-256-CBC with HMAC-SHA256

- AES-256 with CCM Mode, and AAD

- Hashing + Salt function via PBKDF2S

The Library is split into Classes, that take on a key and use re-use it, and core functions that either add utility or achieve similiar things with more options avaliable.
____
Layout

- AES Class = AES-256-CBC-HMAC-SHA256 encryption/decryption
- AES_CCM Class = AES-256-CCM with AAD encryption/decryption

- encryptIv/decryptIv = AES-256-CBC-HMAC-SHA256 encryption decryption with optional param to provide custom IV ( Initial Vector )

- encryptCCM/decryptCCM = AES-256-CCM encryption/decryption with optional params to provide custom IV or AAD ( Additional authenticated data )

- saltHash = Hash and then salt data/string, using PBKDF2S

- secretKey = Util function to generate a hex key of N bytes
_________

## <b>AES Class</b>

### <b>constructor:</b> AES(key)

```
  const { AES } = require('cryptic-js');

  const key = '2ba4ac21202c7619bc16e359e84fdc70';
  const aes = new AES(key);
```
_________


### <b>encrypt:</b> AES.encrypt(data, inEncoding, outEncoding)
<br>
Encrypt data/string via AES-256-CBC with key from instance, returns the encrypted string in the encoding of your choice via outEncoding.
<br><br>
This function will store the initial vector inside the instance via the ivTable, for lookup on decryption later, you can also obtain it via property access or the 'getIv' method
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
data: Data/String to encrypt

inEncoding: Encoding of the input Data/String

outEncoding: Encoding of the output encrypted Data/String

  Example Usage:

      const { AES } = require('cryptic-js');

      const key = '2ba4ac21202c7619bc16e359e84fdc70';
      const aes = new AES(key);

      const data = JSON.stringify({ hello: 'world' });

      const encrypted = aes.encrypt(data, 'utf-8', 'hex');

      console.log(encrypted);
      // cf05edcfa2....d83da6101349db0f4df46c078f73d2cc90823d8e26
```

_________



### <b>decrypt:</b> AES.decrypt(encrypted, inEncoding, outEncoding)
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
encrypted: encrypted Data/String

inEncoding: Encoding of the encrypted Data/String

outEncoding: Encoding of the output decrypted Data/String

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
This is not standard functionality, and I would reccomend using the 'encryptIv' and 'decryptIv' functions if you find yourself often needing to carry on or pass along the IV.
<br><br>
If the IV is not from a previous encryption, you can simply set it to the IV table, and use the function as noraml by doing something like this (example below) or using the .setIv method

```
  const iv = randomBytes(16);

  aes.ivTable[encryptedString] = iv;

  OR

  aes.setIv(encryptedString, iv);
```
___