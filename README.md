# cryptic-js

Node-JS Cryptography Library implementing the following

- AES-256-CBC with HMAC-SHA256

- AES-256 with CCM Mode, and AAD

- Hashing + Salt function via PBKDF2S

_________

## <b>AES Class</b>

### <b>constructor:</b> AES(key)

```
  const { AES } = require('cryptic-js');

  const key = '2ba4ac21202c7619bc16e359e84fdc70';
  const aes = new AES(key);
```

### <b>encrypt:</b> AES.encrypt(data, inEncoding, outEncoding)
<br>
Encrypt data via AES-256-CBC with key from instance
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
Data: Data/String to encrypt

inEncoding: Encoding of the input Data/String

outEncoding: Encoding of the output encrypted Data/String

  Example Usage:

      const { AES } = require('cryptic-js');

      const key = '2ba4ac21202c7619bc16e359e84fdc70';
      const aes = new AES(key);

      const data = JSON.stringify({ hello: 'world' });

      const encrypted = aes.encrypt(data, 'utf-8', 'hex');

      console.log(encrypted)
      // cf05edcfa2....d83da6101349db0f4df46c078f73d2cc90823d8e26
```

<br>