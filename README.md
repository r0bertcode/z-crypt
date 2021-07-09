# cryptic-js
Node.js Library built on-top of Node.js' 'Crypto' module. When using the module myself I found it a bit cumbersome at times and I am providing a cleaner API to access the underlying methods in a more standardized way.


# Docs

## saltHash (data, [options]) : Hash and salt data

Returns the hashed and salted key ( Uses PBKDF2 )
```
  data can be of Type: String, Buffer, TypedArray, DataView

  options => {
    // Salt needs to be minimum 16 bytes
    salt: Salt to add to the hash (Default: 116-10016 random bytes)

    // The higher, the more secure, and the longer it will take
    iters: Number of iters for the hash algo (Default: 100000)

    keyLen: Length of the output key (Default: 64)

    digest: HMAC digest algorithm (Default: 'sha512')

    encoding: encoding of the output (Default: 'hex')
  }


  Usage example:

  const userPassword = 'bestPassword';

  const salted = cryptic.saltHash(userPassword);

  console.log(salted) => a6ec645c5744786b046e7....fb5fb03

  With custom configuration:

  const salted = cryptic.saltHash(userPassword, { iters: 1000000 })

```

<br>

## encryptIv (data, key, [options])

Returns the encrypted data and the IV ( initialization vector )