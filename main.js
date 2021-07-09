const {
  createCipheriv,
  randomBytes,
  pbkdf2Sync,
  createDecipheriv,
} = require('crypto');

// Salt and hash a String, Buffer, TypedArray, or DataView
const saltHash = (data, options) => {
  const { salt, iters, keyLen, digest, encoding } = Object.assign({
    // We want the min amount of bytes to be 16 for the salt
    salt: randomBytes(Math.floor(Math.random() * 10000) + 116),
    // Number of iterations for the hash
    iters: 100000,
    // Length of the output key
    keyLen: 64,
    // Digest of the Hash
    digest: 'sha512',
    // Encoding of the output key
    encoding: 'hex',
  }, options);

  return pbkdf2Sync(data, salt, iters, keyLen, digest).toString(encoding);
};

console.log(saltHash('bestPassword'));

// Generate a secret key for AES-256-CBC ( Will return a random hex string from 16 bytes )
const secretKey = () => randomBytes(16).toString('hex');
// Generate a secret key for AES-192-CCM ( Will return a random hex string from 32 bytes )
const secretKeyCCM = () => randomBytes(24).toString('hex');

// Standard AES-256-CBC encryption ( Will return the encrypted string, and the IV )
const encryptIv = function(data, key, options = {}) {
  const { encoding, outcoding, iv } = Object.assign({
    encoding: 'utf-8',
    outcoding: 'hex',
    iv: randomBytes(16),
  }, options);

  const cipher = createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(data, encoding, outcoding);
  encrypted += cipher.final(outcoding);

  return { encrypted, iv };
};

// Standard AES-256-CBC decryption ( Defaults input encoding to HEX as 'encrypt' defaults its outcoding to HEX )
// Returns the decrypted data
const decryptIv = function(encrypted, key, iv, options = {}) {
  const { encoding, outcoding } = Object.assign({
    encoding: 'hex',
    outcoding: 'utf-8',
  }, options);

  const decipher = createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encrypted, encoding, outcoding);
  decrypted += decipher.final(outcoding);

  return decrypted;
};

// AES-192-CCM encryption, requiring a Auth tag alongside an (Optional) AAD or String used as an additonal layer of information needed to decrypt
// This will return the encrypted string, IV, the AuthTag, and AAD
const encryptCCM = (key, text, encoding, options) => {
  // aad, iv = randomBytes(12), outcoding = 'hex'
  let { aad, iv, outcoding, tagLength } = Object.assign({
    aad: false,
    iv: randomBytes(12),
    outcoding: 'hex',
    tagLength: 16,
  }, options);

  if (typeof key === 'string') {
    key = Buffer.from(key, 'hex');
  }

  const cipher = createCipheriv('aes-192-ccm', key, iv, {
    authTagLength: tagLength,
  });

  if (aad) {
    aad = Buffer.from(aad, 'utf-8');
    cipher.setAAD(aad, {
      plaintextLength: Buffer.byteLength(text),
    });
  }

  let encrypted = cipher.update(text, encoding, outcoding);
  encrypted += cipher.final(outcoding);
  const tag = cipher.getAuthTag();

  return { encrypted, iv, tag, aad };
};

// Not working => Error: Unsupported state or unable to authenticate data
// const decryptCCM = (key, encrypted, iv, tag, outcoding, options) => {
//   let { aad, encoding, tagLength } = Object.assign({
//     aad: false,
//     encoding: 'hex',
//     tagLength: 16,
//   }, options);

//   if (typeof key === 'string') {
//     key = Buffer.from(key, 'hex');
//   }

//   const decipher = createDecipheriv('aes-192-ccm', key, iv, {
//     authTagLength: tagLength,
//   });
//   decipher.setAuthTag(tag);

//   if (aad) {
//     aad = Buffer.from(aad, 'utf-8');
//     decipher.setAAD(aad, {
//       plaintextLength: encrypted.length,
//     });
//   }

//   let decrypted = decipher.update(encrypted, encoding, outcoding);
//   decrypted += decipher.final(outcoding);

//   return decrypted;
// };
