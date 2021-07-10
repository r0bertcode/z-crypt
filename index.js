const {
  createCipheriv,
  randomBytes,
  pbkdf2Sync,
  createDecipheriv,
  getCiphers,
} = require('crypto');

const AES = require('./AES');
const AES_CCM = require('./AES-CCM');

// Generate a secret key for encryption and decryption
const secretKey = (bytes) => randomBytes(bytes).toString('hex');

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

// AES-256-CBC + HMAC-SHA256 encryption, returning the IV and encrypted string
const encryptIv = (data, key, options) => {
  const { encoding: { in, out }, iv } = Object.assign({
    // Encoding of the input data and ouput string
    encoding: { in: null, out: null },
    // Will default IV to a random 16 byte Buffer, if not provided
    iv: randomBytes(16),
  }, options);

  const cipher = createCipheriv('aes-256-cbc-hmac-sha256', key, iv);
  let encrypted = cipher.update(data, inEncoding, outEncoding);
  encrypted += cipher.final(outEncoding);

  return { encrypted, iv };
};

// AES-256-CBC + HMAC-SHA256 decryption, returning the decrypted string
const decryptIv = (encrypted, key, options) => {
  const { encoding: { in, out }, iv } = Object.assign({
    // Will default these to null, as all are required for consistent encryption / decryption
    encoding: { in: null, out: null },
    iv: null,
  }, options);

  const decipher = createDecipheriv('aes-256-cbc-hmac-sha256', key, iv);
  let decrypted = decipher.update(encrypted, inEncoding, outEncoding);
  decrypted += decipher.final(outEncoding);

  return decrypted;
};

module.exports = {
  AES, AES_CCM, saltHash, secretKey,
  encryptIv, decryptIv,
};
