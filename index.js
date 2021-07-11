const {
  createCipheriv,
  randomBytes,
  pbkdf2Sync,
  createDecipheriv,
  getCiphers,
} = require('crypto');
const error = require('./internal/error');

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

  if (!data) error.noParam('saltHash', 'data (data/string)');

  return pbkdf2Sync(data, salt, iters, keyLen, digest).toString(encoding);
};

// AES-256-CBC + HMAC-SHA256 encryption, returning the IV and encrypted string
const encryptIv = (data, key, options) => {
  const { inE, outE, iv } = Object.assign({
    // Encoding of the input data and ouput string
    inE: null,
    outE: null,
    // Will default IV to a random 16 byte Buffer, if not provided
    iv: randomBytes(16),
  }, options);

  if (!iv) error.noParam('encryptIv', 'iv (inital vector)');
  if (!inE) error.noParam('encryptIv', 'inE (input encoding)');
  if (!outE) error.noParam('encryptIv', 'outE (output encoding)');
  if (!data) error.noParam('encryptIv', 'data (data/string)');

  const cipher = createCipheriv('aes-256-cbc-hmac-sha256', key, iv);
  let encrypted = cipher.update(data, inE, outE);
  encrypted += cipher.final(outE);

  return { encrypted, iv };
};

// AES-256-CBC + HMAC-SHA256 decryption, returning the decrypted string
const decryptIv = (encrypted, key, iv, options) => {
  const { inE, outE } = Object.assign({
    // Will default these to null, as all are required for consistent encryption / decryption
    inE: null,
    outE: null,
  }, options);

  if (!iv) error.noParam('decryptIv', 'iv (inital vector)');
  if (!inE) error.noParam('decryptIv', 'inE (input encoding)');
  if (!outE) error.noParam('decryptIv', 'outE (output encoding)');
  if (!encrypted) error.noParam('decryptIv', 'encrypted (encrypted data/string)');

  const decipher = createDecipheriv('aes-256-cbc-hmac-sha256', key, iv);
  let decrypted = decipher.update(encrypted, inE, outE);
  decrypted += decipher.final(outE);

  return decrypted;
};

// AES-256-CCM Mode encryption
const encryptCCM = (data, key, options) => {
  const { inE, outE, iv, aad } = Object.assign({
    iv: randomBytes(13),
    inE: null,
    outE: null,
    aad: null,
  }, options);

  if (!iv) error.noParam('encryptCCM', 'iv (inital vector)');
  if (!inE) error.noParam('encryptCCM', 'inE (input encoding)');
  if (!outE) error.noParam('encryptCCM', 'outE (output encoding)');
  if (!data) error.noParam('encryptCCM', 'data (data/string)');

};


// AES-256-CCM Mode decryption
const decryptCCM = (encrypted, iv, tag, options) => {
  const { inE, outE, aad } = Object.assign({
    inE: null,
    outE: null,
    aad: null,
  }, options);

  if (!iv) error.noParam('decryptCCM', 'iv (initial vector)');
  if (!tag) error.noParam('decryptCCM', 'tag (auth tag)');
  if (!inE) error.noParam('decryptCCM', 'inE (input encoding)');
  if (!outE) error.noParam('decryptCCM', 'outE (output encoding)');
  if (!encrypted) error.noParam('decryptCCM', 'encrypted (encrypted data/string)');

};

module.exports = {
  AES, AES_CCM, saltHash, secretKey,
  encryptIv, decryptIv,
};
