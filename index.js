const {
  createCipheriv,
  randomBytes,
  pbkdf2Sync,
  createDecipheriv,
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

const key = '2ba4ac21202c7619bc16e359e84fdc70';
const aes = new AES(key);

const data = JSON.stringify({ hello: 'world' });

const encrypted = aes.encrypt(data, 'utf-8', 'hex');

console.log(encrypted);
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
  let { inE, outE, iv, tagLength, aad } = Object.assign({
    iv: randomBytes(13),
    inE: 'utf-8',
    outE: 'hex',
    aad: null,
    tagLength: 16,
  }, options);

  if (!data) error.noParam('encryptCCM', 'data (string to encrypt)');
  if (!key) error.noParam('encryptCCM', 'key (secret key)');

  if (aad && !Buffer.isBuffer(aad)) aad = Buffer.from(aad);

  const cipher = createCipheriv('aes-256-ccm', key, iv, {
    authTagLength: tagLength,
  });

  if (aad) {
    cipher.setAAD(aad, {
      plaintextLength: Buffer.byteLength(data),
    });
  }

  let encrypted = cipher.update(data, inE, outE);
  encrypted += cipher.final(outE);
  const tag = cipher.getAuthTag();

  return { encrypted, tag, iv };
};


// AES-256-CCM Mode decryption
const decryptCCM = (encrypted, iv, tag, options) => {
  let { inE, outE, tagLength, aad } = Object.assign({
    inE: 'hex',
    outE: 'utf-8',
    aad: null,
    tagLength: 16,
  }, options);

  if (!iv) error.noParam('decryptCCM', 'iv (initial vector)');
  if (!tag) error.noParam('decryptCCM', 'tag (auth tag)');
  if (!encrypted) error.noParam('decryptCCM', 'encrypted (encrypted string)');

  if (aad && !Buffer.isBuffer(aad)) aad = Buffer.from(aad);

  const decipher = createDecipheriv('aes-256-ccm', key, iv, {
    authTagLength: tagLength,
  });
  decipher.setAuthTag(tag);

  if (aad) {
    decipher.setAAD(aad, {
      plaintextLength: Buffer.byteLength(encrypted) / 2,
    });
  }

  let decrypted = decipher.update(encrypted, inE, outE);
  decrypted += decipher.final(outE);

  return decrypted;
};

module.exports = {
  AES, AES_CCM, saltHash, secretKey,
  encryptIv, decryptIv, encryptCCM,
  decryptCCM,
};
