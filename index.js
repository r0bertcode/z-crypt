const {
  createCipheriv,
  randomBytes,
  pbkdf2Sync,
  createDecipheriv,
  getCiphers,
} = require('crypto');

// Generate a secret key for AES-256-CBC ( Will return a random hex string from 16 bytes )
const secretKey = () => randomBytes(16).toString('hex');
// Generate a secret key for AES-192-CCM ( Will return a random hex string from 32 bytes )
const secretKeyCCM = () => randomBytes(24).toString('hex');

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
const encryptIv = (data, key, inEncoding, outEncoding, iv) => {
  if (!iv) iv = randomBytes(16);

  const cipher = createCipheriv('aes-256-cbc-hmac-sha256', key, iv);
  let encrypted = cipher.update(data, inEncoding, outEncoding);
  encrypted += cipher.final(outEncoding);

  return { encrypted, iv };
};

// AES-256-CBC + HMAC-SHA256 decryption, returning the decrypted string
const decryptIv = (encrypted, key, iv, inEncoding, outEncoding) => {
  const decipher = createDecipheriv('aes-256-cbc-hmac-sha256', key, iv);
  let decrypted = decipher.update(encrypted, inEncoding, outEncoding);
  decrypted += decipher.final(outEncoding);

  return decrypted;
};

const key = secretKey();
const data = 'hello-world';

const { encrypted, iv } = encryptIv(data, key, 'utf8', 'hex');
console.log(encrypted);
const decrypted = decryptIv(encrypted, key, iv, 'hex', 'utf8');

console.log(decrypted);

// AES-256-CBC + HMAC-SHA256 encryption class
const AES = function(key) {
  this.key = key;
  this.iv = randomBytes(16);
};

// Standard encryption of data, returns the encrypted string
AES.prototype.encrypt = function(data, inEncoding, outEncoding) {
  const cipher = createCipheriv('aes-256-cbc-hmac-sha256', this.key, this.iv);
  let encrypted = cipher.update(data, inEncoding, outEncoding);
  encrypted += cipher.final(outEncoding);

  return encrypted;
};

// Standard decryption of a encrypted string, returns the decrypted data
AES.prototype.decrypt = function(encrypted, inEncoding, outEncoding) {
  const decipher = createDecipheriv('aes-256-cbc-hmac-sha256', this.key, this.iv);
  let decrypted = decipher.update(encrypted, inEncoding, outEncoding);
  decrypted += decipher.final(outEncoding);

  this.iv = randomBytes(16);

  return decrypted;
};

// AES-192-ccm Encryption with CCM mode ( Add a 'AuthTag' and an additonal data authentication (AAD) )
const AESCCM = function(key) {

};

module.exports = {
  AES, saltHash, secretKey, secretKeyCCM,
  encryptIv, decryptIv,
};

