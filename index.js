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

// const key = secretKey();
// const data = 'hello-world';

// const { encrypted, iv } = encryptIv(data, key, 'utf8', 'hex');
// console.log(encrypted);
// const decrypted = decryptIv(encrypted, key, iv, 'hex', 'utf8');

// console.log(decrypted);

// AES-256-CBC + HMAC-SHA256 encryption class
const AES = function(key) {
  this.key = key;
  this.ivTable = {};
};

// Standard encryption of data, returns the encrypted string
AES.prototype.encrypt = function(data, inEncoding, outEncoding) {
  const iv =  randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc-hmac-sha256', this.key, iv);
  let encrypted = cipher.update(data, inEncoding, outEncoding);
  encrypted += cipher.final(outEncoding);

  this.ivTable[encrypted] = iv;
  return { encrypted, iv };
};

// Standard decryption of a encrypted string, returns the decrypted data
AES.prototype.decrypt = function(encrypted, inEncoding, outEncoding) {
  const iv = this.ivTable[encrypted];
  const decipher = createDecipheriv('aes-256-cbc-hmac-sha256', this.key, iv);
  let decrypted = decipher.update(encrypted, inEncoding, outEncoding);
  decrypted += decipher.final(outEncoding);

  delete this.ivTable[encrypted];

  return decrypted;
};

// AES-192-ccm Encryption with CCM mode ( Add a 'AuthTag' and an additonal data authentication (AAD) )
const AESCCM = function(key, tagLength) {
  this.key = key;
  this.tagLength = tagLength;
  this.ivTable = {};
};

AESCCM.prototype.encrypt = function(data, inEncoding, outEncoding, aad) {
  if (!Buffer.isBuffer(aad)) aad = Buffer.from(aad);

  const iv = randomBytes(13);
  const cipher = createCipheriv('aes-256-ccm', this.key, iv, {
    authTagLength: this.tagLength,
  });

  if (aad) {
    cipher.setAAD(aad, {
      plaintextLength: Buffer.byteLength(data),
    });
  }

  let encrypted = cipher.update(data, inEncoding, outEncoding);
  encrypted += cipher.final(outEncoding);
  const tag = cipher.getAuthTag();
  this.ivTable[encrypted] = iv;

  return { encrypted, tag, iv };
};

AESCCM.prototype.decrypt = function(encrypted, tag, inEncoding, outEncoding, aad) {
  if (!Buffer.isBuffer(aad)) aad = Buffer.from(aad);

  const iv = this.ivTable[encrypted];
  const decipher = createDecipheriv('aes-256-ccm', this.key, iv, {
    authTagLength: this.tagLength,
  });
  decipher.setAuthTag(tag);

  if (aad) {
    decipher.setAAD(aad, {
      plaintextLength: Buffer.byteLength(encrypted) / 2,
    });
  }

  let decrypted = decipher.update(encrypted, inEncoding, outEncoding);
  decrypted += decipher.final(outEncoding);

  delete this.ivTable[encrypted];

  return decrypted;
};

const key = secretKey();
const aesCCM = new AESCCM(key, 16);
const aad = randomBytes(130);

const data = 'testing this out';

const { encrypted, tag } = aesCCM.encrypt(data, 'utf8', 'hex', aad);
console.log(encrypted);

const decrypted = aesCCM.decrypt(encrypted, tag, 'hex', 'utf8', aad);

console.log(decrypted);
module.exports = {
  AES, saltHash, secretKey, secretKeyCCM,
  encryptIv, decryptIv,
};

