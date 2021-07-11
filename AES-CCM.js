const {
  createCipheriv,
  randomBytes,
  createDecipheriv,
} = require('crypto');
const error = require('./internal/error');

// AES-192-ccm Encryption with CCM mode ( Add a 'AuthTag' and an additonal data authentication (AAD) )
const AES_CCM = function(key, tagLength) {
  this.key = key;
  this.tagLength = tagLength;
  this.ivTable = {};
};

// AES-256 encryption with CCM Mode ( Generates an auth tag ), if aad is passed in, will also require the aad during decryption
AES_CCM.prototype.encrypt = function(data, inEncoding, outEncoding, aad) {
  if (!data) error.noParam('AES_CCM.encrypt', 'data (input data/string)');
  if (!inEncoding) error.noParam('AES_CCM.encrypt', 'inEncoding (input encoding)');
  if (!outEncoding) error.noParam('AES_CCM.encrypt', 'outEncoding (output encoding)');

  if (aad && !Buffer.isBuffer(aad)) aad = Buffer.from(aad);

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

// AES-256 encryption with CCM Mode, requires the auth tag, and the aad if used during in encryption
AES_CCM.prototype.decrypt = function(encrypted, tag, inEncoding, outEncoding, aad) {
  if (!inEncoding) error.noParam('AES_CCM.decrypt', 'inEncoding (input encoding)');
  if (!outEncoding) error.noParam('AES_CCM.decrypt', 'outEncoding (output encoding)');
  if (!encrypted) error.noParam('AES_CCM.decrypt', 'encrypted (encrypted data/string)');

  if (aad && !Buffer.isBuffer(aad)) aad = Buffer.from(aad);

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

// Get IV for specified encryption string OR null if not found
AES_CCM.prototype.getIv = function(encrypted) {
  return this.ivTable[encrypted] || null;
};

// Get entire IV table
AES_CCM.prototype.getIvTable = function() {
  return this.ivTable;
};

module.exports = AES_CCM;
