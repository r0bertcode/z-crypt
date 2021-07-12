const {
  createCipheriv,
  randomBytes,
  createDecipheriv,
} = require('crypto');
const error = require('./internal/error');

// AES-192-ccm Encryption with CCM mode ( Add a 'AuthTag' and an additonal data authentication (AAD) )
const AES_CCM = function(key) {
  this.key = key;
  this.ivTable = {};
};

// AES-256 encryption with CCM Mode ( Generates an auth tag ), if aad is passed in, will also require the aad during decryption
AES_CCM.prototype.encrypt = function(data, options) {
  let { inE, outE, aad, tagLength} = Object.assign({
    inE: 'utf-8',
    outE: 'hex',
    aad: null,
    tagLength: 16,
  }, options);

  if (!data) error.noParam('AES_CCM.encrypt', 'data (input data/string)');

  if (aad && !Buffer.isBuffer(aad)) aad = Buffer.from(aad);

  const iv = randomBytes(13);
  const cipher = createCipheriv('aes-256-ccm', this.key, iv, {
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
  this.ivTable[encrypted] = iv;

  return { encrypted, tag };
};

// AES-256 encryption with CCM Mode, requires the auth tag, and the aad if used during in encryption
AES_CCM.prototype.decrypt = function(encrypted, tag, options) {
  let { inE, outE, tagLength, aad } = Object.assign({
    inE: 'hex',
    outE: 'utf-8',
    aad: null,
    tagLength: 16,
  }, options);

  if (!encrypted) error.noParam('AES_CCM.decrypt', 'encrypted (encrypted data/string)');
  if (!tag) error.noParam('AES_CCM.decrypt', 'tag (auth tag)');

  if (aad && !Buffer.isBuffer(aad)) aad = Buffer.from(aad);

  const iv = this.ivTable[encrypted];
  const decipher = createDecipheriv('aes-256-ccm', this.key, iv, {
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
