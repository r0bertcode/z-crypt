const {
  encryptCCM,
  decryptCCM,
  decrypt,
} = require('./encrypt');
const { noParam } = require('./internal/error');

// AES-192-ccm Encryption with CCM mode ( Add a 'AuthTag' and an additonal data authentication (AAD) )
const AES_CCM = function(key) {
  this.key = key;
  this.ivTable = {};
};

// AES-256 encryption with CCM Mode ( Generates an auth tag ), if aad is passed in, will also require the aad during decryption
AES_CCM.prototype.encrypt = function(data, options) {
  if (!data) noParam('AES_CCM.encrypt', 'data (input data/string)');

  const { encrypted, tag, iv } = encryptCCM(data, this.key, options);
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

  if (!encrypted) noParam('AES_CCM.decrypt', 'encrypted (encrypted data/string)');

  const iv = this.ivTable[encrypted];
  const decrypted = decryptCCM(encrypted, this.key, iv, tag, options);
  delete this.ivTable[encrypted];

  return decrypted;
};

module.exports = AES_CCM;
