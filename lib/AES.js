const { encrypt: _encrypt, decrypt: _decrypt } = require('./encrypt');
const { noParam } = require('./internal/error');

// AES-256-CBC + HMAC-SHA256 encryption class
const AES = function (key) {
  this.key = key;
  this.ivTable = {};
};

// Standard encryption of data, returns the encrypted string
AES.prototype.encrypt = function (data, inEncoding, outEncoding) {
  if (!data) noParam('AES.encrypt', 'data (input data/string)');

  const { encrypted, iv } = _encrypt(data, this.key, {
    inE: inEncoding || 'utf-8',
    outE: outEncoding || 'hex',
  });

  this.ivTable[encrypted] = iv;
  return encrypted;
};

// Standard decryption of a encrypted string, returns the decrypted data
AES.prototype.decrypt = function (encrypted, inEncoding, outEncoding) {
  if (!encrypted) noParam('AES.decrypt', 'encrypted (encrypted data/string)');

  const iv = this.ivTable[encrypted];
  const decrypted = _decrypt(encrypted, this.key, iv, {
    inE: inEncoding || 'hex',
    outE: outEncoding || 'utf-8',
  });

  delete this.ivTable[encrypted];
  return decrypted;
};

module.exports = AES;
