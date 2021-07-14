const {
  encrypt: _encrypt,
  decrypt: _decrypt,
} = require('./encrypt');
const { noParam } = require('./internal/error');

// AES-256-CBC + HMAC-SHA256 encryption class
const AES = function(key) {
  this.key = key;
  this.ivTable = {};
};

// Standard encryption of data, returns the encrypted string
AES.prototype.encrypt = function(data, inEncoding, outEncoding) {
  if (!data) noParam('AES.encrypt', 'data (input data/string)');
  if (!inEncoding) noParam('AES.encrypt', 'inEncoding (input encoding)');
  if (!outEncoding) noParam('AES.encrypt', 'outEncoding (output encoding)');

  const { encrypted, iv } = _encrypt(data, this.key, {
    inE: inEncoding,
    outE: outEncoding,
  });

  this.ivTable[encrypted] = iv;
  return encrypted;
};

// Standard decryption of a encrypted string, returns the decrypted data
AES.prototype.decrypt = function(encrypted, inEncoding, outEncoding) {
  if (!inEncoding) noParam('AES.decrypt', 'inEncoding (input encoding)');
  if (!outEncoding) noParam('AES.decrypt', 'outEncoding (output encoding)');
  if (!encrypted) noParam('AES.decrypt', 'encrypted (encrypted data/string)');

  const iv = this.ivTable[encrypted];
  const decrypted = _decrypt(encrypted, this.key, iv, {
    inE: inEncoding,
    outE: outEncoding,
  });

  delete this.ivTable[encrypted];
  return decrypted;
};

module.exports = AES;