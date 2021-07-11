const {
  createCipheriv,
  randomBytes,
  createDecipheriv,
} = require('crypto');
const error = require('./internal/error');

// AES-256-CBC + HMAC-SHA256 encryption class
const AES = function(key) {
  this.key = key;
  this.ivTable = {};
};

// Standard encryption of data, returns the encrypted string
AES.prototype.encrypt = function(data, inEncoding, outEncoding) {
  if (!data) error.noParam('AES.encrypt', 'data (input data/string)');
  if (!inEncoding) error.noParam('AES.encrypt', 'inEncoding (input encoding)');
  if (!outEncoding) error.noParam('AES.encrypt', 'outEncoding (output encoding)');

  const iv =  randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc-hmac-sha256', this.key, iv);
  let encrypted = cipher.update(data, inEncoding, outEncoding);
  encrypted += cipher.final(outEncoding);

  this.ivTable[encrypted] = iv;
  return encrypted;
};

// Standard decryption of a encrypted string, returns the decrypted data
AES.prototype.decrypt = function(encrypted, inEncoding, outEncoding) {
  if (!inEncoding) error.noParam('AES.decrypt', 'inEncoding (input encoding)');
  if (!outEncoding) error.noParam('AES.decrypt', 'outEncoding (output encoding)');
  if (!encrypted) error.noParam('AES.decrypt', 'encrypted (encrypted data/string)');

  const iv = this.ivTable[encrypted];
  const decipher = createDecipheriv('aes-256-cbc-hmac-sha256', this.key, iv);
  let decrypted = decipher.update(encrypted, inEncoding, outEncoding);
  decrypted += decipher.final(outEncoding);

  delete this.ivTable[encrypted];
  return decrypted;
};

// Get IV associated with a specific encrypted string
AES.prototype.getIv = function(encrypted) {
  return this.ivTable[encrypted] || null;
};

// Get entire IV table
AES.prototype.getIvTable = function() {
  return this.ivTable;
};

module.exports = AES;
