const {
  encryptFile,
  decryptFile,
} = require('./index');

const File = function(key) {
    this.key = key;
    this.ivTable = {};
};

File.prototype.encrypt = function(file) {
  const iv = encryptFile(file, this.key);
  this.ivTable[file] = iv;

  return this;
};

File.prototype.decrypt = function(file) {
  const iv = this.ivTable[file];
  decryptFile(file, this.key, iv);

  delete this.ivTable[file];

  return this;
};
