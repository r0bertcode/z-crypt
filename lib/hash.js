const { randomBytes, pbkdf2Sync, createHash } = require('crypto');
const { noParam } = require('./internal/error');

// Hash via sha256, option to add salt
const hashSHA = (data, salt) => {
  if (!data) noParam('hashSHA', 'data (data/string to hash)');
  if (!Buffer.isBuffer(data) && typeof data === 'object') {
    data = JSON.stringify(data);
  }
  const hash = createHash('sha512');
  hash.update(data);
  if (salt) hash.update(salt);

  return hash.digest('hex');
};

// Salt and hash a String, Buffer, TypedArray, or DataView
const hashPBK = (data, options) => {
  const { salt, iters, keyLen, digest, encoding } = Object.assign(
    {
      // We want the min amount of bytes to be 16 for the salt
      salt: randomBytes(Math.floor(Math.random() * 10000) + 116),
      iters: 100000,
      keyLen: 64,
      digest: 'sha512',
      encoding: 'hex',
    },
    options
  );

  if (!data) noParam('saltHash', 'data (data/string to hash and salt)');
  if (!Buffer.isBuffer(data) && typeof data === 'object') {
    data = JSON.stringify(data);
  }

  return pbkdf2Sync(data, salt, iters, keyLen, digest).toString(encoding);
};

module.exports = { hashPBK, hashSHA };
