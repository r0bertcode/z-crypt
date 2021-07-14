const {
    randomBytes,
    pbkdf2Sync,
    createHash,
} = require('crypto');
const { noParam } = require('./internal/error');
  

// Hash via sha256, option to add salt
const hashSHA = (data, salt) => {
    if (!data) noParam('hashSHA', 'data (data/string to hash)');
    
    const hash = createHash('sha512');
    hash.update(data);
    salt && hash.update(salt);
  
    return hash.digest('hex');
  };
  
// Salt and hash a String, Buffer, TypedArray, or DataView
const hashPBK = (data, options) => {
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
  
    if (!data) error.noParam('saltHash', 'data (data/string to hash and salt)');
  
    return pbkdf2Sync(data, salt, iters, keyLen, digest).toString(encoding);
};
  
module.exports = { hashPBK, hashSHA };
