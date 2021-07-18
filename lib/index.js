const { randomBytes } = require('crypto');

const { hashPBK, hashSHA } = require('./hash');
const { encrypt, decrypt, encryptCCM, decryptCCM } = require('./encrypt');
const { encryptFile, decryptFile, encryptFileCCM, decryptFileCCM } = require('./file');

const AES = require('./AES');
const AES_CCM = require('./AES-CCM');

// Generate a secret key for encryption and decryption
const secretKey = (bytes = 16) => randomBytes(bytes).toString('hex');

module.exports = {
  AES,
  AES_CCM,
  hashPBK,
  hashSHA,
  encrypt,
  decrypt,
  secretKey,
  encryptCCM,
  decryptCCM,
  encryptFile,
  decryptFile,
  encryptFileCCM,
  decryptFileCCM,
};
