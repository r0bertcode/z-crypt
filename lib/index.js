const { randomBytes } = require('crypto');

const {
  encrypt,
  decrypt,
  encryptCCM,
  decryptCCM,
} = require('./encrypt');

const {
  hashPBK,
  hashSHA,
} = require('./hash');

const {
  encryptFile,
  decryptFile,
  encryptFileCCM,
  decryptFileCCM,
} = require('./file');

const AES = require('./AES');
const AES_CCM = require('./AES-CCM');

// Generate a secret key for encryption and decryption
const secretKey = (bytes) => randomBytes(bytes).toString('hex');


module.exports = {
  AES, AES_CCM, hashPBK, hashSHA,
  secretKey, encrypt, decrypt, encryptCCM,
  decryptCCM, encryptFile, decryptFile,
  encryptFileCCM, decryptFileCCM,
};
