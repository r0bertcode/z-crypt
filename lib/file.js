const {
    readFileSync,
    writeFileSync,
} = require('fs');

const {
    encrypt,
    decrypt,
    encryptCCM,
    decryptCCM,
} = require('./encrypt');

const { noParam } = require('./internal/error');

// Encrypt file, returns the IV that is needed for decryption
const encryptFile = (file, key) => {
    if (!key) noParam('encryptFile', 'key (secret key)');
    if (!file) noParam('encryptFile', 'file (filepath)');
  
    const fileBuffer = readFileSync(file);
  
    const data = fileBuffer.toString('utf-8');
    const { encrypted, iv } = encrypt(data, key, { inE: 'utf-8', outE: 'binary' });
  
    writeFileSync(file, encrypted, { encoding: 'binary' });
  
    return iv;
};
  
// Decrypt file 
const decryptFile = (file, key, iv) => {
    if (!key) noParam('decryptFile', 'key (secret key)');
    if (!file) noParam('decryptFile', 'file (filepath)');
  
    const fileBuffer = readFileSync(file);
  
    const data = fileBuffer.toString('binary');
    const decrypted = decrypt(data, key, iv, { inE: 'binary', outE: 'utf-8' });
  
    writeFileSync(file, decrypted, { encoding: 'utf-8' });
};
  
const encryptFileCCM = (file, key, aad) => {
    if (!key) noParam('encryptFileCCM', 'key (secret key)');
    if (!file) noParam('encryptFileCCM', 'file (filepath)');
  
    const fileBuffer = readFileSync(file);
    
    const data = fileBuffer.toString('utf-8');
    const { encrypted, tag, iv } = encryptCCM(data, key, { aad });
  
    writeFileSync(file, encrypted, { encoding: 'binary' });
  
    return { iv, tag };
};
  
const decryptFileCCM = (file, key, iv, tag, aad) => {
    if (!key) noParam('decryptFileCCM', 'key (secret key)');
    if (!file) noParam('decryptFileCCM', 'file (filepath)');
  
    const fileBuffer = readFileSync(file);
  
    const data = fileBuffer.toString('binary');
    const decrypted = decryptCCM(data, key, iv, tag, { aad });
  
    writeFileSync(file, decrypted, { encoding: 'utf-8' });
};

module.exports = {
    encryptFile, decryptFile,
    encryptFileCCM, decryptFileCCM,
};
