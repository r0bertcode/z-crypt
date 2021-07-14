const { createCipheriv, randomBytes, createDecipheriv } = require('crypto');
const { noParam } = require('./internal/error');

// AES-256-CBC + HMAC-SHA256 encryption, returning the IV and encrypted string
const encrypt = (data, key, options) => {
  const { inE, outE, iv } = Object.assign(
    {
      inE: 'utf-8',
      outE: 'hex',
      iv: randomBytes(16),
    },
    options
  );

  if (!iv) noParam('encrypt', 'iv (inital vector)');
  if (!inE) noParam('encrypt', 'inE (input encoding)');
  if (!outE) noParam('encrypt', 'outE (output encoding)');
  if (!data) noParam('encrypt', 'data (data/string)');

  if (!Buffer.isBuffer(data) && typeof data === 'object') {
    data = JSON.stringify(data);
  }

  const cipher = createCipheriv('aes-256-cbc-hmac-sha256', key, iv);
  let encrypted = cipher.update(data, inE, outE);
  encrypted += cipher.final(outE);

  return { encrypted, iv };
};

// AES-256-CBC + HMAC-SHA256 decryption, returning the decrypted string
const decrypt = (encrypted, key, iv, options) => {
  const { inE, outE } = Object.assign(
    {
      // Will default these to null, as all are required for consistent encryption / decryption
      inE: 'hex',
      outE: 'utf-8',
    },
    options
  );

  if (!iv) noParam('decrypt', 'iv (inital vector)');
  if (!inE) noParam('decrypt', 'inE (input encoding)');
  if (!outE) noParam('decrypt', 'outE (output encoding)');
  if (!encrypted) noParam('decrypt', 'encrypted (encrypted data/string)');

  const decipher = createDecipheriv('aes-256-cbc-hmac-sha256', key, iv);
  let decrypted = decipher.update(encrypted, inE, outE);
  decrypted += decipher.final(outE);

  return decrypted;
};

// AES-256-CCM Mode encryption
const encryptCCM = (data, key, options) => {
  let { inE, outE, iv, tagLength, aad } = Object.assign(
    {
      iv: randomBytes(13),
      inE: 'utf-8',
      outE: 'hex',
      aad: null,
      tagLength: 16,
    },
    options
  );

  if (!data) noParam('encryptCCM', 'data (string to encrypt)');
  if (!key) noParam('encryptCCM', 'key (secret key)');

  if (aad && !Buffer.isBuffer(aad)) aad = Buffer.from(aad);
  if (!Buffer.isBuffer(data) && typeof data === 'object') {
    data = JSON.stringify(data);
  }
  const cipher = createCipheriv('aes-256-ccm', key, iv, {
    authTagLength: tagLength,
  });

  if (aad) {
    cipher.setAAD(aad, {
      plaintextLength: Buffer.byteLength(data),
    });
  }

  let encrypted = cipher.update(data, inE, outE);
  encrypted += cipher.final(outE);
  const tag = cipher.getAuthTag();

  return { encrypted, tag, iv };
};

// AES-256-CCM Mode decryption
const decryptCCM = (encrypted, key, iv, tag, options) => {
  let { inE, outE, tagLength, aad } = Object.assign(
    {
      inE: 'hex',
      outE: 'utf-8',
      aad: null,
      tagLength: 16,
    },
    options
  );

  if (!iv) noParam('decryptCCM', 'iv (initial vector)');
  if (!tag) noParam('decryptCCM', 'tag (auth tag)');
  if (!encrypted) noParam('decryptCCM', 'encrypted (encrypted string)');

  if (aad && !Buffer.isBuffer(aad)) aad = Buffer.from(aad);

  const decipher = createDecipheriv('aes-256-ccm', key, iv, {
    authTagLength: tagLength,
  });
  decipher.setAuthTag(tag);

  if (aad) {
    decipher.setAAD(aad, {
      plaintextLength: Buffer.byteLength(encrypted) / 2,
    });
  }

  let decrypted = decipher.update(encrypted, inE, outE);
  decrypted += decipher.final(outE);

  return decrypted;
};

module.exports = {
  encrypt,
  decrypt,
  encryptCCM,
  decryptCCM,
};
