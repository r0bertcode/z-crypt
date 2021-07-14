const { AES_CCM, secretKey } = require('../lib/index');

const key = secretKey(16);
const aesCCM = new AES_CCM(key);

const data = JSON.stringify({ test: true });
const data2 = secretKey(133);

test('AES_CCM encryption / decryption should work with AAD', () => {
  const aad = 'superSecurePass';
  const { encrypted: e1, tag: t1 } = aesCCM.encrypt(data, { aad });
  const { encrypted: e2, tag: t2 } = aesCCM.encrypt(data2, { aad });

  const decrypted1 = aesCCM.decrypt(e1, t1, { aad });
  const decrypted2 = aesCCM.decrypt(e2, t2, { aad });

  expect(JSON.parse(decrypted1).test).toEqual(true);
  expect(decrypted2).toEqual(data2);
});

test('AES_CCM encryption / decryption should work without AAD', () => {
  const { encrypted: e1, tag: t1 } = aesCCM.encrypt(data);
  const { encrypted: e2, tag: t2 } = aesCCM.encrypt(data2);

  const decrypted1 = aesCCM.decrypt(e1, t1);
  const decrypted2 = aesCCM.decrypt(e2, t2);

  expect(JSON.parse(decrypted1).test).toEqual(true);
  expect(decrypted2).toEqual(data2);
});
