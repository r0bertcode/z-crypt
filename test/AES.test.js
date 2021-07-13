const { AES, secretKey } = require('../lib/index');

const key = secretKey(16);
const aes = new AES(key);


test('AES encryption / decryption should work', () => {
   const data = JSON.stringify({ test: true });
   const data2 = secretKey(133);

   const encrypted = aes.encrypt(data, 'utf-8', 'hex');
   const encrypted2 = aes.encrypt(data2, 'hex', 'binary');

   const decrypted2 = aes.decrypt(encrypted2, 'binary', 'hex');
   const decrypted = aes.decrypt(encrypted, 'hex', 'utf-8');

   expect(JSON.parse(decrypted).test).toEqual(true);
   expect(decrypted2).toEqual(data2);
});
