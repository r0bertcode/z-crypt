const { AES, secretKey } = require('../lib/index');

const key = secretKey(16);
const aes = new AES(key);


test('AES encryption / decryption should work', () => {
   const data = JSON.stringify({ test: true });
   
   const encrypted = aes.encrypt(data, 'utf-8', 'hex');

   const decrypted = aes.decrypt(encrypted, 'hex', 'utf-8');

   expect(JSON.parse(decrypted).test).toEqual(true);

   const data2 = secretKey(133);

   const encrypted2 = aes.encrypt(data2, 'hex', 'binary');

   const decrypted2 = aes.decrypt(encrypted2, 'binary', 'hex');

   expect(decrypted2).toEqual(data2);
});


describe('Get methods should work', () => {
    const data = secretKey(30);
    const encrypted = aes.encrypt(data, 'hex', 'utf-8');

    test('getIv should return the IV', () => {
        const iv = aes.getIv(encrypted);

        expect(iv).toBeDefined();
    });
});

describe('Set methods should work', () => {
    const data = secretKey(33);
    const encrypted = aes.encrypt(data, 'hex', 'utf-8');

    test('setIv should add the encrypted string and IV to the table', () => {
        const iv = 'test';
        aes.setIv(encrypted, iv);

        expect(aes.ivTable[encrypted]).toEqual('test');
    });

    test('setKey should change the key', () => {
        const newKey = secretKey(16);

        aes.setKey(newKey);
        expect(aes.key).toEqual(newKey);
    });

    test('setIvTable should change the IvTable', () => {
        const ivTable = { test: true };

        aes.setIvTable(ivTable);
        expect(aes.ivTable.test).toEqual(true);
        expect(aes.ivTable[encrypted]).toEqual(undefined);
    });
});