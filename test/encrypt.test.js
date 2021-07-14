const {
    encrypt,
    decrypt,
    encryptCCM,
    decryptCCM,
} = require('../lib/encrypt');

const { secretKey } = require('../lib/index');

const key = secretKey(16);

const data = JSON.stringify({ test: true });

test('encrypt and decrypt should work as expected', () => {
    const { encrypted, iv } = encrypt(data, key, {
        inE: 'utf-8',
        outE: 'hex',
    });

    expect(encrypted.length).toBeGreaterThan(data.length);

    const decrypted = decrypt(encrypted, key, iv, {
        inE: 'hex',
        outE: 'utf-8',
    });

    expect(JSON.parse(decrypted).test).toEqual(true);
});

test('encryptCCM and decryptCCM should work as expected with or without AAD', () => {
    const aad = 'superPassword';

    const { encrypted: e1, tag: t1, iv: iv1 } = encryptCCM(data, key, { aad });
    const { encrypted: e2, tag: t2, iv: iv2 } = encryptCCM(data, key);

    expect(e1).not.toEqual(e2);
    expect(e1.length).toBeGreaterThan(data.length);
    expect(e2.length).toBeGreaterThan(data.length);

    const decrypted1 = decryptCCM(e1, key, iv1, t1, { aad });
    const decrypted2 = decryptCCM(e2, key, iv2, t2);

    expect(JSON.parse(decrypted1).test).toEqual(true);
    expect(JSON.parse(decrypted2).test).toEqual(true);
});
