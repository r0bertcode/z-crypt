const { hashSHA, hashPBK } = require('../lib/index');

test('hashSHA should work as expected', () => {
   const data = JSON.stringify({ test: true });
   const salt = 'thisIsMySalt';

   const h1 = hashSHA(data);
   const h2 = hashSHA(data, salt);

   expect(h1).not.toEqual(data);
   expect(h2).not.toEqual(data);
   expect(h1).not.toEqual(h2);
});

test('hashPBK should work as expected', () => {
    const data = '123456778';
    const salt = 'customSalt';

    const h1 = hashPBK(data);
    const h2 = hashPBK(data);
    const h3 = hashPBK(data, { iters: 444444, salt });

    expect(h1).not.toEqual(data);
    expect(h2).not.toEqual(data);
    expect(h3).not.toEqual(data);
    expect(h1).not.toEqual(h2);
    expect(h2).not.toEqual(h3);
});