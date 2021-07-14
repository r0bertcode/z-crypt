const { readFileSync } = require('fs');
const path = require('path');

const { encryptFile, decryptFile, encryptFileCCM, decryptFileCCM } = require('../lib/file');

const { secretKey } = require('../lib/index');

const key = secretKey(16);

test('encryptFile and decrpytFile should work as expected', () => {
  const testFile = path.join(__dirname, '/textFiles/file_test_1.txt');

  const iv = encryptFile(testFile, key);

  let fileBuffer = readFileSync(testFile);
  let string = fileBuffer.toString('utf-8').trim();

  expect(string).not.toEqual('hello');

  decryptFile(testFile, key, iv);

  fileBuffer = readFileSync(testFile);
  string = fileBuffer.toString('utf-8').trim();

  expect(string).toEqual('hello');
});

test('encryptFileCCM and decryptFileCCM should work as expected w/ or w/o AAD', () => {
  const testFile1 = path.join(__dirname, '/textFiles/file_test_2.txt');
  const testFile2 = path.join(__dirname, '/textFiles/file_test_3.txt');
  const aad = 'mySecretPass';

  const { iv: iv1, tag: tag1 } = encryptFileCCM(testFile1, key);
  const { iv: iv2, tag: tag2 } = encryptFileCCM(testFile2, key, aad);

  let buff1 = readFileSync(testFile1);
  let buff2 = readFileSync(testFile2);

  let str1 = buff1.toString('utf-8').trim();
  let str2 = buff2.toString('utf-8').trim();

  expect(str1).not.toEqual('world');
  expect(str2).not.toEqual('1337');

  decryptFileCCM(testFile1, key, iv1, tag1);
  decryptFileCCM(testFile2, key, iv2, tag2, aad);

  buff1 = readFileSync(testFile1);
  buff2 = readFileSync(testFile2);

  str1 = buff1.toString('utf-8').trim();
  str2 = buff2.toString('utf-8').trim();

  expect(str1).toEqual('world');
  expect(str2).toEqual('1337');
});
