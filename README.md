# cryptic-js

The cryptic library is a cryptography library for Node.js created on-top of Node.js' Crypto module.

It provides a standardized API to access encryption/decryption of data/strings and files utilizing AES-256-CBC with HMAC-SHA-256 and support for CCM Mode and AAD authorization with AES-256-CCM, and hashing/salting with PBKDF2S and SHA512.

## Table of contents

### Stand-alone encryption

- [encrypt](#encrypt) | AES-256-CBC with HMAC-SHA256 encryption
- [decrypt](#decrypt) | AES-256-CBC with HMAC-SHA256 decryption
- [encryptCCM](#encryptCCM) | AES-256-CCM encryption with optional AAD
- [decryptCCM](#decryptCCM) | AES-256-CCM decryption with optional AAD

### Encryption classes

- [AES Class](#AES-Class) | AES-256-CBC with HMAC-SHA-256
- [AES CCM Class](#AES-CCM-Class) | AES-256-CCM with optional AAD

### File encryption

- [encryptFile](#encryptFile) | AES-256-CBC with HMAC-SHA256 file encryption
- [decryptFile](#decryptFile) | AES-256-CBC with HMAC-SHA256 file decryption
- [encryptFileCCM](#encryptFileCCM) | AES-256-CCM file encryption with optional AAD
- [decryptFileCCM](#decryptFileCCM) | AES-256-CCM file decryption with optional AAD
