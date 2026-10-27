# WSTG-CRYP: Cryptography Testing

- [ ] WSTG-CRYP-01: Test for Weak Transport Layer Security
- [ ] WSTG-CRYP-02: Test for Padding Oracle
- [ ] WSTG-CRYP-03: Test for Sensitive Information Sent via Unencrypted Channels
- [ ] WSTG-CRYP-04: Test for Weak Encryption

## Additional checks (2026 landscape)

- [ ] Test for weak password hashing (MD5, SHA1, unsalted SHA256)
- [ ] Test for broken random number generation (Math.random, time-based seeds)
- [ ] Test for hardcoded encryption keys in source code
- [ ] Test for CBC bit-flipping (unauthenticated ciphertext manipulation)
- [ ] Test for PKCS#7/CMS parameter injection (CVE-2026-34182 class)
- [ ] Test for JWT cryptographic weaknesses (HS256 with weak secret, RSA/HMAC confusion)
- [ ] Test for TLS certificate validation bypass (verify=False, rejectUnauthorized)
- [ ] Test for deprecated protocols (SSLv3, TLS 1.0/1.1, DES, 3DES, RC4)
- [ ] Test for insufficient key length (RSA < 2048, ECDSA < 256)
- [ ] Test for missing HSTS (Strict-Transport-Security header)
