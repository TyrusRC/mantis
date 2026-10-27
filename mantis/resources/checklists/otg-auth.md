# WSTG-ATHN: Authentication Testing

- [ ] WSTG-ATHN-01: Test for Credentials Transported over an Encrypted Channel
- [ ] WSTG-ATHN-02: Test for Default Credentials
- [ ] WSTG-ATHN-03: Test for Weak Lock Out Mechanism
- [ ] WSTG-ATHN-04: Test for Bypassing Authentication Schema
- [ ] WSTG-ATHN-05: Test for Vulnerable Remember Password
- [ ] WSTG-ATHN-06: Test for Browser Cache Weaknesses
- [ ] WSTG-ATHN-07: Test for Weak Password Policy
- [ ] WSTG-ATHN-08: Test for Weak Security Question/Answer
- [ ] WSTG-ATHN-09: Test for Weak Password Change or Reset Functionalities
- [ ] WSTG-ATHN-10: Test for Weaker Authentication in Alternative Channel

## Additional checks (2026 landscape)

- [ ] Test for MFA bypass (step skip, code reuse, response manipulation, AiTM)
- [ ] Test for OAuth/OIDC misconfigurations (redirect_uri, PKCE, state, nonce)
- [ ] Test for SAML assertion bypass (signature wrapping, encrypted assertion)
- [ ] Test for JWT attacks (alg:none, key confusion, kid injection, jku swap)
- [ ] Test for passkey/WebAuthn downgrade to password
- [ ] Test for device code flow phishing (OAuth device authorization grant)
- [ ] Test for OTP cross-account binding (OTP from account A resets account B)
- [ ] Test for password reset token leak via Referer header
- [ ] Test for credential stuffing resistance (rate limiting, CAPTCHA)
- [ ] Test for biometric bypass (rooted device, Frida hook)
