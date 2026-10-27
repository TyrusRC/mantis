# WSTG-SESS: Session Management Testing

- [ ] WSTG-SESS-01: Test for Session Management Schema
- [ ] WSTG-SESS-02: Test for Cookies Attributes
- [ ] WSTG-SESS-03: Test for Session Fixation
- [ ] WSTG-SESS-04: Test for Exposed Session Variables
- [ ] WSTG-SESS-05: Test for Cross Site Request Forgery
- [ ] WSTG-SESS-06: Test for Logout Functionality
- [ ] WSTG-SESS-07: Test for Session Timeout
- [ ] WSTG-SESS-08: Test for Session Puzzling
- [ ] WSTG-SESS-09: Test for Session Hijacking

## Additional checks (2026 landscape)

- [ ] Test for session not invalidated after password change
- [ ] Test for concurrent session handling (multiple devices)
- [ ] Test for session token in URL (Referer leak)
- [ ] Test for session cookie without Secure flag (transmitted over HTTP)
- [ ] Test for session cookie without HttpOnly flag (accessible to JS)
- [ ] Test for SameSite=None without Secure (CSRF via cross-site requests)
- [ ] Test for OAuth refresh token not revoked after logout
- [ ] Test for session race condition (parallel requests create multiple sessions)
- [ ] Test for bfcache auth bypass (browser back/forward cache shows authenticated page after logout)
- [ ] Test for session ID entropy (predictable/sequential tokens)
