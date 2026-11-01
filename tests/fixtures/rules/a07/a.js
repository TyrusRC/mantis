const h = crypto.createHash("md5").update(password).digest("hex"); // ruleid: web-a07-weak-password-hash-javascript
const e = crypto.createHash("md5").update(fileBuf).digest("hex");  // ok
res.redirect(`/app?token=${t}`);       // ruleid: web-a07-session-id-in-url-javascript
if (password === "letmein") {}         // ruleid: web-a07-hardcoded-credential-in-auth-javascript
if (password === "") {}                // ok
