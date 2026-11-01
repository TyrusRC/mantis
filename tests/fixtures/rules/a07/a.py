import hashlib
h = hashlib.md5(password.encode()).hexdigest()   # ruleid: web-a07-weak-password-hash-python
h2 = hashlib.md5(file_bytes).hexdigest()          # ok
return redirect(f"/home?token={tok}")             # ruleid: web-a07-session-id-in-url-python
return redirect("/home")                          # ok
if password == "hunter2":                         # ruleid: web-a07-hardcoded-credential-in-auth-python
    pass
if password == "":                                # ok: emptiness check
    pass
if mode == "admin":                               # ok
    pass
