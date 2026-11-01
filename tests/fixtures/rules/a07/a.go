package main
func f(password string) { s := md5.Sum([]byte(password)); if password == "pw123" {} ; _ = s } // ruleid: web-a07-weak-password-hash-go, web-a07-hardcoded-credential-in-auth-go
func g(mode string) { if mode == "x" {} } // ok
