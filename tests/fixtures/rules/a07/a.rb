h = Digest::MD5.hexdigest(password)    # ruleid: web-a07-weak-password-hash-ruby
redirect_to "/x?session_id=#{sid}"     # ruleid: web-a07-session-id-in-url-ruby
if password == "secret1"               # ruleid: web-a07-hardcoded-credential-in-auth-ruby
end
