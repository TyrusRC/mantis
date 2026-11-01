class A { void f(String password, HttpServletResponse response) throws Exception {
  MessageDigest md = MessageDigest.getInstance("MD5");
  md.update(password.getBytes());                         // ruleid: web-a07-weak-password-hash-java
  MessageDigest md2 = MessageDigest.getInstance("SHA-256");
  md2.update(password.getBytes());                        // ok
  response.sendRedirect("/x?JSESSIONID=" + sid);          // ruleid: web-a07-session-id-in-url-java
  if (password.equals("admin123")) {}                     // ruleid: web-a07-hardcoded-credential-in-auth-java
}}
