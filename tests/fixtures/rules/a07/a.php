<?php
$h = md5($password);                        // ruleid: web-a07-weak-password-hash-php
$x = md5($filename);                        // ok
header("Location: /x?PHPSESSID=" . $sid);  // ruleid: web-a07-session-id-in-url-php
