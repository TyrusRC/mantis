const fs = require('fs'); const path = require('path');
app.get('/a', (req, res) => {
  const p = req.query.name;
  fs.readFile(p, () => {});                                 // ruleid: web-a03-path-traversal-fs-node
  fs.readFile(req.query.name, () => {});                    // ruleid: web-a03-path-traversal-fs-node
  fs.readFile(path.basename(req.query.name), () => {});     // ok: basename
  res.sendFile(req.params.f, { root: __dirname + '/pub' }); // ok: root option
  const q = { user: req.body.user };
  User.findOne(q);                                          // ruleid: web-a03-nosql-injection-mongoose
  User.findOne({ user: String(req.body.user) });            // ok: cast
  const hit = items.find(i => i.id === req.query.id);       // ok: Array.find
  const u = req.body.url;
  fetch(u);                                                 // ruleid: web-a10-ssrf-fetch-with-user-url-node
  axios.get(`https://api.example.com/v1/${req.query.id}`);  // ok: fixed host
  const next = req.query.next;
  res.redirect(next);                                       // ruleid: web-a01-open-redirect-express, web-a01-open-redirect-express-broad
  res.redirect('/profile/' + req.query.id);                 // ok: same-origin path
  res.redirect(302, req.query.to);                          // ruleid: web-a01-open-redirect-express
});
