'use strict';
try { require('dotenv').config(); } catch (e) {}
const express = require('express'), crypto = require('crypto'), fs = require('fs'), path = require('path');
const archiver = require('archiver'), QRCode = require('qrcode');

// ---------- config ----------
const PORT = +process.env.PORT || 3000;
const BASE = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const PROD = process.env.NODE_ENV === 'production';
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const MAX_POSTS = +process.env.MAX_POSTS || 3;
const SUPER = (process.env.SUPER_ADMIN_EMAIL || 'admin@xerago.com').toLowerCase();
const ADMIN_PATH = process.env.ADMIN_PATH || '/admin';
const DEPTS = ['Engineering', 'Marketing', 'HR', 'Finance', 'Operations', 'Sales', 'Design'];
const DATA = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const PHOTOS = path.join(DATA, 'photos');
fs.mkdirSync(PHOTOS, { recursive: true });
let mailer = null;
if (process.env.SMTP_HOST) {
  mailer = require('nodemailer').createTransport({
    host: process.env.SMTP_HOST, port: +process.env.SMTP_PORT || 587, secure: process.env.SMTP_SECURE === 'true',
    auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined });
}

// ---------- tiny JSON database (swap for Postgres/Mongo in production) ----------
const DBF = path.join(DATA, 'db.json');
let db = { photos: [], votes: {}, reports: [], admins: [], otps: {}, audit: [],
  settings: { autoPublish: process.env.AUTO_PUBLISH !== 'false', voting: true, manualExpire: false, expiresAt: null } };
if (fs.existsSync(DBF)) db = { ...db, ...JSON.parse(fs.readFileSync(DBF, 'utf8')) };
if (!db.admins.length) {
  db.admins.push({ email: SUPER, role: 'Super admin' });
  (process.env.ADMIN_EMAILS || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
    .forEach(e => e !== SUPER && db.admins.push({ email: e, role: 'Admin' }));
}
let saving = false, again = false;
function save() {
  if (saving) { again = true; return; }
  saving = true;
  fs.writeFile(DBF + '.tmp', JSON.stringify(db), err => {
    if (!err) fs.renameSync(DBF + '.tmp', DBF);
    saving = false; if (again) { again = false; save(); }
  });
}
save();
const audit = (who, action, detail = '') => { db.audit.unshift({ at: Date.now(), who, action, detail }); db.audit.length = Math.min(db.audit.length, 500); save(); };
const expired = () => db.settings.manualExpire || (db.settings.expiresAt && Date.now() > db.settings.expiresAt);
const voteCount = id => (db.votes[id] || []).length;

// ---------- signed cookies, rate limit ----------
const hmac = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
const sign = o => { const p = Buffer.from(JSON.stringify(o)).toString('base64url'); return p + '.' + hmac(p); };
const verify = t => {
  if (!t) return null; const [p, s] = t.split('.'); if (!p || !s) return null;
  const e = hmac(p); if (s.length !== e.length || !crypto.timingSafeEqual(Buffer.from(s), Buffer.from(e))) return null;
  try { const o = JSON.parse(Buffer.from(p, 'base64url').toString()); return o.exp > Date.now() ? o : null; } catch (e) { return null; }
};
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(a => a[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join('='))]));
const hits = new Map();
const limited = (key, max, ms) => { const n = Date.now(), a = (hits.get(key) || []).filter(t => n - t < ms); a.push(n); hits.set(key, a); return a.length > max; };
const setCookie = (res, name, val, maxAge) => res.cookie(name, val, { httpOnly: true, sameSite: 'lax', secure: PROD, ...(maxAge ? { maxAge } : {}) });

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN', 'Referrer-Policy': 'same-origin' });
  if (PROD && req.headers['x-forwarded-proto'] === 'http') return res.redirect(301, BASE + req.originalUrl);
  next();
});
app.use(express.json({ limit: '8mb' }));
app.use((req, res, next) => { // simple CSRF guard: every write must come from our own JS
  if (req.path.startsWith('/api/') && !['GET', 'HEAD'].includes(req.method) && req.get('X-XDM') !== '1') return res.status(403).json({ error: 'Blocked request' });
  const c = cookies(req); const e = verify(c.xdm_emp), a = verify(c.xdm_adm);
  req.emp = e && e.empId ? e : null;
  const rec = a && db.admins.find(x => x.email === a.email); // re-checked every request, so revoking is instant
  req.admin = rec || null;
  next();
});
const needEmp = (req, res, next) => req.emp ? next() : res.status(401).json({ error: 'Please sign in' });
const needAdmin = (req, res, next) => req.admin ? next() : res.status(401).json({ error: 'Admin sign-in required' });
const needSuper = (req, res, next) => req.admin && req.admin.role === 'Super admin' ? next() : res.status(403).json({ error: 'Super admin only' });

// ---------- public ----------
app.get('/api/config', (req, res) => res.json({ expired: !!expired(), voting: db.settings.voting, autoPublish: db.settings.autoPublish, maxPosts: MAX_POSTS, depts: DEPTS }));
app.get('/scan', (req, res) => expired() ? res.status(410).sendFile(path.join(__dirname, 'public', 'expired.html')) : res.redirect('/#scan'));
app.get(ADMIN_PATH, (req, res) => { res.set('X-Robots-Tag', 'noindex'); res.sendFile(path.join(__dirname, 'views', 'admin.html')); });

// ---------- employee auth ----------
app.post('/api/auth/employee', (req, res) => {
  if (limited('login:' + req.ip, 20, 600e3)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  if (expired()) return res.status(403).json({ error: 'This QR code has expired', code: 'expired' });
  const name = String(req.body.name || '').trim().replace(/\s+/g, ' '), empId = String(req.body.empId || '').trim().toUpperCase(), dept = String(req.body.dept || '');
  if (name.split(' ').length < 2 || name.length > 80) return res.status(400).json({ error: 'Enter your full name (first and last)' });
  if (!/^[A-Z0-9-]{3,20}$/.test(empId)) return res.status(400).json({ error: 'Enter a valid employee ID' });
  if (!DEPTS.includes(dept)) return res.status(400).json({ error: 'Choose your department' });
  if (process.env.EMPLOYEE_ALLOWLIST === 'true') {
    const f = path.join(DATA, 'employees.json'); let list = [];
    try { list = JSON.parse(fs.readFileSync(f, 'utf8')); } catch (e) {}
    const m = list.find(x => String(x.empId).toUpperCase() === empId && String(x.name).toLowerCase() === name.toLowerCase());
    if (!m) return res.status(403).json({ error: 'We could not verify you as a Xerago employee' });
  }
  const remember = !!req.body.remember, life = remember ? 30 * 864e5 : 12 * 36e5;
  setCookie(res, 'xdm_emp', sign({ empId, name, dept, exp: Date.now() + life }), remember ? life : 0);
  res.json({ empId, name, dept });
});
app.get('/api/me', needEmp, (req, res) => res.json({ empId: req.emp.empId, name: req.emp.name, dept: req.emp.dept }));
app.post('/api/auth/logout', (req, res) => { res.clearCookie('xdm_emp'); res.json({ ok: true }); });

// ---------- employee photos ----------
const url = p => `/photos/${p.id}.png`;
app.get('/api/gallery', needEmp, (req, res) => {
  const me = req.emp.empId;
  const own = db.photos.filter(p => p.empId === me).sort((a, b) => b.at - a.at)
    .map(p => ({ id: p.id, url: url(p), status: p.status, votes: voteCount(p.id), at: p.at, own: true }));
  const others = db.photos.filter(p => p.empId !== me && p.status === 'approved' && !p.hidden)
    .map(p => ({ id: p.id, url: url(p), votes: voteCount(p.id), voted: (db.votes[p.id] || []).includes(me), at: p.at, own: false }));
  res.json({ own, others });
});
app.post('/api/photos', needEmp, (req, res) => {
  if (expired()) return res.status(403).json({ error: 'This QR code has expired' });
  const m = /^data:image\/png;base64,([A-Za-z0-9+/=]+)$/.exec(String(req.body.image || ''));
  if (!m) return res.status(400).json({ error: 'Invalid image' });
  const buf = Buffer.from(m[1], 'base64');
  if (buf.length > 6e6 || buf.length < 100 || buf.readUInt32BE(0) !== 0x89504e47) return res.status(400).json({ error: 'Invalid or too large image' });
  const active = db.photos.filter(p => p.empId === req.emp.empId && p.status !== 'rejected').length;
  if (active >= MAX_POSTS) return res.status(409).json({ error: `You have used all ${MAX_POSTS} gallery posts. You can still capture and download.` });
  const id = crypto.randomBytes(8).toString('hex');
  fs.writeFileSync(path.join(PHOTOS, id + '.png'), buf);
  const p = { id, empId: req.emp.empId, name: req.emp.name, dept: req.emp.dept, status: db.settings.autoPublish ? 'approved' : 'pending', at: Date.now(), hidden: null };
  db.photos.push(p); save();
  res.json({ id, status: p.status });
});
app.delete('/api/photos/:id', needEmp, (req, res) => {
  const i = db.photos.findIndex(p => p.id === req.params.id && p.empId === req.emp.empId);
  if (i < 0) return res.status(404).json({ error: 'Not found' });
  const [p] = db.photos.splice(i, 1); delete db.votes[p.id];
  fs.rm(path.join(PHOTOS, p.id + '.png'), () => {}); save(); res.json({ ok: true });
});
app.post('/api/photos/:id/vote', needEmp, (req, res) => {
  const p = db.photos.find(x => x.id === req.params.id);
  if (!db.settings.voting) return res.status(403).json({ error: 'Voting is paused by the organisers' });
  if (!p || p.status !== 'approved' || p.hidden) return res.status(404).json({ error: 'Not found' });
  if (p.empId === req.emp.empId) return res.status(403).json({ error: "You can't vote for your own photo" });
  const v = db.votes[p.id] = db.votes[p.id] || [], i = v.indexOf(req.emp.empId);
  i < 0 ? v.push(req.emp.empId) : v.splice(i, 1); save();
  res.json({ votes: v.length, voted: i < 0 });
});
app.post('/api/photos/:id/report', needEmp, (req, res) => {
  const p = db.photos.find(x => x.id === req.params.id && x.empId !== req.emp.empId);
  if (!p) return res.status(404).json({ error: 'Not found' });
  const cat = String(req.body.category || 'Other').slice(0, 60);
  p.hidden = cat; db.reports.push({ photoId: p.id, by: req.emp.empId, cat, at: Date.now() }); save();
  res.json({ ok: true });
});
app.get('/photos/:id.png', (req, res) => {
  const p = /^[a-f0-9]{16}$/.test(req.params.id) && db.photos.find(x => x.id === req.params.id);
  if (!p) return res.sendStatus(404);
  const ok = req.admin || (req.emp && (req.emp.empId === p.empId || (p.status === 'approved' && !p.hidden)));
  if (!ok) return res.sendStatus(req.emp ? 404 : 401);
  res.set('Cache-Control', 'private, max-age=300'); res.sendFile(path.join(PHOTOS, p.id + '.png'));
});

// ---------- admin auth (email allowlist + one-time code) ----------
const h = s => crypto.createHash('sha256').update(s + SECRET).digest('hex');
app.post('/api/admin/auth/request-code', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (limited('otp:' + req.ip, 10, 600e3) || limited('otp:' + email, 5, 600e3)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  const out = { ok: true, message: 'If this email has admin access, a code has been sent.' };
  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && db.admins.find(a => a.email === email)) {
    const code = String(crypto.randomInt(100000, 1000000));
    db.otps[email] = { h: h(code), exp: Date.now() + 10 * 60e3, tries: 0 }; save();
    try {
      if (mailer) await mailer.sendMail({ from: process.env.MAIL_FROM || 'no-reply@xerago.com', to: email, subject: 'Your Xerago Diwali admin code', text: `Your sign-in code is ${code}. It expires in 10 minutes.` });
      else console.log(`[admin code] ${email}: ${code}`);
    } catch (e) { console.error('mail error', e.message); }
    if (process.env.DEV_SHOW_CODE === 'true' && !PROD) out.devCode = code;
  }
  res.json(out);
});
app.post('/api/admin/auth/verify', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase(), code = String(req.body.code || '');
  if (limited('ver:' + req.ip, 15, 600e3)) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  const o = db.otps[email], rec = db.admins.find(a => a.email === email);
  if (!o || !rec || o.exp < Date.now() || o.tries >= 5) return res.status(401).json({ error: 'Invalid or expired code' });
  o.tries++;
  if (h(code) !== o.h) { save(); return res.status(401).json({ error: 'Invalid or expired code' }); }
  delete db.otps[email]; save();
  setCookie(res, 'xdm_adm', sign({ email, exp: Date.now() + 8 * 36e5 }));
  audit(email, 'sign-in'); res.json({ email, role: rec.role });
});
app.post('/api/admin/auth/logout', (req, res) => { res.clearCookie('xdm_adm'); res.json({ ok: true }); });
app.get('/api/admin/me', needAdmin, (req, res) => res.json(req.admin));

// ---------- admin console ----------
app.get('/api/admin/photos', needAdmin, (req, res) => res.json(db.photos.slice().sort((a, b) => b.at - a.at)
  .map(p => ({ id: p.id, url: url(p), empId: p.empId, name: p.name, dept: p.dept, status: p.status, hidden: p.hidden, votes: voteCount(p.id), at: p.at }))));
app.post('/api/admin/photos/:id/status', needAdmin, (req, res) => {
  const p = db.photos.find(x => x.id === req.params.id), st = req.body.status;
  if (!p || !['approved', 'rejected', 'pending'].includes(st)) return res.status(400).json({ error: 'Bad request' });
  p.status = st; p.hidden = null; save(); audit(req.admin.email, st, `${p.empId} ${p.id}`); res.json({ ok: true });
});
app.post('/api/admin/photos/:id/restore', needAdmin, (req, res) => {
  const p = db.photos.find(x => x.id === req.params.id); if (!p) return res.sendStatus(404);
  p.hidden = null; save(); audit(req.admin.email, 'restore', `${p.empId} ${p.id}`); res.json({ ok: true });
});
const csv = v => `"${String(v).replace(/"/g, '""').replace(/^([=+\-@])/, "'$1")}"`;
app.get('/api/admin/zip', needAdmin, (req, res) => {
  const f = String(req.query.status || 'all');
  const list = db.photos.filter(p => f === 'all' || (f === 'reported' ? p.hidden : p.status === f)).sort((a, b) => a.at - b.at);
  res.set({ 'Content-Type': 'application/zip', 'Content-Disposition': 'attachment; filename="xerago-diwali-photos.zip"' });
  const z = archiver('zip', { zlib: { level: 3 } }); z.on('error', () => res.end()); z.pipe(res);
  let m = 'file,employee_id,name,department,status,votes,posted_at\n';
  list.forEach((p, i) => {
    const fn = `${p.empId}_${p.name.replace(/[^A-Za-z0-9]+/g, '-')}_${i + 1}.png`;
    z.file(path.join(PHOTOS, p.id + '.png'), { name: fn });
    m += [fn, p.empId, p.name, p.dept, p.hidden ? 'reported' : p.status, voteCount(p.id), new Date(p.at).toISOString()].map(csv).join(',') + '\n';
  });
  z.append(m, { name: 'manifest.csv' }); z.finalize(); audit(req.admin.email, 'zip-download', `${f} (${list.length})`);
});
app.get('/api/admin/settings', needAdmin, (req, res) => res.json({ ...db.settings, expired: !!expired(), scanUrl: BASE + '/scan' }));
app.put('/api/admin/settings', needAdmin, (req, res) => {
  const b = req.body, s = db.settings;
  ['autoPublish', 'voting', 'manualExpire'].forEach(k => typeof b[k] === 'boolean' && (s[k] = b[k]));
  if ('expiresAt' in b) { const t = b.expiresAt ? Date.parse(b.expiresAt) : null; if (b.expiresAt && isNaN(t)) return res.status(400).json({ error: 'Bad date' }); s.expiresAt = t; }
  save(); audit(req.admin.email, 'settings', JSON.stringify(b)); res.json({ ...s, expired: !!expired(), scanUrl: BASE + '/scan' });
});
app.get('/api/admin/qr.png', needAdmin, async (req, res) => {
  res.type('png').send(await QRCode.toBuffer(BASE + '/scan', { width: 700, margin: 2, errorCorrectionLevel: 'H', color: { dark: '#005239', light: '#ffffff' } }));
});
app.get('/api/admin/admins', needAdmin, needSuper, (req, res) => res.json(db.admins));
app.post('/api/admin/admins', needAdmin, needSuper, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email' });
  if (db.admins.find(a => a.email === email)) return res.status(409).json({ error: 'Already an admin' });
  db.admins.push({ email, role: 'Admin' }); save(); audit(req.admin.email, 'grant-admin', email); res.json(db.admins);
});
app.delete('/api/admin/admins/:email', needAdmin, needSuper, (req, res) => {
  const email = req.params.email.toLowerCase();
  if (email === SUPER) return res.status(400).json({ error: 'The super admin cannot be removed' });
  db.admins = db.admins.filter(a => a.email !== email); save(); audit(req.admin.email, 'revoke-admin', email); res.json(db.admins);
});
app.get('/api/admin/audit', needAdmin, needSuper, (req, res) => res.json(db.audit.slice(0, 100)));

app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html', extensions: ['html'], setHeaders: r => r.setHeader('Cache-Control', 'no-cache') }));
app.use((err, req, res, next) => { console.error(err.message); res.status(err.status || 500).json({ error: err.status === 413 ? 'Image too large' : 'Server error' }); });
if (require.main === module) app.listen(PORT, () => console.log(`Xerago Diwali Moments on ${BASE}  (admin: ${BASE}${ADMIN_PATH})`));
module.exports = app;
