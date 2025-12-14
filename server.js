require('dotenv').config();
const express = require('express');
const session = require('express-session');
const crypto = require('crypto');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const db = new sqlite3.Database('keys.db');

// ===== DB init =====
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS api_keys (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);
});

// ===== middleware =====
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET || 'dev_secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true }
}));

// ===== helpers =====
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, m => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[m]));
}

function genApiKey() {
  return crypto.randomBytes(32).toString('hex'); // 64 chars
}

function hashKey(key) {
  return crypto.createHash('sha256').update(key).digest('hex');
}

// sqlite helpers (promise)
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => err ? reject(err) : resolve(row));
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => err ? reject(err) : resolve(rows));
  });
}
function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) reject(err);
      else resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function requireLogin(req, res, next) {
  if (req.session?.authed) return next();
  return res.redirect('/login');
}

async function requireApiKey(req, res, next) {
  try {
    const key = String(req.headers['x-api-key'] || '').trim();
    if (!key) return res.status(401).json({ error: 'Missing x-api-key' });

    const row = await dbGet(
      `SELECT id, name, active FROM api_keys WHERE key_hash = ?`,
      [hashKey(key)]
    );

    if (!row || row.active !== 1) {
      return res.status(403).json({ error: 'Invalid or revoked API key' });
    }

    req.apiKey = row;
    next();
  } catch (e) {
    return res.status(500).json({ error: 'Server error' });
  }
}

// ===== routes =====
app.get('/', (req, res) => res.redirect('/dashboard'));

app.get('/login', (req, res) => {
  res.type('html').send(`
  <html><head><meta charset="utf-8"><title>Login</title></head>
  <body style="font-family:system-ui;max-width:420px;margin:40px auto">
    <h2>Admin Login</h2>
    <form method="POST" action="/login">
      <div style="margin:10px 0">
        <label>User</label><br/>
        <input name="user" style="width:100%;padding:10px" />
      </div>
      <div style="margin:10px 0">
        <label>Password</label><br/>
        <input name="pass" type="password" style="width:100%;padding:10px" />
      </div>
      <button style="padding:10px 14px">Login</button>
    </form>
  </body></html>
  `);
});

app.post('/login', (req, res) => {
  const user = String(req.body.user || '');
  const pass = String(req.body.pass || '');

  const okUser = user === (process.env.ADMIN_USER || 'admin');
  const okPass = pass === (process.env.ADMIN_PASS || '123456');

  if (!okUser || !okPass) return res.status(401).send('Sai tài khoản hoặc mật khẩu');

  req.session.authed = true;
  res.redirect('/dashboard');
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.get('/dashboard', requireLogin, async (req, res) => {
  const keys = await dbAll(
    `SELECT id, name, active, created_at FROM api_keys ORDER BY id DESC`
  );

  const rows = keys.map(k => `
    <tr>
      <td>${k.id}</td>
      <td>${escapeHtml(k.name)}</td>
      <td>${k.active ? '✅ Active' : '⛔ Revoked'}</td>
      <td>${k.created_at}</td>
      <td>
        ${k.active ? `<form method="POST" action="/keys/revoke/${k.id}" style="display:inline">
          <button>Revoke</button>
        </form>` : ''}
      </td>
    </tr>
  `).join('');

  res.type('html').send(`
  <html><head><meta charset="utf-8"><title>Key Dashboard</title></head>
  <body style="font-family:system-ui;max-width:900px;margin:40px auto">
    <div style="display:flex;justify-content:space-between;align-items:center">
      <h2>API Key Dashboard</h2>
      <form method="POST" action="/logout"><button>Logout</button></form>
    </div>

    <h3>Tạo key mới</h3>
    <form method="POST" action="/keys/create" style="display:flex;gap:10px;align-items:center">
      <input name="name" placeholder="Tên key (vd: user A / app mobile)" style="flex:1;padding:10px" />
      <button style="padding:10px 14px">Create</button>
    </form>

    <p style="color:#555">Lưu ý: hệ thống chỉ hiển thị <b>key gốc 1 lần</b> ngay lúc tạo.</p>

    <h3>Danh sách key</h3>
    <table border="1" cellpadding="10" cellspacing="0" style="width:100%;border-collapse:collapse">
      <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Created</th><th>Action</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="5">Chưa có key</td></tr>'}</tbody>
    </table>

    <hr style="margin:24px 0" />
    <h3>Test gọi API validate</h3>
    <pre>curl -H "x-api-key: YOUR_KEY" https://doulinsupermax.onrender.com:${process.env.PORT || 3000}/api/validate-key</pre>
  </body></html>
  `);
});

app.post('/keys/create', requireLogin, async (req, res) => {
  const name = String(req.body.name || 'unnamed').slice(0, 80);
  const key = genApiKey();

  await dbRun(
    `INSERT INTO api_keys (name, key_hash, active) VALUES (?, ?, 1)`,
    [name, hashKey(key)]
  );

  res.type('html').send(`
  <html><head><meta charset="utf-8"><title>Key Created</title></head>
  <body style="font-family:system-ui;max-width:720px;margin:40px auto">
    <h2>✅ Tạo key thành công</h2>
    <p><b>Name:</b> ${escapeHtml(name)}</p>
    <p><b>API Key (chỉ hiện 1 lần):</b></p>
    <pre style="padding:12px;background:#111;color:#0f0;border-radius:8px;white-space:pre-wrap">${key}</pre>
    <a href="/dashboard">← Về Dashboard</a>
  </body></html>
  `);
});

app.post('/keys/revoke/:id', requireLogin, async (req, res) => {
  const id = Number(req.params.id);
  await dbRun(`UPDATE api_keys SET active = 0 WHERE id = ?`, [id]);
  res.redirect('/dashboard');
});

// ===== API validate key =====
app.get('/api/validate-key', requireApiKey, (req, res) => {
  res.json({ ok: true, owner: req.apiKey.name });
});

// ===== start =====
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running: https://doulinsupermax.onrender.com:${port}`);
});
