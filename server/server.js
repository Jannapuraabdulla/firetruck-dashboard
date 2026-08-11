const path = require('path');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db');

const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';
const PORT = process.env.PORT || 3000;

const app = express();
app.use(cors());
app.use(express.json({ limit: '25mb' }));

function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE').get(username);
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: 'Invalid username or password' });
  }

  const token = jwt.sign({ sub: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, username: user.username, role: user.role });
});

app.get('/api/me', auth, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

app.post('/api/change-password', auth, (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both passwords required' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.sub);
  if (!user || !bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, user.id);
  res.json({ ok: true });
});

// Returns all stored data keys/values as a single object: { key: rawJsonStringValue, ... }
app.get('/api/data', auth, (req, res) => {
  const rows = db.prepare('SELECT key, value FROM data_store').all();
  const out = {};
  for (const row of rows) out[row.key] = row.value;
  res.json(out);
});

app.get('/api/data/:key', auth, (req, res) => {
  const row = db.prepare('SELECT value FROM data_store WHERE key = ?').get(req.params.key);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json({ key: req.params.key, value: row.value });
});

app.put('/api/data/:key', auth, (req, res) => {
  const { value } = req.body || {};
  if (typeof value !== 'string') return res.status(400).json({ error: 'value must be a string' });

  db.prepare(`
    INSERT INTO data_store (key, value, updated_by, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_by = excluded.updated_by, updated_at = excluded.updated_at
  `).run(req.params.key, value, req.user.username);

  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, '..')));

app.listen(PORT, () => {
  console.log(`Firetruck dashboard server listening on port ${PORT}`);
});
