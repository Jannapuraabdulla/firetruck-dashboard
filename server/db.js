const path = require('path');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, 'data.sqlite'));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS data_store (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_by TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

const userCount = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (userCount === 0) {
  const username = process.env.SEED_ADMIN_USER || 'Shakeel.Abdulla';
  const password = process.env.SEED_ADMIN_PASS || 'Operations@2026';
  const hash = bcrypt.hashSync(password, 10);
  db.prepare('INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)')
    .run(username, hash, 'admin');
  console.log(`Seeded default admin user "${username}". Change this password after first login.`);
}

module.exports = db;
