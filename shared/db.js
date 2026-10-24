// Satu database SQLite bersama untuk gateway (policy engine + audit) dan kedua service.
const fs = require('fs');
const path = require('path');
const { DatabaseSync } = require('node:sqlite'); // bawaan Node >= 22.13 (tanpa kompilasi native)
const cfg = require('./config');

fs.mkdirSync(path.dirname(cfg.dbPath), { recursive: true });
const raw = new DatabaseSync(cfg.dbPath);
raw.exec('PRAGMA busy_timeout = 5000'); // beberapa proses menulis ke file yang sama
raw.exec('PRAGMA foreign_keys = ON');

// Pembungkus tipis agar API-nya: db.prepare(...).get/all/run, db.exec, db.transaction(fn)
const db = {
  prepare: (sql) => raw.prepare(sql),
  exec: (sql) => raw.exec(sql),
  transaction: (fn) => (...args) => {
    raw.exec('BEGIN IMMEDIATE');
    try {
      const result = fn(...args);
      raw.exec('COMMIT');
      return result;
    } catch (err) {
      raw.exec('ROLLBACK');
      throw err;
    }
  },
};

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('mahasiswa','dosen','admin')),
  nama TEXT NOT NULL,
  nim TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS devices (
  user_id TEXT NOT NULL REFERENCES users(id),
  device_id TEXT NOT NULL,
  PRIMARY KEY (user_id, device_id)
);
CREATE TABLE IF NOT EXISTS kelas (
  id TEXT PRIMARY KEY,
  kode TEXT NOT NULL,
  nama TEXT NOT NULL,
  dosen_id TEXT NOT NULL REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS nilai (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kelas_id TEXT NOT NULL REFERENCES kelas(id),
  mahasiswa_id TEXT NOT NULL REFERENCES users(id),
  nilai REAL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','final')),
  UNIQUE (kelas_id, mahasiswa_id)
);
CREATE TABLE IF NOT EXISTS transkrip (
  nim TEXT NOT NULL,
  kelas_id TEXT NOT NULL,
  kode TEXT NOT NULL,
  mata_kuliah TEXT NOT NULL,
  nilai REAL NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (nim, kelas_id)
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS service_clients (
  client_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  waktu TEXT NOT NULL,
  subjek TEXT NOT NULL,
  endpoint TEXT NOT NULL,
  device TEXT,
  hasil TEXT NOT NULL CHECK (hasil IN ('allow','deny')),
  alasan TEXT NOT NULL
);
`);

module.exports = db;
