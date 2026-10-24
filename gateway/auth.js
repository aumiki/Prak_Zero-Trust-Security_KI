// Policy Administrator (PA): login, refresh, logout, dan token service (4.1).
// Endpoint /auth/* ditangani langsung oleh gateway.
const crypto = require('crypto');
const express = require('express');
const db = require('../shared/db');
const cfg = require('../shared/config');
const sec = require('../shared/security');
const audit = require('./audit');

const router = express.Router();
router.use(express.json({ limit: '10kb' }));

const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  device: db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'),
  insRefresh: db.prepare('INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?,?,?)'),
  getRefresh: db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?'),
  revokeRefresh: db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?'),
  client: db.prepare('SELECT * FROM service_clients WHERE client_id = ?'),
};

// Respons + audit dalam satu langkah
function respond(req, res, { status, subject, allow, reason, body }) {
  audit.log({
    subject,
    endpoint: `${req.method} ${req.baseUrl}${req.path}`,
    device: req.get('x-device-id'),
    allow,
    reason,
  });
  res.status(status).json(body ?? (allow ? { message: reason } : { error: reason }));
}

// Refresh token: string acak, hanya hash-nya yang disimpan di DB sehingga dapat dicabut.
function issueRefreshToken(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  q.insRefresh.run(sec.sha256(token), userId, Date.now() + cfg.tokenTtl.refreshMs);
  return token;
}

const tokenPair = (user) => ({
  access_token: sec.signAccessToken(user), // JWT 10 menit
  token_type: 'Bearer',
  expires_in: 600,
  refresh_token: issueRefreshToken(user.id), // 1 hari
});

// POST /auth/login - kredensial valid + device terdaftar
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const deviceId = req.get('x-device-id');
  const user = typeof username === 'string' ? q.userByName.get(username) : null;
  const subject = user ? user.id : `anonim(${String(username).slice(0, 30)})`;

  if (!user || !sec.verifySecret(password, user.password_hash)) {
    return respond(req, res, { status: 401, subject, allow: false, reason: 'Kredensial tidak valid' });
  }
  if (!deviceId) {
    return respond(req, res, { status: 403, subject, allow: false, reason: 'Header X-Device-ID tidak ada' });
  }
  if (!q.device.get(user.id, deviceId)) {
    return respond(req, res, { status: 403, subject, allow: false, reason: 'Device tidak terdaftar untuk user ini' });
  }
  respond(req, res, {
    status: 200, subject, allow: true, reason: 'Login berhasil', body: { ...tokenPair(user), role: user.role },
  });
});

// POST /auth/refresh - refresh token valid dan belum dicabut (dirotasi: yang lama dicabut)
router.post('/refresh', (req, res) => {
  const { refresh_token } = req.body || {};
  const row = typeof refresh_token === 'string' ? q.getRefresh.get(sec.sha256(refresh_token)) : null;
  if (!row) return respond(req, res, { status: 401, subject: 'anonim', allow: false, reason: 'Refresh token tidak dikenal' });
  if (row.revoked) return respond(req, res, { status: 401, subject: row.user_id, allow: false, reason: 'Refresh token sudah dicabut' });
  if (row.expires_at < Date.now()) return respond(req, res, { status: 401, subject: row.user_id, allow: false, reason: 'Refresh token kedaluwarsa' });

  const user = q.userById.get(row.user_id);
  if (!user) return respond(req, res, { status: 401, subject: row.user_id, allow: false, reason: 'User tidak ditemukan' });

  q.revokeRefresh.run(row.token_hash);
  respond(req, res, { status: 200, subject: user.id, allow: true, reason: 'Token diperbarui', body: tokenPair(user) });
});

// POST /auth/logout - mencabut refresh token
router.post('/logout', (req, res) => {
  const { refresh_token } = req.body || {};
  const row = typeof refresh_token === 'string' ? q.getRefresh.get(sec.sha256(refresh_token)) : null;
  if (!row) return respond(req, res, { status: 401, subject: 'anonim', allow: false, reason: 'Refresh token tidak dikenal' });
  q.revokeRefresh.run(row.token_hash);
  respond(req, res, { status: 200, subject: row.user_id, allow: true, reason: 'Logout: refresh token dicabut' });
});

// POST /auth/service - token service (5 menit, role: service) hanya untuk Service Nilai
router.post('/service', (req, res) => {
  const { client_id, client_secret } = req.body || {};
  const client = typeof client_id === 'string' ? q.client.get(client_id) : null;
  const subject = typeof client_id === 'string' ? client_id : 'anonim';
  if (!client || !sec.verifySecret(client_secret, client.secret_hash)) {
    return respond(req, res, { status: 401, subject, allow: false, reason: 'Client ID/secret tidak valid' });
  }
  respond(req, res, {
    status: 200, subject, allow: true, reason: 'Token service diterbitkan',
    body: { access_token: sec.signServiceToken(client.client_id), token_type: 'Bearer', expires_in: 300 },
  });
});

// Endpoint /auth/* lain: default deny
router.use((req, res) =>
  respond(req, res, { status: 404, subject: 'anonim', allow: false, reason: 'Tidak ada kebijakan untuk endpoint ini (default deny)' })
);

module.exports = router;
