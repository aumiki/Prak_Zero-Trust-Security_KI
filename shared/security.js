// Fungsi keamanan bersama: hash secret, JWT, dan middleware verifikasi ulang di service.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const cfg = require('./config');

const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function hashSecret(plain) {
  const salt = crypto.randomBytes(16).toString('hex');
  return `${salt}:${crypto.scryptSync(plain, salt, 32).toString('hex')}`;
}

function verifySecret(plain, stored) {
  if (typeof plain !== 'string' || typeof stored !== 'string') return false;
  const [salt, hash] = stored.split(':');
  const expected = Buffer.from(hash, 'hex');
  const actual = crypto.scryptSync(plain, salt, expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

// Perbandingan waktu-konstan (dibandingkan lewat hash agar panjang selalu sama)
const safeEqual = (a, b) =>
  crypto.timingSafeEqual(Buffer.from(sha256(a ?? '')), Buffer.from(sha256(b ?? '')));

// ---- JWT ----
const jwtOpts = (expiresIn) => ({ algorithm: 'HS256', expiresIn, issuer: cfg.issuer });

const signAccessToken = (user) =>
  jwt.sign({ sub: user.id, role: user.role }, cfg.jwtSecret, jwtOpts(cfg.tokenTtl.access));

const signServiceToken = (clientId) =>
  jwt.sign({ sub: clientId, role: 'service' }, cfg.jwtSecret, jwtOpts(cfg.tokenTtl.service));

// Memverifikasi tanda tangan, masa berlaku, dan issuer. Hanya HS256 yang diterima
// (menolak alg "none" / algoritma lain).
const verifyJwt = (token) =>
  jwt.verify(token, cfg.jwtSecret, { algorithms: ['HS256'], issuer: cfg.issuer });

function bearerToken(req) {
  const m = /^Bearer (.+)$/i.exec(req.headers.authorization || '');
  return m ? m[1] : null;
}

// ---- Middleware untuk Service Nilai & Service Transkrip (4.1) ----

// Lapis 1: request hanya boleh datang dari gateway.
function requireGatewaySecret(req, res, next) {
  if (!safeEqual(req.headers['x-gateway-secret'], cfg.gatewaySecret)) {
    return res.status(403).json({ error: 'Ditolak: X-Gateway-Secret tidak ada/tidak valid (akses langsung ke service tidak diizinkan)' });
  }
  next();
}

// Lapis 2: verifikasi ulang token di service, walau gateway sudah memeriksanya.
function requireValidToken(req, res, next) {
  const token = bearerToken(req);
  if (!token) return res.status(401).json({ error: 'Ditolak: access token tidak ada' });
  try {
    req.auth = verifyJwt(token); // { sub, role, iat, exp, iss }
    next();
  } catch (err) {
    const msg = err.name === 'TokenExpiredError' ? 'token kedaluwarsa' : 'token tidak valid';
    res.status(401).json({ error: `Ditolak: ${msg}` });
  }
}

// Lapis 3 (defense in depth): pembatasan role di tingkat service.
const allowRoles = (...roles) => (req, res, next) =>
  roles.includes(req.auth.role)
    ? next()
    : res.status(403).json({ error: `Ditolak: role '${req.auth.role}' tidak diizinkan di endpoint ini` });

module.exports = {
  sha256, hashSecret, verifySecret, safeEqual,
  signAccessToken, signServiceToken, verifyJwt, bearerToken,
  requireGatewaySecret, requireValidToken, allowRoles,
};
