// API Gateway = Policy Enforcement Point (PEP). Satu-satunya pintu masuk (port 3000).
// Alur tiap request: verifikasi token -> minta keputusan ke Policy Engine -> audit log -> teruskan.
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');
const cfg = require('../shared/config');
const sec = require('../shared/security');
const policy = require('./policy');
const audit = require('./audit');
const authRouter = require('./auth');

const app = express();
app.disable('x-powered-by');

// Proxy ke service; X-Gateway-Secret selalu ditimpa oleh gateway (tidak bisa dipalsukan client).
const makeProxy = (target) =>
  createProxyMiddleware({
    target,
    changeOrigin: true,
    on: {
      proxyReq: (proxyReq) => proxyReq.setHeader('X-Gateway-Secret', cfg.gatewaySecret),
      error: (err, req, res) => {
        if (res.writeHead) res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Service tidak dapat dihubungi' }));
      },
    },
  });
const nilaiProxy = makeProxy(cfg.nilaiUrl);
const transkripProxy = makeProxy(cfg.transkripUrl);

// /auth/* ditangani gateway sendiri (Policy Administrator)
app.use('/auth', authRouter);

// Semua endpoint lain: PEP
app.use((req, res, next) => {
  const endpoint = `${req.method} ${req.path}`;
  const deviceId = req.get('x-device-id');
  const refuse = (status, subject, reason) => {
    audit.log({ subject, endpoint, device: deviceId, allow: false, reason });
    res.status(status).json({ error: reason });
  };

  // 1. Access token wajib ada & valid (tanda tangan + masa berlaku)
  const token = sec.bearerToken(req);
  if (!token) return refuse(401, 'anonim', 'Access token tidak ada');
  let claims;
  try {
    claims = sec.verifyJwt(token);
  } catch (err) {
    return refuse(401, 'anonim', err.name === 'TokenExpiredError' ? 'Access token kedaluwarsa' : 'Access token tidak valid');
  }

  // 2. Minta keputusan ke Policy Engine
  const decision = policy.decide({
    method: req.method, path: req.path, query: req.query, deviceId, subject: claims,
  });

  // 3. Catat audit log (allow maupun deny)
  audit.log({ subject: claims.sub, endpoint, device: deviceId, allow: decision.allow, reason: decision.reason });
  if (!decision.allow) return res.status(403).json({ error: decision.reason });

  // 4. Teruskan ke service yang sesuai
  delete req.headers['x-gateway-secret'];
  const proxy = req.path.startsWith('/transkrip') ? transkripProxy : nilaiProxy;
  proxy(req, res, next);
});

app.listen(cfg.ports.gateway, () => console.log(`[gateway] PEP berjalan di port ${cfg.ports.gateway}`));
