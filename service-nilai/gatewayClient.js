// Panggilan antar-service (Service Nilai -> Service Transkrip) SELALU lewat gateway,
// memakai token service (role: service) dari POST /auth/service.
const cfg = require('../shared/config');

let cache = { token: null, expiresAt: 0 };

async function getServiceToken() {
  if (cache.token && Date.now() < cache.expiresAt - 30_000) return cache.token; // pakai ulang sampai hampir habis
  const res = await fetch(`${cfg.gatewayUrl}/auth/service`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: cfg.serviceClientId, client_secret: cfg.serviceClientSecret }),
  });
  if (!res.ok) throw new Error(`POST /auth/service gagal (HTTP ${res.status})`);
  const data = await res.json();
  cache = { token: data.access_token, expiresAt: Date.now() + data.expires_in * 1000 };
  return cache.token;
}

async function sinkronTranskrip(payload) {
  const token = await getServiceToken();
  const res = await fetch(`${cfg.gatewayUrl}/transkrip/sinkron`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(`POST /transkrip/sinkron ditolak (HTTP ${res.status}): ${detail}`);
  }
  return res.json();
}

module.exports = { sinkronTranskrip };
