// Konfigurasi terpusat. Semua nilai bisa di-override lewat environment variable.
const path = require('path');
const ROOT = path.join(__dirname, '..');

module.exports = {
  ports: {
    gateway: Number(process.env.GATEWAY_PORT) || 3000,
    nilai: Number(process.env.NILAI_PORT) || 3001,
    transkrip: Number(process.env.TRANSKRIP_PORT) || 3002,
  },
  // URL tujuan (gateway meneruskan request ke sini; Service Nilai memanggil gateway)
  gatewayUrl: process.env.GATEWAY_URL || 'http://localhost:3000',
  nilaiUrl: process.env.NILAI_URL || 'http://localhost:3001',
  transkripUrl: process.env.TRANSKRIP_URL || 'http://localhost:3002',

  dbPath: process.env.DB_PATH || path.join(ROOT, 'data', 'sistem-nilai.db'),

  // Rahasia (ganti lewat env untuk lingkungan nyata)
  jwtSecret: process.env.JWT_SECRET || 'dev-jwt-secret-ganti-di-produksi',
  gatewaySecret: process.env.GATEWAY_SECRET || 'dev-gateway-secret-ganti-di-produksi',

  // Kredensial Service Nilai untuk POST /auth/service
  serviceClientId: process.env.SERVICE_CLIENT_ID || 'service-nilai',
  serviceClientSecret: process.env.SERVICE_CLIENT_SECRET || 'service-nilai-secret',

  tokenTtl: { access: '10m', service: '5m', refreshMs: 24 * 60 * 60 * 1000 },
  issuer: 'sistem-nilai-gateway',

  // Jam akses dibaca dari file ini pada setiap request (bisa diubah tanpa restart)
  accessHoursFile: process.env.ACCESS_HOURS_FILE || path.join(ROOT, 'config', 'access-hours.json'),
};
