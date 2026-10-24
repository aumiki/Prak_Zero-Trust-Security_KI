// Uji otomatis seluruh kebijakan (Tabel 3) + verifikasi konteks + keamanan service.
// Prasyarat: `npm start` sedang berjalan. Skrip ini me-reset data (seed) di awal.
const fs = require('fs');
const jwt = require('jsonwebtoken');
const cfg = require('../shared/config');
const db = require('../shared/db');
const { seed, PASSWORD } = require('../db/seed');

const GW = cfg.gatewayUrl;
let pass = 0, fail = 0;

async function call(method, url, { token, device, body, headers = {} } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  if (device) h['X-Device-ID'] = device;
  if (body !== undefined) h['Content-Type'] = 'application/json';
  const res = await fetch(url, { method, headers: h, body: body !== undefined ? JSON.stringify(body) : undefined });
  let data = null;
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}
const gw = (m, p, o) => call(m, GW + p, o);

function expect(name, actual, expected) {
  const ok = actual === expected;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (dapat ${actual}, harusnya ${expected})`}`);
}

async function login(username, device) {
  const r = await gw('POST', '/auth/login', { body: { username, password: PASSWORD }, device });
  return r.data;
}

function setHours(start, end) {
  fs.writeFileSync(cfg.accessHoursFile, JSON.stringify({ start, end }, null, 2));
}

(async () => {
  const originalHours = fs.readFileSync(cfg.accessHoursFile, 'utf8');
  seed();
  setHours('00:00', '23:59'); // pastikan tes tidak bergantung jam eksekusi
  try {
    console.log('\n== Autentikasi ==');
    expect('login valid + device terdaftar -> 200', (await gw('POST', '/auth/login', { body: { username: 'mhs1', password: PASSWORD }, device: 'DEV-MHS1' })).status, 200);
    expect('login password salah -> 401', (await gw('POST', '/auth/login', { body: { username: 'mhs1', password: 'salah' }, device: 'DEV-MHS1' })).status, 401);
    expect('login device milik user lain -> 403', (await gw('POST', '/auth/login', { body: { username: 'mhs1', password: PASSWORD }, device: 'DEV-MHS2' })).status, 403);
    expect('login tanpa X-Device-ID -> 403', (await gw('POST', '/auth/login', { body: { username: 'mhs1', password: PASSWORD } })).status, 403);

    const mhs1 = await login('mhs1', 'DEV-MHS1');
    const mhs2 = await login('mhs2', 'DEV-MHS2');
    const d1 = await login('dosen1', 'DEV-DOSEN1');
    const d2 = await login('dosen2', 'DEV-DOSEN2');
    const adm = await login('admin1', 'DEV-ADMIN1');
    const D = { m1: 'DEV-MHS1', d1: 'DEV-DOSEN1', d2: 'DEV-DOSEN2', adm: 'DEV-ADMIN1' };

    console.log('\n== Token & konteks ==');
    expect('tanpa token -> 401', (await gw('GET', '/nilai', { device: D.m1 })).status, 401);
    expect('token sampah -> 401', (await gw('GET', '/nilai', { token: 'abc.def.ghi', device: D.m1 })).status, 401);
    expect('token kedaluwarsa -> 401', (await gw('GET', '/nilai', { token: jwt.sign({ sub: 'mhs1', role: 'mahasiswa', iss: cfg.issuer }, cfg.jwtSecret, { expiresIn: -10 }), device: D.m1 })).status, 401);
    expect('token ditandatangani secret lain -> 401', (await gw('GET', '/nilai', { token: jwt.sign({ sub: 'admin1', role: 'admin' }, 'secret-palsu', { issuer: cfg.issuer }), device: D.adm })).status, 401);
    expect('tanpa X-Device-ID -> 403', (await gw('GET', '/nilai', { token: mhs1.access_token })).status, 403);
    expect('device tidak terdaftar -> 403', (await gw('GET', '/nilai', { token: mhs1.access_token, device: 'DEV-ASING' })).status, 403);
    expect('device milik user lain -> 403', (await gw('GET', '/nilai', { token: mhs1.access_token, device: D.d1 })).status, 403);
    expect('endpoint tak dikenal -> 403 (default deny)', (await gw('GET', '/admin/rahasia', { token: adm.access_token, device: D.adm })).status, 403);

    console.log('\n== GET /nilai ==');
    let r = await gw('GET', '/nilai', { token: mhs1.access_token, device: D.m1 });
    expect('mahasiswa lihat nilai sendiri -> 200', r.status, 200);
    expect('  hanya 2 nilai miliknya', r.data.data.length, 2);
    expect('  semua NIM miliknya', r.data.data.every((x) => x.nim === '247006111001'), true);
    expect('mahasiswa ?nim=orang lain -> 403', (await gw('GET', '/nilai?nim=247006111002', { token: mhs1.access_token, device: D.m1 })).status, 403);
    r = await gw('GET', '/nilai', { token: d1.access_token, device: D.d1 });
    expect('dosen1 lihat nilai -> 200', r.status, 200);
    expect('  hanya kelas KLS-A (3 nilai)', r.data.data.length === 3 && r.data.data.every((x) => x.kelas_id === 'KLS-A'), true);
    expect('dosen1 ?kelas_id=KLS-A -> 200', (await gw('GET', '/nilai?kelas_id=KLS-A', { token: d1.access_token, device: D.d1 })).status, 200);
    expect('dosen1 ?kelas_id=KLS-B (bukan kelasnya) -> 403', (await gw('GET', '/nilai?kelas_id=KLS-B', { token: d1.access_token, device: D.d1 })).status, 403);
    expect('dosen1 ?kelas_id=KLS-A&kelas_id=KLS-B (parameter ganda) -> 403', (await gw('GET', '/nilai?kelas_id=KLS-A&kelas_id=KLS-B', { token: d1.access_token, device: D.d1 })).status, 403);
    expect('admin GET /nilai -> 403', (await gw('GET', '/nilai', { token: adm.access_token, device: D.adm })).status, 403);

    console.log('\n== PUT /nilai/:id ==');
    // id 1 = mhs1 di KLS-A (dosen1); id 2 = mhs1 di KLS-B (dosen2)
    expect('mahasiswa ubah nilai -> 403', (await gw('PUT', '/nilai/1', { token: mhs1.access_token, device: D.m1, body: { nilai: 100 } })).status, 403);
    expect('dosen2 ubah nilai kelas dosen1 -> 403', (await gw('PUT', '/nilai/1', { token: d2.access_token, device: D.d2, body: { nilai: 100 } })).status, 403);
    expect('dosen1 ubah nilai kelasnya -> 200', (await gw('PUT', '/nilai/1', { token: d1.access_token, device: D.d1, body: { nilai: 90 } })).status, 200);
    expect('dosen1 nilai di luar 0-100 -> 400', (await gw('PUT', '/nilai/1', { token: d1.access_token, device: D.d1, body: { nilai: 150 } })).status, 400);
    setHours('03:00', '03:01');
    expect('dosen1 ubah nilai di luar jam akses -> 403', (await gw('PUT', '/nilai/1', { token: d1.access_token, device: D.d1, body: { nilai: 91 } })).status, 403);
    expect('  (membaca nilai tetap boleh di luar jam akses) -> 200', (await gw('GET', '/nilai', { token: d1.access_token, device: D.d1 })).status, 200);
    expect('dosen1 finalisasi di luar jam akses -> 403', (await gw('POST', '/kelas/KLS-A/finalisasi', { token: d1.access_token, device: D.d1 })).status, 403);
    setHours('00:00', '23:59');

    console.log('\n== Finalisasi + sinkron transkrip ==');
    expect('mahasiswa finalisasi -> 403', (await gw('POST', '/kelas/KLS-A/finalisasi', { token: mhs1.access_token, device: D.m1 })).status, 403);
    expect('dosen2 finalisasi kelas dosen1 -> 403', (await gw('POST', '/kelas/KLS-A/finalisasi', { token: d2.access_token, device: D.d2 })).status, 403);
    r = await gw('GET', '/transkrip/247006111001', { token: adm.access_token, device: D.adm });
    expect('transkrip kosong sebelum finalisasi', r.data.transkrip.length, 0);
    r = await gw('POST', '/kelas/KLS-A/finalisasi', { token: d1.access_token, device: D.d1 });
    expect('dosen1 finalisasi KLS-A -> 200', r.status, 200);
    r = await gw('GET', '/transkrip/247006111001', { token: adm.access_token, device: D.adm });
    expect('transkrip mhs1 berisi KLS-A setelah finalisasi', r.data.transkrip.length === 1 && r.data.transkrip[0].nilai === 90, true);
    expect('ubah nilai setelah final -> 403', (await gw('PUT', '/nilai/1', { token: d1.access_token, device: D.d1, body: { nilai: 50 } })).status, 403);
    expect('finalisasi ulang -> 409', (await gw('POST', '/kelas/KLS-A/finalisasi', { token: d1.access_token, device: D.d1 })).status, 409);

    console.log('\n== GET /transkrip/:nim ==');
    expect('mahasiswa NIM sendiri -> 200', (await gw('GET', '/transkrip/247006111001', { token: mhs1.access_token, device: D.m1 })).status, 200);
    expect('mahasiswa NIM orang lain -> 403', (await gw('GET', '/transkrip/247006111002', { token: mhs1.access_token, device: D.m1 })).status, 403);
    expect('admin NIM siapa pun -> 200', (await gw('GET', '/transkrip/247006111002', { token: adm.access_token, device: D.adm })).status, 200);
    expect('dosen lihat transkrip -> 403', (await gw('GET', '/transkrip/247006111001', { token: d1.access_token, device: D.d1 })).status, 403);

    console.log('\n== Token service & POST /transkrip/sinkron ==');
    const body = { kelas_id: 'KLS-X', kode: 'X', mata_kuliah: 'X', items: [] };
    expect('/auth/service secret salah -> 401', (await gw('POST', '/auth/service', { body: { client_id: 'service-nilai', client_secret: 'salah' } })).status, 401);
    const svc = (await gw('POST', '/auth/service', { body: { client_id: cfg.serviceClientId, client_secret: cfg.serviceClientSecret } })).data;
    expect('/auth/service valid -> token 5 menit', svc.expires_in, 300);
    const claims = jwt.decode(svc.access_token);
    expect('  role token = service', claims.role, 'service');
    expect('  masa berlaku 5 menit', claims.exp - claims.iat, 300);
    expect('sinkron dengan token user (dosen) -> 403', (await gw('POST', '/transkrip/sinkron', { token: d1.access_token, device: D.d1, body })).status, 403);
    expect('sinkron dengan token admin -> 403', (await gw('POST', '/transkrip/sinkron', { token: adm.access_token, device: D.adm, body })).status, 403);
    expect('sinkron tanpa token -> 401', (await gw('POST', '/transkrip/sinkron', { body })).status, 401);
    expect('sinkron dengan token service -> 200', (await gw('POST', '/transkrip/sinkron', { token: svc.access_token, body })).status, 200);
    expect('token service di /nilai -> 403', (await gw('GET', '/nilai', { token: svc.access_token })).status, 403);

    console.log('\n== Akses langsung ke service (bypass gateway) ==');
    const tokenMhs = mhs1.access_token;
    expect('service nilai tanpa gateway secret -> 403', (await call('GET', `${cfg.nilaiUrl}/nilai`, { token: tokenMhs })).status, 403);
    expect('service transkrip tanpa gateway secret -> 403', (await call('GET', `${cfg.transkripUrl}/transkrip/247006111001`, { token: tokenMhs })).status, 403);
    const sec = { 'X-Gateway-Secret': cfg.gatewaySecret };
    expect('gateway secret tanpa token -> 401', (await call('GET', `${cfg.nilaiUrl}/nilai`, { headers: sec })).status, 401);
    expect('gateway secret + token palsu -> 401', (await call('GET', `${cfg.nilaiUrl}/nilai`, { headers: sec, token: jwt.sign({ sub: 'dosen1', role: 'dosen', iss: cfg.issuer }, 'palsu') })).status, 401);
    expect('gateway secret + token kedaluwarsa -> 401', (await call('GET', `${cfg.nilaiUrl}/nilai`, { headers: sec, token: jwt.sign({ sub: 'dosen1', role: 'dosen', iss: cfg.issuer }, cfg.jwtSecret, { expiresIn: -5 }) })).status, 401);
    expect('gateway secret + token valid -> 200', (await call('GET', `${cfg.nilaiUrl}/nilai`, { headers: sec, token: tokenMhs })).status, 200);
    expect('X-Gateway-Secret palsu dari client lewat gateway tetap ditolak policy -> 403', (await gw('GET', '/nilai', { token: tokenMhs, device: 'DEV-ASING', headers: sec })).status, 403);

    console.log('\n== Refresh & logout ==');
    const rf = mhs2.refresh_token;
    r = await gw('POST', '/auth/refresh', { body: { refresh_token: rf } });
    expect('refresh valid -> 200', r.status, 200);
    expect('refresh token lama tidak bisa dipakai lagi -> 401', (await gw('POST', '/auth/refresh', { body: { refresh_token: rf } })).status, 401);
    expect('logout -> 200', (await gw('POST', '/auth/logout', { body: { refresh_token: r.data.refresh_token } })).status, 200);
    expect('refresh setelah logout -> 401', (await gw('POST', '/auth/refresh', { body: { refresh_token: r.data.refresh_token } })).status, 401);
    expect('refresh token acak -> 401', (await gw('POST', '/auth/refresh', { body: { refresh_token: 'abc' } })).status, 401);
    db.prepare('UPDATE refresh_tokens SET expires_at = 0 WHERE user_id = ?').run('dosen2');
    expect('refresh token kedaluwarsa (1 hari) -> 401', (await gw('POST', '/auth/refresh', { body: { refresh_token: d2.refresh_token } })).status, 401);

    console.log('\n== Audit log ==');
    const total = db.prepare('SELECT COUNT(*) c FROM audit_log').get().c;
    const denies = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE hasil='deny'").get().c;
    const allows = db.prepare("SELECT COUNT(*) c FROM audit_log WHERE hasil='allow'").get().c;
    expect('audit log berisi allow dan deny', total > 0 && denies > 0 && allows > 0, true);
    const sample = db.prepare("SELECT * FROM audit_log WHERE hasil='deny' AND subjek='mhs1' AND endpoint LIKE '%/transkrip/%' LIMIT 1").get();
    expect('  entri deny memuat waktu, subjek, endpoint, device, alasan', !!(sample && sample.waktu && sample.subjek && sample.endpoint && sample.device && sample.alasan), true);
  } finally {
    fs.writeFileSync(cfg.accessHoursFile, originalHours);
  }
  console.log(`\nHasil: ${pass} lulus, ${fail} gagal`);
  process.exit(fail ? 1 : 0);
})();
