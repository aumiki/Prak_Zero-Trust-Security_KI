// Service Transkrip (port 3002): data transkrip mahasiswa. Hanya dapat diakses via gateway.
const express = require('express');
const cfg = require('../shared/config');
const db = require('../shared/db');
const { requireGatewaySecret, requireValidToken, allowRoles } = require('../shared/security');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));

// 4.1: gateway secret + verifikasi ulang token untuk SETIAP request
app.use(requireGatewaySecret, requireValidToken);

// GET /transkrip/:nim - mahasiswa: NIM sendiri; admin: semua NIM
app.get('/transkrip/:nim', allowRoles('mahasiswa', 'admin'), (req, res) => {
  const { sub, role } = req.auth;
  const { nim } = req.params;

  if (role === 'mahasiswa') {
    const me = db.prepare('SELECT nim FROM users WHERE id = ?').get(sub);
    if (!me || me.nim !== nim) return res.status(403).json({ error: 'Mahasiswa hanya boleh melihat transkrip sendiri' });
  }
  const mhs = db.prepare("SELECT nama FROM users WHERE nim = ? AND role = 'mahasiswa'").get(nim);
  if (!mhs) return res.status(404).json({ error: 'NIM tidak ditemukan' });

  const rows = db.prepare(
    'SELECT kelas_id, kode, mata_kuliah, nilai, updated_at FROM transkrip WHERE nim = ? ORDER BY kode'
  ).all(nim);
  res.json({ nim, nama: mhs.nama, transkrip: rows });
});

// POST /transkrip/sinkron - hanya token service (token user mana pun ditolak)
app.post('/transkrip/sinkron', allowRoles('service'), (req, res) => {
  if (req.auth.sub !== 'service-nilai') return res.status(403).json({ error: 'Hanya Service Nilai yang diizinkan' });

  const { kelas_id, kode, mata_kuliah, items } = req.body || {};
  const valid = typeof kelas_id === 'string' && typeof kode === 'string' && typeof mata_kuliah === 'string'
    && Array.isArray(items)
    && items.every((i) => i && typeof i.nim === 'string' && typeof i.nilai === 'number' && i.nilai >= 0 && i.nilai <= 100);
  if (!valid) return res.status(400).json({ error: 'Payload tidak valid' });

  const exists = db.prepare("SELECT 1 FROM users WHERE nim = ? AND role = 'mahasiswa'");
  const upsert = db.prepare(`
    INSERT INTO transkrip (nim, kelas_id, kode, mata_kuliah, nilai, updated_at) VALUES (?,?,?,?,?,?)
    ON CONFLICT (nim, kelas_id) DO UPDATE SET nilai = excluded.nilai, updated_at = excluded.updated_at`);

  try {
    db.transaction(() => {
      for (const it of items) {
        if (!exists.get(it.nim)) throw new Error(`NIM ${it.nim} tidak ditemukan`);
        upsert.run(it.nim, kelas_id, kode, mata_kuliah, it.nilai, new Date().toISOString());
      }
    })();
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
  res.json({ message: 'Transkrip tersinkron', jumlah: items.length });
});

app.listen(cfg.ports.transkrip, () => console.log(`[service-transkrip] berjalan di port ${cfg.ports.transkrip}`));
