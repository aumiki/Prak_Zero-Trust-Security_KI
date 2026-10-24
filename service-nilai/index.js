// Service Nilai (port 3001): data nilai & kelas. Tidak dapat diakses langsung - hanya via gateway.
const express = require('express');
const cfg = require('../shared/config');
const db = require('../shared/db');
const { requireGatewaySecret, requireValidToken, allowRoles } = require('../shared/security');
const { sinkronTranskrip } = require('./gatewayClient');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '100kb' }));

// 4.1: gateway secret + verifikasi ulang token untuk SETIAP request
app.use(requireGatewaySecret, requireValidToken);

const LIST_BASE = `
  SELECT n.id, n.kelas_id, k.kode, k.nama AS mata_kuliah, u.nim, u.nama AS mahasiswa, n.nilai, n.status
  FROM nilai n JOIN kelas k ON k.id = n.kelas_id JOIN users u ON u.id = n.mahasiswa_id`;

// GET /nilai - mahasiswa: nilai miliknya; dosen: kelas yang diampu
app.get('/nilai', allowRoles('mahasiswa', 'dosen'), (req, res) => {
  const { sub, role } = req.auth;
  const kelasId = typeof req.query.kelas_id === 'string' ? req.query.kelas_id : null;
  // Filter data berdasarkan identitas di token (bukan parameter query) -> tidak bisa melebar
  const rows = role === 'mahasiswa'
    ? db.prepare(`${LIST_BASE} WHERE n.mahasiswa_id = ?`).all(sub)
    : db.prepare(`${LIST_BASE} WHERE k.dosen_id = ? AND (? IS NULL OR n.kelas_id = ?)`).all(sub, kelasId, kelasId);
  res.json({ data: rows });
});

// PUT /nilai/:id - dosen mengubah nilai (kelas diampu & belum final)
app.put('/nilai/:id', allowRoles('dosen'), (req, res) => {
  const value = req.body?.nilai;
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100) {
    return res.status(400).json({ error: 'Field "nilai" wajib angka 0-100' });
  }
  // Kepemilikan & status dicek ulang di dalam query (defense in depth)
  const r = db.prepare(`
    UPDATE nilai SET nilai = ?
    WHERE id = ? AND status != 'final'
      AND kelas_id IN (SELECT id FROM kelas WHERE dosen_id = ?)`).run(value, Number(req.params.id), req.auth.sub);
  if (r.changes === 0) return res.status(403).json({ error: 'Nilai tidak dapat diubah (bukan kelas Anda atau sudah final)' });
  res.json({ message: 'Nilai diperbarui', id: Number(req.params.id), nilai: value });
});

// POST /kelas/:id/finalisasi - finalisasi lalu sinkron ke Service Transkrip (via gateway)
app.post('/kelas/:id/finalisasi', allowRoles('dosen'), async (req, res) => {
  const kelas = db.prepare('SELECT * FROM kelas WHERE id = ? AND dosen_id = ?').get(req.params.id, req.auth.sub);
  if (!kelas) return res.status(403).json({ error: 'Kelas tidak diampu oleh dosen ini' });

  const rows = db.prepare(`
    SELECT n.id, u.nim, n.nilai, n.status FROM nilai n JOIN users u ON u.id = n.mahasiswa_id
    WHERE n.kelas_id = ?`).all(kelas.id);
  if (rows.length === 0) return res.status(409).json({ error: 'Kelas belum memiliki nilai' });
  if (rows.every((r) => r.status === 'final')) return res.status(409).json({ error: 'Kelas sudah difinalisasi' });
  if (rows.some((r) => r.nilai === null)) return res.status(409).json({ error: 'Masih ada nilai yang kosong' });

  db.prepare("UPDATE nilai SET status = 'final' WHERE kelas_id = ?").run(kelas.id);
  try {
    await sinkronTranskrip({
      kelas_id: kelas.id, kode: kelas.kode, mata_kuliah: kelas.nama,
      items: rows.map((r) => ({ nim: r.nim, nilai: r.nilai })),
    });
  } catch (err) {
    // Kompensasi: sinkron gagal -> kembalikan ke draft agar tidak ada nilai final yang tidak masuk transkrip
    db.prepare("UPDATE nilai SET status = 'draft' WHERE kelas_id = ?").run(kelas.id);
    return res.status(502).json({ error: 'Sinkron transkrip gagal, finalisasi dibatalkan', detail: err.message });
  }
  res.json({ message: 'Kelas difinalisasi dan transkrip tersinkron', kelas_id: kelas.id, jumlah_nilai: rows.length });
});

app.listen(cfg.ports.nilai, () => console.log(`[service-nilai] berjalan di port ${cfg.ports.nilai}`));
