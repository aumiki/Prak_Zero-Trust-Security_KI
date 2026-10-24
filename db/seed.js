// Mengisi data awal. Aman dijalankan berulang kali (menghapus & mengisi ulang semua data).
const db = require('../shared/db');
const cfg = require('../shared/config');
const { hashSecret } = require('../shared/security');

const PASSWORD = 'password123';

function seed() {
  const hash = hashSecret(PASSWORD); // satu hash dipakai semua akun demo (salt acak tetap valid)

  const users = [
    ['admin1', 'admin1', 'admin', 'Admin Prodi', null],
    ['dosen1', 'dosen1', 'dosen', 'Dosen Satu', null],
    ['dosen2', 'dosen2', 'dosen', 'Dosen Dua', null],
    ['mhs1', 'mhs1', 'mahasiswa', 'Mahasiswa Satu', '247006111001'],
    ['mhs2', 'mhs2', 'mahasiswa', 'Mahasiswa Dua', '247006111002'],
    ['mhs3', 'mhs3', 'mahasiswa', 'Mahasiswa Tiga', '247006111003'],
  ];
  const devices = [
    ['admin1', 'DEV-ADMIN1'], ['dosen1', 'DEV-DOSEN1'], ['dosen2', 'DEV-DOSEN2'],
    ['mhs1', 'DEV-MHS1'], ['mhs2', 'DEV-MHS2'], ['mhs3', 'DEV-MHS3'],
  ];
  const kelas = [
    ['KLS-A', 'KP70065004', 'Keamanan Informasi', 'dosen1'],
    ['KLS-B', 'KP70065002', 'Basis Data', 'dosen2'],
  ];
  // nilai awal berstatus draft; setiap mahasiswa mengikuti kedua kelas
  const scores = { mhs1: [80, 75], mhs2: [85, 90], mhs3: [70, 65] };

  db.transaction(() => {
    for (const t of ['audit_log', 'refresh_tokens', 'transkrip', 'nilai', 'kelas', 'devices', 'service_clients', 'users']) {
      db.prepare(`DELETE FROM ${t}`).run();
    }
    db.prepare("DELETE FROM sqlite_sequence WHERE name IN ('nilai','audit_log')").run();

    const insUser = db.prepare('INSERT INTO users (id, username, password_hash, role, nama, nim) VALUES (?,?,?,?,?,?)');
    users.forEach(([id, uname, role, nama, nim]) => insUser.run(id, uname, hash, role, nama, nim));

    const insDev = db.prepare('INSERT INTO devices (user_id, device_id) VALUES (?,?)');
    devices.forEach((d) => insDev.run(...d));

    const insKelas = db.prepare('INSERT INTO kelas (id, kode, nama, dosen_id) VALUES (?,?,?,?)');
    kelas.forEach((k) => insKelas.run(...k));

    const insNilai = db.prepare("INSERT INTO nilai (kelas_id, mahasiswa_id, nilai, status) VALUES (?,?,?, 'draft')");
    for (const [mhs, [a, b]] of Object.entries(scores)) {
      insNilai.run('KLS-A', mhs, a);
      insNilai.run('KLS-B', mhs, b);
    }

    db.prepare('INSERT INTO service_clients (client_id, secret_hash) VALUES (?,?)')
      .run(cfg.serviceClientId, hashSecret(cfg.serviceClientSecret));
  })();
}

module.exports = { seed, PASSWORD };

if (require.main === module) {
  seed();
  console.log('Seed selesai. Password semua akun demo:', PASSWORD);
}
