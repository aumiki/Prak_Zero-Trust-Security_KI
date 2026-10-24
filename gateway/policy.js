// Policy Engine (PE) - memutuskan allow/deny berdasarkan Tabel 3 + atribut dari database.
// Prinsip: default deny. Setiap keputusan mengembalikan { allow, reason }.
const db = require('../shared/db');
const { isWithinAccessHours, getAccessHours } = require('./accessHours');

const USER_ROLES = ['mahasiswa', 'dosen', 'admin'];

const q = {
  user: db.prepare('SELECT id, role, nim FROM users WHERE id = ?'),
  device: db.prepare('SELECT 1 FROM devices WHERE user_id = ? AND device_id = ?'),
  kelas: db.prepare('SELECT id, dosen_id FROM kelas WHERE id = ?'),
  nilai: db.prepare(
    'SELECT n.id, n.status, k.dosen_id FROM nilai n JOIN kelas k ON k.id = n.kelas_id WHERE n.id = ?'
  ),
};

const allow = (reason) => ({ allow: true, reason });
const deny = (reason) => ({ allow: false, reason });

const oneString = (v) => typeof v === 'string'; // menolak ?x=a&x=b (array) & objek

function checkHours() {
  if (isWithinAccessHours()) return null;
  const { start, end } = getAccessHours();
  return deny(`Di luar jam akses (${start}-${end})`);
}

// ---- Tabel 3: kebijakan per endpoint ----
const ROUTES = [
  {
    name: 'GET /nilai', method: 'GET', re: /^\/nilai\/?$/, roles: ['mahasiswa', 'dosen'],
    check({ user, query }) {
      if (query.kelas_id !== undefined && !oneString(query.kelas_id)) return deny('Parameter kelas_id tidak valid');
      if (query.nim !== undefined && !oneString(query.nim)) return deny('Parameter nim tidak valid');

      if (user.role === 'mahasiswa') {
        // Mahasiswa: hanya nilai miliknya
        if (query.nim !== undefined && query.nim !== user.nim) return deny('Mahasiswa hanya boleh melihat nilai miliknya sendiri');
        return allow('Mahasiswa melihat nilai miliknya');
      }
      // Dosen: hanya kelas yang diampu
      if (query.kelas_id !== undefined) {
        const k = q.kelas.get(query.kelas_id);
        if (!k || k.dosen_id !== user.id) return deny('Dosen hanya boleh melihat nilai pada kelas yang diampunya');
      }
      return allow('Dosen melihat nilai pada kelas yang diampunya');
    },
  },
  {
    name: 'PUT /nilai/:id', method: 'PUT', re: /^\/nilai\/(\d+)\/?$/, roles: ['dosen'],
    check({ user, match }) {
      const n = q.nilai.get(Number(match[1]));
      if (!n || n.dosen_id !== user.id) return deny('Nilai bukan pada kelas yang diampu dosen');
      if (n.status === 'final') return deny('Nilai sudah final dan tidak dapat diubah');
      return checkHours() || allow('Dosen mengubah nilai pada kelas yang diampunya (draft, dalam jam akses)');
    },
  },
  {
    name: 'POST /kelas/:id/finalisasi', method: 'POST', re: /^\/kelas\/([A-Za-z0-9_-]+)\/finalisasi\/?$/, roles: ['dosen'],
    check({ user, match }) {
      const k = q.kelas.get(match[1]);
      if (!k || k.dosen_id !== user.id) return deny('Kelas tidak diampu oleh dosen ini');
      return checkHours() || allow('Dosen memfinalisasi kelas yang diampunya (dalam jam akses)');
    },
  },
  {
    name: 'GET /transkrip/:nim', method: 'GET', re: /^\/transkrip\/([A-Za-z0-9_-]+)\/?$/, roles: ['mahasiswa', 'admin'],
    check({ user, match }) {
      if (user.role === 'admin') return allow('Admin melihat transkrip semua mahasiswa');
      if (match[1] !== user.nim) return deny('Mahasiswa hanya boleh melihat transkrip dengan NIM sendiri');
      return allow('Mahasiswa melihat transkrip miliknya');
    },
  },
  {
    name: 'POST /transkrip/sinkron', method: 'POST', re: /^\/transkrip\/sinkron\/?$/, roles: ['service'],
    check({ subject }) {
      if (subject.sub !== 'service-nilai') return deny('Hanya Service Nilai yang boleh sinkron transkrip');
      return allow('Service Nilai sinkron transkrip');
    },
  },
];

/**
 * @param {{method:string, path:string, query:object, deviceId?:string,
 *          subject:{sub:string, role:string}}} ctx  subject = klaim JWT yang sudah diverifikasi
 * @returns {{allow:boolean, reason:string}}
 */
function decide(ctx) {
  const { method, path, query, deviceId, subject } = ctx;

  // 1. Cari kebijakan (default deny jika tidak ada)
  let route = null;
  let match = null;
  for (const r of ROUTES) {
    if (r.method !== method) continue;
    const m = r.re.exec(path);
    if (m) { route = r; match = m; break; }
  }
  if (!route) return deny('Tidak ada kebijakan untuk endpoint ini (default deny)');

  // 2. Cek role pada token
  if (!route.roles.includes(subject.role)) {
    return deny(`Role '${subject.role}' tidak diizinkan pada ${route.name}`);
  }

  // 3. Panggilan service: tanpa device, langsung ke aturan endpoint
  if (subject.role === 'service') {
    return route.check({ subject, user: null, query, match });
  }

  // 4. Panggilan user: atribut dari database (assume breach: jangan percaya isi token begitu saja)
  if (!USER_ROLES.includes(subject.role)) return deny('Role tidak dikenal');
  const user = q.user.get(subject.sub);
  if (!user) return deny('User tidak ditemukan di database');
  if (user.role !== subject.role) return deny('Role pada token tidak sesuai dengan database');

  // 5. Verifikasi konteks: device terdaftar (4.3)
  if (!deviceId) return deny('Header X-Device-ID tidak ada');
  if (!q.device.get(user.id, deviceId)) return deny('Device tidak terdaftar untuk user ini');

  // 6. Aturan khusus endpoint (kepemilikan data, status nilai, jam akses)
  return route.check({ subject, user, query, match });
}

module.exports = { decide };
