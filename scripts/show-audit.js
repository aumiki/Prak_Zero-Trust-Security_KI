// Menampilkan audit log terbaru: npm run audit [jumlah]
const db = require('../shared/db');
const n = Number(process.argv[2]) || 30;
const rows = db.prepare('SELECT waktu, subjek, endpoint, device, hasil, alasan FROM audit_log ORDER BY id DESC LIMIT ?').all(n).reverse();
console.table(rows);
