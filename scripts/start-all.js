// Menjalankan gateway + 2 service sekaligus (satu perintah: npm start).
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const cfg = require('../shared/config');

if (!fs.existsSync(cfg.dbPath)) {
  console.log('Database belum ada -> menjalankan seed...');
  require('../db/seed').seed();
}

const root = path.join(__dirname, '..');
const procs = [
  ['service-nilai', 'service-nilai/index.js'],
  ['service-transkrip', 'service-transkrip/index.js'],
  ['gateway', 'gateway/index.js'],
].map(([name, file]) => {
  const p = spawn(process.execPath, [file], { cwd: root, stdio: 'inherit' });
  p.on('exit', (code) => { console.log(`[${name}] berhenti (kode ${code})`); shutdown(); });
  return p;
});

function shutdown() {
  procs.forEach((p) => p.kill());
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
