// Verifikasi konteks: jam akses (4.3). Rentang dibaca dari config/access-hours.json
// pada setiap request, jadi bisa diubah saat demo tanpa restart.
const fs = require('fs');
const cfg = require('../shared/config');

const toMinutes = (hhmm) => {
  const [h, m] = String(hhmm).split(':').map(Number);
  return h * 60 + (m || 0);
};

function getAccessHours() {
  try {
    const { start, end } = JSON.parse(fs.readFileSync(cfg.accessHoursFile, 'utf8'));
    return { start, end };
  } catch {
    return { start: '07:00', end: '21:00' }; // fallback aman bila file hilang/rusak
  }
}

// true bila start <= waktu sekarang < end (waktu lokal server)
function isWithinAccessHours(now = new Date()) {
  const { start, end } = getAccessHours();
  const t = now.getHours() * 60 + now.getMinutes();
  return t >= toMinutes(start) && t < toMinutes(end);
}

module.exports = { getAccessHours, isWithinAccessHours };
