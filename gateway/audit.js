// Audit log (4.4): setiap keputusan akses dicatat oleh gateway.
const db = require('../shared/db');

const insert = db.prepare(
  'INSERT INTO audit_log (waktu, subjek, endpoint, device, hasil, alasan) VALUES (?,?,?,?,?,?)'
);

/**
 * @param {object} e
 * @param {string} e.subject  user id / client id service / "anonim"
 * @param {string} e.endpoint "METHOD /path"
 * @param {string} [e.device]
 * @param {boolean} e.allow
 * @param {string} e.reason
 */
function log({ subject, endpoint, device, allow, reason }) {
  insert.run(
    new Date().toISOString(),
    subject || 'anonim',
    endpoint,
    device || '-',
    allow ? 'allow' : 'deny',
    reason
  );
}

module.exports = { log };
