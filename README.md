# Sistem Nilai - Zero Trust Security

Tugas Praktikum Individu - Keamanan Informasi (KP70065004), Informatika Universitas Siliwangi.

API Gateway (PEP) + Policy Engine/Administrator + Service Nilai + Service Transkrip, mengikuti NIST SP 800-207.
Stack: Node.js 22.13+ (diuji di Node 22), Express, `http-proxy-middleware`, `jsonwebtoken`, SQLite bawaan Node (`node:sqlite`, tanpa kompilasi native).

```
Client --(Bearer + X-Device-ID)--> Gateway :3000 (PEP + PE/PA + audit log)
                                      |-- X-Gateway-Secret --> Service Nilai     :3001
                                      '-- X-Gateway-Secret --> Service Transkrip :3002
Service Nilai --(token service, via gateway)--> POST /transkrip/sinkron
Semua komponen memakai satu database SQLite: data/sistem-nilai.db
```

## Cara menjalankan

```bash
npm install
npm run seed      # opsional; `npm start` otomatis seed jika database belum ada
npm start         # gateway :3000, service nilai :3001, service transkrip :3002
npm test          # (di terminal lain) 64 uji otomatis seluruh kebijakan
npm run audit     # menampilkan audit log terbaru
```

Docker (opsional): `docker compose up --build` - hanya gateway (3000) yang dipublikasikan ke host.

Konfigurasi lewat environment variable (lihat `shared/config.js`): `JWT_SECRET`, `GATEWAY_SECRET`,
`SERVICE_CLIENT_ID`, `SERVICE_CLIENT_SECRET`, `DB_PATH`, port, dan URL antar-komponen.

## Akun data awal (password semua akun: `password123`)

| Username | Role | Device ID terdaftar | NIM |
|---|---|---|---|
| admin1 | admin | DEV-ADMIN1 | - |
| dosen1 | dosen (mengampu KLS-A) | DEV-DOSEN1 | - |
| dosen2 | dosen (mengampu KLS-B) | DEV-DOSEN2 | - |
| mhs1 | mahasiswa | DEV-MHS1 | 247006111001 |
| mhs2 | mahasiswa | DEV-MHS2 | 247006111002 |
| mhs3 | mahasiswa | DEV-MHS3 | 247006111003 |

Kelas: `KLS-A` (Keamanan Informasi, dosen1) dan `KLS-B` (Basis Data, dosen2). Setiap mahasiswa memiliki nilai (draft) di kedua kelas.
ID nilai: 1-6 (`1` = mhs1 di KLS-A, `2` = mhs1 di KLS-B, dst).
Client service: `service-nilai` / `service-nilai-secret`.

## Jam akses

Perubahan & finalisasi nilai hanya boleh pukul 07.00-21.00 (waktu server). Rentang dibaca dari
`config/access-hours.json` pada **setiap request**, jadi dapat diubah saat demo tanpa restart, mis.:

```json
{ "start": "03:00", "end": "03:01" }
```

## Contoh curl

```bash
# Login (device wajib terdaftar)
curl -s -X POST localhost:3000/auth/login -H "Content-Type: application/json" -H "X-Device-ID: DEV-DOSEN1" \
  -d '{"username":"dosen1","password":"password123"}'
TOKEN=<access_token dari respons>

# Dosen melihat nilai kelasnya
curl -s localhost:3000/nilai -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN1"

# Dosen mengubah nilai, lalu finalisasi (otomatis sinkron ke transkrip)
curl -s -X PUT localhost:3000/nilai/1 -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN1" \
  -H "Content-Type: application/json" -d '{"nilai":90}'
curl -s -X POST localhost:3000/kelas/KLS-A/finalisasi -H "Authorization: Bearer $TOKEN" -H "X-Device-ID: DEV-DOSEN1"

# Admin melihat transkrip
curl -s localhost:3000/transkrip/247006111001 -H "Authorization: Bearer $ADMIN_TOKEN" -H "X-Device-ID: DEV-ADMIN1"

# Bukti service tidak bisa diakses langsung
curl -i localhost:3001/nilai          # 403 (tanpa X-Gateway-Secret)
```

## Pemetaan kebutuhan -> kode (panduan video demo)

| Kebutuhan | Lokasi kode |
|---|---|
| Gateway sebagai PEP, satu-satunya pintu masuk | `gateway/index.js` (middleware PEP: verifikasi token -> `policy.decide` -> audit -> proxy) |
| Policy Engine: allow/deny + alasan, default deny | `gateway/policy.js` (`ROUTES` = Tabel 3, `decide()`) |
| 4.1 Access token JWT 10 menit (sub, role) | `shared/security.js` `signAccessToken`; `gateway/auth.js` `/login` |
| 4.1 Refresh token 1 hari, di DB, dapat dicabut; logout | `gateway/auth.js` `issueRefreshToken`, `/refresh` (rotasi), `/logout`; tabel `refresh_tokens` (hanya hash disimpan) |
| 4.1 Token service 5 menit, role service | `gateway/auth.js` `/service`; `service-nilai/gatewayClient.js` |
| 4.1 Gateway secret (service tidak bisa diakses langsung) | `gateway/index.js` (`proxyReq` menimpa header); `shared/security.js` `requireGatewaySecret` |
| 4.1 Verifikasi ulang token di service | `shared/security.js` `requireValidToken` (dipakai kedua service); `allowRoles` sebagai lapis tambahan |
| 4.2 Kebijakan berbasis kepemilikan data (dibaca dari DB) | `gateway/policy.js` (query `q.kelas`, `q.nilai`, `q.user`) |
| 4.2 Panggilan antar-service via gateway | `service-nilai/gatewayClient.js` -> `POST /transkrip/sinkron` |
| 4.3 Device terdaftar | `gateway/policy.js` `decide()` langkah 5; `gateway/auth.js` `/login` |
| 4.3 Jam akses dapat dikonfigurasi | `gateway/accessHours.js`, `config/access-hours.json` |
| 4.4 Audit log (waktu, subjek, endpoint, device, hasil, alasan) | `gateway/audit.js`; tabel `audit_log`; `npm run audit` |
| Seed (1 admin, 2 dosen, 3 mahasiswa, 2 kelas, 1 device/user) | `db/seed.js` |

## Catatan desain

- **Default deny**: endpoint tanpa kebijakan ditolak; parameter query ganda (`?kelas_id=a&kelas_id=b`) ditolak.
- **Assume breach**: role di token dicocokkan dengan database; kepemilikan data dicek di Policy Engine **dan** difilter ulang di service (query memakai identitas dari token).
- Hanya algoritma HS256 yang diterima saat verifikasi JWT (menolak `alg: none`), issuer diperiksa.
- Secret dan refresh token tidak disimpan polos (scrypt / SHA-256).
- Finalisasi bersifat kompensatif: jika sinkron ke transkrip gagal, status nilai dikembalikan ke `draft`.
- Access token tidak dapat dicabut sebelum kedaluwarsa (10 menit); yang dicabut adalah refresh token.

## Catatan instalasi

Proyek ini tidak memakai paket native, jadi `npm install` tidak memerlukan Python/Visual Studio. Peringatan
`ExperimentalWarning: SQLite is an experimental feature` saat dijalankan berasal dari modul `node:sqlite` bawaan Node dan
dapat diabaikan. Bila `npm install` pernah gagal sebelumnya, hapus folder `node_modules` dan `package-lock.json` lama, lalu jalankan lagi.
