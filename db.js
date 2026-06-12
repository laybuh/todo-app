const { Pool } = require('pg')
require('dotenv').config()

// TLS strategy:
//  - If DB_CA_CERT is set (recommended in production — paste the provider's CA
//    cert, e.g. Render's, into the env var), verify the server certificate
//    against it. This prevents man-in-the-middle attacks on the DB connection.
//  - Otherwise fall back to encrypted-but-unverified TLS so local dev and
//    providers that don't expose a CA still connect. Avoid this in production.
function sslConfig() {
  if (process.env.DB_CA_CERT) {
    return { rejectUnauthorized: true, ca: process.env.DB_CA_CERT }
  }
  if (process.env.DB_SSL === 'false') {
    return false
  }
  // Encrypted but unverified: fine for local dev, but in production this leaves
  // the DB connection open to a man-in-the-middle. Set DB_CA_CERT (e.g. Render's
  // CA cert) to verify the server certificate. Warn loudly if we ever run this
  // way in production so it doesn't go unnoticed.
  if (process.env.NODE_ENV === 'production') {
    console.warn('[db] WARNING: TLS is on but the database certificate is NOT being verified. Set DB_CA_CERT to enable verification.')
  }
  return { rejectUnauthorized: false }
}

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 5432,
  ssl: sslConfig()
})

module.exports = pool