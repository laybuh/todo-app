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