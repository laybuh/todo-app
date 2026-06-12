// Single source of truth for the CORS allowlist and the CSRF origin check on
// cookie-authenticated endpoints. Configure extra origins via ALLOWED_ORIGINS
// (comma-separated).
const allowedOrigins = [
    process.env.FRONTEND_URL,
    'https://lunev.vercel.app',
    'https://dospace.vercel.app',
    'http://localhost:5173',
    'http://localhost:3000',
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()) : []),
].filter(Boolean)

module.exports = allowedOrigins
