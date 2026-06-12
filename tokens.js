const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const db = require('./db')

// Short-lived access token; long-lived rotating refresh token.
const ACCESS_TTL = '15m'
const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

const signAccess = (user) =>
    jwt.sign({ id: user.id, username: user.username }, process.env.SECRETEST_KEY, { expiresIn: ACCESS_TTL })

const hashToken = (raw) => crypto.createHash('sha256').update(raw).digest('hex')

// Cookie security adapts to the request: over HTTPS (prod behind Render's proxy)
// we use SameSite=None+Secure so the cross-site cookie (Vercel↔Render) is sent;
// over plain HTTP (local dev) we use Lax so it still works without HTTPS.
function cookieOptions(req) {
    const isHttps = req.secure || req.headers['x-forwarded-proto'] === 'https'
    return {
        httpOnly: true,
        secure: isHttps,
        sameSite: isHttps ? 'none' : 'lax',
        path: '/auth',
        maxAge: REFRESH_TTL_MS,
    }
}

// Store a new refresh token (hashed) in a token "family" for reuse detection.
async function issueRefreshToken(userId, familyId) {
    const raw = crypto.randomBytes(48).toString('hex')
    const family = familyId || crypto.randomBytes(16).toString('hex')
    const expiresAt = Date.now() + REFRESH_TTL_MS
    await db.query(
        'INSERT INTO refresh_tokens (user_id, token_hash, family_id, expires_at) VALUES ($1, $2, $3, $4)',
        [userId, hashToken(raw), family, expiresAt]
    )
    return { raw, family }
}

// Issue an access token + set the rotating refresh cookie. Returns the access token.
async function startSession(req, res, user, familyId) {
    const { raw } = await issueRefreshToken(user.id, familyId)
    res.cookie('refreshToken', raw, cookieOptions(req))
    return signAccess(user)
}

function clearRefreshCookie(req, res) {
    const opts = cookieOptions(req)
    delete opts.maxAge
    res.clearCookie('refreshToken', opts)
}

module.exports = { signAccess, hashToken, issueRefreshToken, startSession, clearRefreshCookie, ACCESS_TTL, REFRESH_TTL_MS }
