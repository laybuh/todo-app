const crypto = require('crypto')
const rateLimit = require('express-rate-limit')
const db = require('../db')

// Postgres-backed store so limits hold across serverless instances (in-memory
// counters reset per instance). Keys are hashed so raw IPs are never stored.
class PgStore {
    constructor(prefix) {
        this.prefix = prefix
    }

    init(options) {
        this.windowMs = options.windowMs
    }

    keyFor(key) {
        return crypto.createHash('sha256').update(`${this.prefix}:${key}`).digest('hex')
    }

    async increment(key) {
        const { rows } = await db.query(
            `INSERT INTO rate_limits (key, hits, reset_at)
             VALUES ($1, 1, now() + $2 * interval '1 millisecond')
             ON CONFLICT (key) DO UPDATE SET
                 hits = CASE WHEN rate_limits.reset_at <= now() THEN 1 ELSE rate_limits.hits + 1 END,
                 reset_at = CASE WHEN rate_limits.reset_at <= now() THEN EXCLUDED.reset_at ELSE rate_limits.reset_at END
             RETURNING hits, reset_at`,
            [this.keyFor(key), this.windowMs]
        )
        return { totalHits: rows[0].hits, resetTime: rows[0].reset_at }
    }

    async decrement(key) {
        await db.query('UPDATE rate_limits SET hits = GREATEST(hits - 1, 0) WHERE key = $1', [this.keyFor(key)])
    }

    async resetKey(key) {
        await db.query('DELETE FROM rate_limits WHERE key = $1', [this.keyFor(key)])
    }
}

// Remove expired counters. Called from the daily cron.
async function purgeExpiredRateLimits() {
    try {
        await db.query('DELETE FROM rate_limits WHERE reset_at <= now()')
    } catch (err) {
        console.error('[cleanup] rate limit purge error:', err.message)
    }
}

// Catch-all limiter for every request — generous, just stops floods/DoS.
// Kept in memory: it's coarse flood protection and shouldn't add a DB query
// to every request.
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many requests. Please slow down and try again shortly.' },
})

// Strict limiter for sensitive auth actions (login, register, forgot/reset).
// Per-IP. Keeps credential-stuffing and brute force in check.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 12,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    store: new PgStore('auth'),
    message: { error: 'Too many attempts. Please wait a few minutes and try again.' },
})

// Tight limiter for OTP code submission/resend.
const otpLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: 6,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    store: new PgStore('otp'),
    message: { error: 'Too many code attempts. Please request a new code shortly.' },
})

module.exports = { globalLimiter, authLimiter, otpLimiter, purgeExpiredRateLimits }
