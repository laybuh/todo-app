const rateLimit = require('express-rate-limit')

// Catch-all limiter for every request — generous, just stops floods/DoS.
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
    message: { error: 'Too many attempts. Please wait a few minutes and try again.' },
})

// Tight limiter for OTP code submission/resend (used once OTP MFA ships).
const otpLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    limit: 6,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: 'Too many code attempts. Please request a new code shortly.' },
})

module.exports = { globalLimiter, authLimiter, otpLimiter }
