const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const { Resend } = require('resend')
const db = require('../db')
const { authLimiter, otpLimiter } = require('../middleware/rateLimiters')
const { validateRegister, validateLogin, validateEmailOnly } = require('../middleware/validate')
const { recordEvent, checkFailedLoginAnomaly, checkSignupSpike } = require('../security')
const verifyToken = require('../middleware/verifyToken')
const { signAccess, hashToken, startSession, clearRefreshCookie } = require('../tokens')

const resend = new Resend(process.env.RESEND_API_KEY)

// Generate a 6-digit code, store it bcrypt-hashed with a 10-minute expiry
// (replacing any prior code for the user), and email it. Used by login + resend.
async function issueOtp(user) {
    const code = String(crypto.randomInt(0, 1000000)).padStart(6, '0')
    const codeHash = await bcrypt.hash(code, 10)
    const expiresAt = Date.now() + 10 * 60 * 1000

    await db.query('DELETE FROM otp_codes WHERE user_id = $1', [user.id])
    await db.query(
        'INSERT INTO otp_codes (user_id, code_hash, expires_at, attempts) VALUES ($1, $2, $3, 0)',
        [user.id, codeHash, expiresAt]
    )

    await resend.emails.send({
        from: 'lunev <noreply@layba.dev>',
        to: user.email,
        subject: 'Your lunev sign-in code',
        html: `
            <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                <h2 style="font-weight: 600;">Your sign-in code</h2>
                <p style="color: #555;">Enter this code to finish signing in. It expires in 10 minutes.</p>
                <p style="font-size: 2rem; font-weight: 700; letter-spacing: 8px; color: #3f3a34;">${code}</p>
                <p style="margin-top: 1.5rem; font-size: 0.8rem; color: #aaa;">If you didn't try to sign in, you can ignore this email. You may also want to change your password.</p>
            </div>
        `,
    })
}

function validatePassword(password) {
    if (password.length < 8) return 'Password must be at least 8 characters.'
    if (!/[A-Z]/.test(password)) return 'Password must contain at least one capital letter.'
    if (!/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/.test(password)) return 'Password must contain at least one symbol.'
    return null
}

router.post('/register', authLimiter, validateRegister, async (req, res) => {
    const { username, email, password } = req.body

    const passwordError = validatePassword(password)
    if (passwordError) return res.status(400).json({ error: passwordError })

    try {
        const verificationToken = crypto.randomBytes(32).toString('hex')
        const hashedPassword = await bcrypt.hash(password, 10)
        await db.query(
            'INSERT INTO users (email, password_hash, username, verified, verification_token) VALUES ($1, $2, $3, $4, $5)',
            [email, hashedPassword, username, false, hashToken(verificationToken)]
        )

        const verifyUrl = `${process.env.BACKEND_URL}/auth/verify-email?token=${verificationToken}`

        await resend.emails.send({
            from: 'noreply@layba.dev',
            to: email,
            subject: 'Verify your lunev account',
            html: `
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="font-weight: 600;">Welcome to lunev.</h2>
                    <p style="color: #555;">Click the button below to verify your email address.</p>
                    <a href="${verifyUrl}" style="display: inline-block; margin-top: 1rem; padding: 0.75rem 1.5rem; background: #4ecca3; color: #0f0f0f; text-decoration: none; border-radius: 6px; font-weight: 500;">Verify email</a>
                    <p style="margin-top: 1.5rem; font-size: 0.8rem; color: #aaa;">If you didn't create an account, you can ignore this email.</p>
                </div>
            `
        })

        checkSignupSpike()
        res.json({ message: 'Account created! Please check your email to verify your account.' })
    } catch (err) {
        if (err.code === '23505') {
            res.status(400).json({ error: 'An account with that email already exists.' })
        } else {
            res.status(500).json({ error: 'Something went wrong.' })
        }
    }
})

router.get('/verify-email', async (req, res) => {
    const { token } = req.query
    if (!token) return res.status(400).send('Invalid verification link.')

    try {
        const result = await db.query('SELECT * FROM users WHERE verification_token = $1', [hashToken(token)])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).send('Invalid or expired verification link.')

        await db.query('UPDATE users SET verified = true, verification_token = NULL WHERE id = $1', [rows[0].id])
        res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`)
    } catch (err) {
        res.status(500).send('Something went wrong.')
    }
})

router.post('/login', authLimiter, validateLogin, async (req, res) => {
    const { email, password } = req.body

    const onFailedLogin = async () => {
        await recordEvent('failed_login', req.ip)
        checkFailedLoginAnomaly(req.ip)
    }

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email])
        const rows = result.rows
        if (rows.length === 0) {
            await onFailedLogin()
            return res.status(400).json({ error: 'Invalid email or password.' })
        }

        if (!rows[0].verified) {
            const oneHour = 1000 * 60 * 60
            if (Date.now() - rows[0].created_at > oneHour) {
                await db.query('DELETE FROM users WHERE id = $1', [rows[0].id])
                return res.status(400).json({ error: 'No account found with that email.' })
            }
            return res.status(400).json({ error: 'Please verify your email before logging in.' })
        }
        const validPassword = await bcrypt.compare(password, rows[0].password_hash)
        if (!validPassword) {
            await onFailedLogin()
            return res.status(400).json({ error: 'Invalid email or password.' })
        }

        // MFA on: don't issue a token yet — email a code and ask for it.
        if (rows[0].mfa_enabled) {
            await issueOtp(rows[0])
            return res.json({ mfaRequired: true, email: rows[0].email })
        }

        const token = await startSession(req, res, rows[0])
        res.json({ token, onboarded: rows[0].onboarded })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

// Rotate the refresh cookie and hand back a fresh access token. Detects reuse.
router.post('/refresh', async (req, res) => {
    const raw = req.cookies?.refreshToken
    if (!raw) return res.status(401).json({ error: 'No active session.' })

    try {
        const r = await db.query('SELECT * FROM refresh_tokens WHERE token_hash = $1', [hashToken(raw)])
        if (!r.rows.length) {
            clearRefreshCookie(req, res)
            return res.status(401).json({ error: 'Invalid session.' })
        }
        const tok = r.rows[0]

        // Reuse of an already-rotated token => likely theft. Kill the whole family.
        if (tok.revoked) {
            await db.query('UPDATE refresh_tokens SET revoked = true WHERE family_id = $1', [tok.family_id])
            await recordEvent('refresh_reuse', req.ip)
            clearRefreshCookie(req, res)
            return res.status(401).json({ error: 'Session expired. Please sign in again.' })
        }
        if (Date.now() > Number(tok.expires_at)) {
            clearRefreshCookie(req, res)
            return res.status(401).json({ error: 'Session expired. Please sign in again.' })
        }

        const u = await db.query('SELECT id, username, onboarded FROM users WHERE id = $1', [tok.user_id])
        if (!u.rows.length) {
            clearRefreshCookie(req, res)
            return res.status(401).json({ error: 'Invalid session.' })
        }

        // Rotate: retire the used token, issue a new one in the same family.
        await db.query('UPDATE refresh_tokens SET revoked = true WHERE id = $1', [tok.id])
        const token = await startSession(req, res, u.rows[0], tok.family_id)
        res.json({ token })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

// Revoke the current refresh token and clear the cookie.
router.post('/logout', async (req, res) => {
    const raw = req.cookies?.refreshToken
    if (raw) {
        await db.query('UPDATE refresh_tokens SET revoked = true WHERE token_hash = $1', [hashToken(raw)])
    }
    clearRefreshCookie(req, res)
    res.json({ message: 'Logged out.' })
})

router.put('/change-password', verifyToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body

        const passwordError = validatePassword(newPassword)
        if (passwordError) return res.status(400).json({ error: passwordError })

        const result = await db.query('SELECT * FROM users WHERE id = $1', [req.userId])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).json({ error: 'User not found.' })

        const validPassword = await bcrypt.compare(currentPassword, rows[0].password_hash)
        if (!validPassword) return res.status(400).json({ error: 'Current password is incorrect.' })

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, req.userId])
        // Changing the password ends all other sessions.
        await db.query('UPDATE refresh_tokens SET revoked = true WHERE user_id = $1', [req.userId])
        res.json({ message: 'Password updated successfully!' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

router.delete('/delete-account', verifyToken, async (req, res) => {
    try {
        const { email } = req.body

        const result = await db.query('SELECT * FROM users WHERE id = $1', [req.userId])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).json({ error: 'User not found.' })

        if (rows[0].email !== email) return res.status(400).json({ error: 'Email does not match your account.' })

        // todos predate ON DELETE CASCADE, so remove them explicitly; the wellness
        // tables cascade automatically when the user row goes.
        await db.query('DELETE FROM todos WHERE user_id = $1', [req.userId])
        await db.query('DELETE FROM users WHERE id = $1', [req.userId])
        clearRefreshCookie(req, res)
        res.json({ message: 'Account deleted successfully.' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

router.post('/forgot-password', authLimiter, validateEmailOnly, async (req, res) => {
    const { email } = req.body

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email])
        const rows = result.rows
        // Don't reveal whether an account exists — same response either way.
        if (rows.length === 0) {
            return res.json({ message: 'If an account exists with that email, a reset link is on its way.' })
        }

        const resetToken = crypto.randomBytes(32).toString('hex')
        const expires = Date.now() + 1000 * 60 * 60

        await db.query(
            'UPDATE users SET forgot_password_token = $1, forgot_password_expires = $2 WHERE id = $3',
            [hashToken(resetToken), expires, rows[0].id]
        )

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`

        await resend.emails.send({
            from: 'noreply@layba.dev',
            to: email,
            subject: 'Reset your lunev password',
            html: `
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="font-weight: 600;">Reset your password.</h2>
                    <p style="color: #555;">Click the button below to reset your password. This link expires in 1 hour.</p>
                    <a href="${resetUrl}" style="display: inline-block; margin-top: 1rem; padding: 0.75rem 1.5rem; background: #4ecca3; color: #0f0f0f; text-decoration: none; border-radius: 6px; font-weight: 500;">Reset password</a>
                    <p style="margin-top: 1.5rem; font-size: 0.8rem; color: #aaa;">If you didn't request this, you can ignore this email.</p>
                </div>
            `
        })

        res.json({ message: 'If an account exists with that email, a reset link is on its way.' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

router.post('/reset-password', authLimiter, async (req, res) => {
    const { token, newPassword } = req.body

    const passwordError = validatePassword(newPassword)
    if (passwordError) return res.status(400).json({ error: passwordError })

    try {
        const result = await db.query('SELECT * FROM users WHERE forgot_password_token = $1', [hashToken(token)])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).json({ error: 'Invalid or expired reset link.' })

        if (Date.now() > rows[0].forgot_password_expires) {
            return res.status(400).json({ error: 'Reset link has expired. Please request a new one.' })
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        await db.query(
            'UPDATE users SET password_hash = $1, forgot_password_token = NULL, forgot_password_expires = NULL WHERE id = $2',
            [hashedPassword, rows[0].id]
        )
        // Resetting the password ends all existing sessions (matches change-password).
        await db.query('UPDATE refresh_tokens SET revoked = true WHERE user_id = $1', [rows[0].id])

        res.json({ message: 'Password reset successfully! You can now sign in.' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

// Step two of an MFA login: exchange a valid code for a token.
router.post('/verify-otp', otpLimiter, async (req, res) => {
    const { email, code } = req.body
    if (typeof email !== 'string' || !/^\d{6}$/.test(String(code || ''))) {
        return res.status(400).json({ error: 'Please enter the 6-digit code.' })
    }

    try {
        const u = await db.query('SELECT * FROM users WHERE email = $1', [email.trim()])
        if (!u.rows.length) return res.status(400).json({ error: 'Invalid or expired code.' })
        const user = u.rows[0]

        const o = await db.query('SELECT * FROM otp_codes WHERE user_id = $1 ORDER BY id DESC LIMIT 1', [user.id])
        if (!o.rows.length) return res.status(400).json({ error: 'No active code. Please request a new one.' })
        const otp = o.rows[0]

        if (Date.now() > Number(otp.expires_at)) {
            await db.query('DELETE FROM otp_codes WHERE user_id = $1', [user.id])
            return res.status(400).json({ error: 'That code has expired. Please request a new one.' })
        }
        if (otp.attempts >= 5) {
            await db.query('DELETE FROM otp_codes WHERE user_id = $1', [user.id])
            return res.status(400).json({ error: 'Too many incorrect attempts. Please request a new code.' })
        }

        const match = await bcrypt.compare(String(code), otp.code_hash)
        if (!match) {
            await db.query('UPDATE otp_codes SET attempts = attempts + 1 WHERE id = $1', [otp.id])
            await recordEvent('failed_otp', req.ip)
            return res.status(400).json({ error: 'Incorrect code.' })
        }

        await db.query('DELETE FROM otp_codes WHERE user_id = $1', [user.id])
        const token = await startSession(req, res, user)
        res.json({ token, onboarded: user.onboarded })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

// Resend a code, with a 60-second per-account cooldown (plus the otpLimiter).
router.post('/resend-otp', otpLimiter, validateEmailOnly, async (req, res) => {
    try {
        const u = await db.query('SELECT * FROM users WHERE email = $1', [req.body.email])
        // Don't reveal whether the account exists / has MFA.
        if (!u.rows.length || !u.rows[0].mfa_enabled) {
            return res.json({ message: 'If a code is needed, a new one has been sent.' })
        }
        const recent = await db.query(
            "SELECT 1 FROM otp_codes WHERE user_id = $1 AND created_at > now() - interval '60 seconds'",
            [u.rows[0].id]
        )
        if (recent.rows.length) {
            return res.status(429).json({ error: 'Please wait a moment before requesting another code.' })
        }
        await issueOtp(u.rows[0])
        res.json({ message: 'A new code is on its way.' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

// Current account info for the settings page.
router.get('/me', verifyToken, async (req, res) => {
    const r = await db.query('SELECT username, email, mfa_enabled, onboarded FROM users WHERE id = $1', [req.userId])
    if (!r.rows.length) return res.status(404).json({ error: 'Not found.' })
    res.json(r.rows[0])
})

// Toggle opt-in MFA. Enabling is simple; disabling requires re-confirming the
// account password so a stolen/lingering access token alone can't weaken MFA.
router.post('/mfa', verifyToken, async (req, res) => {
    const enabled = !!req.body.enabled

    if (!enabled) {
        const { password } = req.body
        if (typeof password !== 'string' || !password) {
            return res.status(400).json({ error: 'Please confirm your password to turn off two-step verification.' })
        }
        const result = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.userId])
        if (!result.rows.length) return res.status(400).json({ error: 'User not found.' })
        const validPassword = await bcrypt.compare(password, result.rows[0].password_hash)
        if (!validPassword) return res.status(400).json({ error: 'Password is incorrect.' })
    }

    await db.query('UPDATE users SET mfa_enabled = $1 WHERE id = $2', [enabled, req.userId])
    res.json({ enabled })
})

// Marks the signed-in user as having completed the first-login walkthrough.
router.post('/onboarded', verifyToken, async (req, res) => {
    try {
        await db.query('UPDATE users SET onboarded = true WHERE id = $1', [req.userId])
        res.json({ message: 'Onboarding complete.' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

module.exports = router