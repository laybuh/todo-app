const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const { Resend } = require('resend')
const db = require('../db')

const resend = new Resend(process.env.RESEND_API_KEY)

function validatePassword(password) {
    if (password.length < 8) return 'Password must be at least 8 characters.'
    if (!/[A-Z]/.test(password)) return 'Password must contain at least one capital letter.'
    if (!/[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?]/.test(password)) return 'Password must contain at least one symbol.'
    return null
}

router.post('/register', async (req, res) => {
    const { username, email, password } = req.body

    const passwordError = validatePassword(password)
    if (passwordError) return res.status(400).json({ error: passwordError })

    try {
        const verificationToken = crypto.randomBytes(32).toString('hex')
        const hashedPassword = await bcrypt.hash(password, 10)
        await db.query(
            'INSERT INTO users (email, password_hash, username, verified, verification_token) VALUES ($1, $2, $3, $4, $5)',
            [email, hashedPassword, username, false, verificationToken]
        )

        const verifyUrl = `${process.env.BACKEND_URL}/auth/verify-email?token=${verificationToken}`

        await resend.emails.send({
            from: 'noreply@layba.dev',
            to: email,
            subject: 'Verify your dospace account',
            html: `
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="font-weight: 600;">Welcome to dospace.</h2>
                    <p style="color: #555;">Click the button below to verify your email address.</p>
                    <a href="${verifyUrl}" style="display: inline-block; margin-top: 1rem; padding: 0.75rem 1.5rem; background: #4ecca3; color: #0f0f0f; text-decoration: none; border-radius: 6px; font-weight: 500;">Verify email</a>
                    <p style="margin-top: 1.5rem; font-size: 0.8rem; color: #aaa;">If you didn't create an account, you can ignore this email.</p>
                </div>
            `
        })

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
        const result = await db.query('SELECT * FROM users WHERE verification_token = $1', [token])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).send('Invalid or expired verification link.')

        await db.query('UPDATE users SET verified = true, verification_token = NULL WHERE id = $1', [rows[0].id])
        res.redirect(`${process.env.FRONTEND_URL}/login?verified=true`)
    } catch (err) {
        res.status(500).send('Something went wrong.')
    }
})

router.post('/login', async (req, res) => {
    const { email, password } = req.body

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).json({ error: 'No account found with that email.' })

        if (!rows[0].verified) {
            const oneHour = 1000 * 60 * 60
            if (Date.now() - rows[0].created_at > oneHour) {
                await db.query('DELETE FROM users WHERE id = $1', [rows[0].id])
                return res.status(400).json({ error: 'No account found with that email.' })
            }
            return res.status(400).json({ error: 'Please verify your email before logging in.' })
        }
        const validPassword = await bcrypt.compare(password, rows[0].password_hash)
        if (!validPassword) return res.status(400).json({ error: 'Incorrect password.' })

        const token = jwt.sign({ id: rows[0].id, username: rows[0].username }, process.env.SECRETEST_KEY)
        res.json({ token })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

router.put('/change-password', async (req, res) => {
    const token = req.headers['authorization']
    if (!token) return res.status(401).json({ error: 'No token provided' })

    try {
        const decoded = jwt.verify(token, process.env.SECRETEST_KEY)
        const { currentPassword, newPassword } = req.body

        const passwordError = validatePassword(newPassword)
        if (passwordError) return res.status(400).json({ error: passwordError })

        const result = await db.query('SELECT * FROM users WHERE id = $1', [decoded.id])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).json({ error: 'User not found.' })

        const validPassword = await bcrypt.compare(currentPassword, rows[0].password_hash)
        if (!validPassword) return res.status(400).json({ error: 'Current password is incorrect.' })

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedPassword, decoded.id])
        res.json({ message: 'Password updated successfully!' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

router.delete('/delete-account', async (req, res) => {
    const token = req.headers['authorization']
    if (!token) return res.status(401).json({ error: 'No token provided' })

    try {
        const decoded = jwt.verify(token, process.env.SECRETEST_KEY)
        const { email } = req.body

        const result = await db.query('SELECT * FROM users WHERE id = $1', [decoded.id])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).json({ error: 'User not found.' })

        if (rows[0].email !== email) return res.status(400).json({ error: 'Email does not match your account.' })

        await db.query('DELETE FROM users WHERE id = $1', [decoded.id])
        res.json({ message: 'Account deleted successfully.' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

router.post('/forgot-password', async (req, res) => {
    const { email } = req.body

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email])
        const rows = result.rows
        if (rows.length === 0) return res.status(400).json({ error: 'No account found with that email.' })

        const resetToken = crypto.randomBytes(32).toString('hex')
        const expires = Date.now() + 1000 * 60 * 60

        await db.query(
            'UPDATE users SET forgot_password_token = $1, forgot_password_expires = $2 WHERE id = $3',
            [resetToken, expires, rows[0].id]
        )

        const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${resetToken}`

        await resend.emails.send({
            from: 'noreply@layba.dev',
            to: email,
            subject: 'Reset your dospace password',
            html: `
                <div style="font-family: sans-serif; max-width: 480px; margin: 0 auto;">
                    <h2 style="font-weight: 600;">Reset your password.</h2>
                    <p style="color: #555;">Click the button below to reset your password. This link expires in 1 hour.</p>
                    <a href="${resetUrl}" style="display: inline-block; margin-top: 1rem; padding: 0.75rem 1.5rem; background: #4ecca3; color: #0f0f0f; text-decoration: none; border-radius: 6px; font-weight: 500;">Reset password</a>
                    <p style="margin-top: 1.5rem; font-size: 0.8rem; color: #aaa;">If you didn't request this, you can ignore this email.</p>
                </div>
            `
        })

        res.json({ message: 'Password reset link sent! Please check your email.' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

router.post('/reset-password', async (req, res) => {
    const { token, newPassword } = req.body

    const passwordError = validatePassword(newPassword)
    if (passwordError) return res.status(400).json({ error: passwordError })

    try {
        const result = await db.query('SELECT * FROM users WHERE forgot_password_token = $1', [token])
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

        res.json({ message: 'Password reset successfully! You can now sign in.' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

module.exports = router