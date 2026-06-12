// Lightweight input validation + normalization. SQL injection is already
// handled by parameterized queries; this guards types, lengths and shapes so
// bad/oversized input never reaches the DB or crypto layer.

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const isStr = (v) => typeof v === 'string'

function validateRegister(req, res, next) {
    const { username, email, password } = req.body || {}

    if (!isStr(email) || email.length > 254 || !EMAIL_RE.test(email.trim())) {
        return res.status(400).json({ error: 'Please enter a valid email address.' })
    }
    if (!isStr(username) || username.trim().length < 1 || username.length > 100) {
        return res.status(400).json({ error: 'Please enter a name (1–100 characters).' })
    }
    if (!isStr(password) || password.length < 8 || password.length > 200) {
        return res.status(400).json({ error: 'Password must be 8–200 characters.' })
    }

    // Normalize (trim only — never change email case to avoid breaking existing accounts).
    req.body.email = email.trim()
    req.body.username = username.trim()
    next()
}

function validateLogin(req, res, next) {
    const { email, password } = req.body || {}
    if (!isStr(email) || email.length > 254 || !EMAIL_RE.test(email.trim())) {
        return res.status(400).json({ error: 'Please enter a valid email address.' })
    }
    if (!isStr(password) || password.length < 1 || password.length > 200) {
        return res.status(400).json({ error: 'Please enter your password.' })
    }
    req.body.email = email.trim()
    next()
}

function validateEmailOnly(req, res, next) {
    const { email } = req.body || {}
    if (!isStr(email) || email.length > 254 || !EMAIL_RE.test(email.trim())) {
        return res.status(400).json({ error: 'Please enter a valid email address.' })
    }
    req.body.email = email.trim()
    next()
}

module.exports = { validateRegister, validateLogin, validateEmailOnly, EMAIL_RE }
