const jwt = require('jsonwebtoken')

// Shared JWT gate for user-scoped routes. Sets req.userId.
module.exports = function verifyToken(req, res, next) {
    const token = req.headers['authorization']
    if (!token) return res.status(401).json({ error: 'No token provided' })

    try {
        const decoded = jwt.verify(token, process.env.SECRETEST_KEY)
        req.userId = decoded.id
        next()
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expired', code: 'token_expired' })
        }
        res.status(401).json({ error: 'Invalid token' })
    }
}
