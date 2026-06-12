const crypto = require('crypto')

// Gate for owner-only admin endpoints. Uses a dedicated ADMIN_SECRET — entirely
// separate from user JWTs — compared in constant time. The admin can see
// aggregate stats but never any user content (it's all encrypted at rest).
module.exports = function adminAuth(req, res, next) {
    const secret = process.env.ADMIN_SECRET
    if (!secret) {
        return res.status(500).json({ error: 'Admin access is not configured.' })
    }

    const provided = req.headers['x-admin-secret']
    if (typeof provided !== 'string') {
        return res.status(401).json({ error: 'Unauthorized.' })
    }

    const a = Buffer.from(provided)
    const b = Buffer.from(secret)
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
        return res.status(401).json({ error: 'Unauthorized.' })
    }
    next()
}
