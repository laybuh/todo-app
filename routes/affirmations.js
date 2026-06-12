const express = require('express')
const router = express.Router()
const db = require('../db')
const verifyToken = require('../middleware/verifyToken')
const { encrypt, decrypt } = require('../encrypt')

router.get('/', verifyToken, async (req, res) => {
    const r = await db.query(
        'SELECT id, text, archived, created_at FROM affirmations WHERE user_id = $1 ORDER BY id DESC',
        [req.userId]
    )
    res.json(r.rows.map((a) => ({ ...a, text: decrypt(a.text) })))
})

// One affirmation to surface as "today's intention" — stable through the day,
// rotating across the user's active affirmations.
router.get('/today', verifyToken, async (req, res) => {
    const r = await db.query(
        'SELECT id, text FROM affirmations WHERE user_id = $1 AND archived = false ORDER BY id ASC',
        [req.userId]
    )
    if (!r.rows.length) return res.json(null)
    const dayIndex = Math.floor(Date.now() / 86400000) % r.rows.length
    const a = r.rows[dayIndex]
    res.json({ id: a.id, text: decrypt(a.text) })
})

router.post('/', verifyToken, async (req, res) => {
    const { text } = req.body
    if (typeof text !== 'string' || !text.trim() || text.length > 500) {
        return res.status(400).json({ error: 'Please write an affirmation.' })
    }
    await db.query('INSERT INTO affirmations (user_id, text) VALUES ($1, $2)', [req.userId, encrypt(text.trim())])
    res.json({ message: 'Added.' })
})

router.put('/:id/archive', verifyToken, async (req, res) => {
    await db.query(
        'UPDATE affirmations SET archived = $1 WHERE id = $2 AND user_id = $3',
        [!!req.body.archived, req.params.id, req.userId]
    )
    res.json({ message: 'Updated.' })
})

router.delete('/:id', verifyToken, async (req, res) => {
    await db.query('DELETE FROM affirmations WHERE id = $1 AND user_id = $2', [req.params.id, req.userId])
    res.json({ message: 'Deleted.' })
})

module.exports = router
