const express = require('express')
const router = express.Router()
const db = require('../db')
const verifyToken = require('../middleware/verifyToken')
const { encrypt, decrypt } = require('../encrypt')

// Full history, oldest first (for the chart). Notes are encrypted at rest.
router.get('/', verifyToken, async (req, res) => {
    const r = await db.query(
        'SELECT id, entry_date, mood, note FROM moods WHERE user_id = $1 ORDER BY entry_date ASC',
        [req.userId]
    )
    res.json(r.rows.map((m) => ({ ...m, note: m.note ? decrypt(m.note) : null })))
})

// Has the user checked in today? Returns the entry or null.
router.get('/today', verifyToken, async (req, res) => {
    const r = await db.query(
        'SELECT id, entry_date, mood, note FROM moods WHERE user_id = $1 AND entry_date = CURRENT_DATE',
        [req.userId]
    )
    if (!r.rows.length) return res.json(null)
    const m = r.rows[0]
    res.json({ ...m, note: m.note ? decrypt(m.note) : null })
})

// Daily check-in — one per calendar day (upsert).
router.post('/', verifyToken, async (req, res) => {
    const mood = parseInt(req.body.mood, 10)
    if (!(mood >= 1 && mood <= 5)) {
        return res.status(400).json({ error: 'Mood must be between 1 and 5.' })
    }
    const note = typeof req.body.note === 'string' && req.body.note.trim()
        ? encrypt(req.body.note.trim().slice(0, 5000))
        : null

    await db.query(
        `INSERT INTO moods (user_id, entry_date, mood, note)
         VALUES ($1, CURRENT_DATE, $2, $3)
         ON CONFLICT (user_id, entry_date)
         DO UPDATE SET mood = EXCLUDED.mood, note = EXCLUDED.note`,
        [req.userId, mood, note]
    )
    res.json({ message: 'Mood saved.' })
})

// Delete a single check-in.
router.delete('/:id', verifyToken, async (req, res) => {
    await db.query('DELETE FROM moods WHERE id = $1 AND user_id = $2', [req.params.id, req.userId])
    res.json({ message: 'Entry deleted.' })
})

// Erase the user's entire mood history.
router.delete('/', verifyToken, async (req, res) => {
    await db.query('DELETE FROM moods WHERE user_id = $1', [req.userId])
    res.json({ message: 'Mood history cleared.' })
})

module.exports = router
