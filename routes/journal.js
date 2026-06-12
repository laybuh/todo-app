const express = require('express')
const router = express.Router()
const db = require('../db')
const verifyToken = require('../middleware/verifyToken')
const { encrypt, decrypt } = require('../encrypt')

// Built-in prompt types. Custom types live in journal_entry_types (per user).
const BUILT_IN = ['brain_dump', 'gratitude', 'letter_future', 'on_my_mind']

// ── custom entry types ────────────────────────────────────────────────
router.get('/types', verifyToken, async (req, res) => {
    const r = await db.query(
        'SELECT id, name, emoji FROM journal_entry_types WHERE user_id = $1 ORDER BY id',
        [req.userId]
    )
    res.json(r.rows)
})

router.post('/types', verifyToken, async (req, res) => {
    let { name, emoji } = req.body
    if (typeof name !== 'string' || !name.trim() || name.length > 40) {
        return res.status(400).json({ error: 'Please enter a valid type name.' })
    }
    if (typeof emoji !== 'string' || !emoji.trim() || emoji.length > 8) emoji = '📝'
    const r = await db.query(
        'INSERT INTO journal_entry_types (user_id, name, emoji) VALUES ($1, $2, $3) RETURNING id, name, emoji',
        [req.userId, name.trim(), emoji]
    )
    res.json(r.rows[0])
})

router.delete('/types/:id', verifyToken, async (req, res) => {
    await db.query('DELETE FROM journal_entry_types WHERE id = $1 AND user_id = $2', [req.params.id, req.userId])
    res.json({ message: 'Type deleted.' })
})

// ── entries (content AES-256 encrypted, same as todos) ─────────────────
router.get('/', verifyToken, async (req, res) => {
    const r = await db.query(
        `SELECT e.id, e.type, e.custom_type_id, e.content, e.created_at,
                t.name AS custom_type_name, t.emoji AS custom_type_emoji
         FROM journal_entries e
         LEFT JOIN journal_entry_types t ON e.custom_type_id = t.id
         WHERE e.user_id = $1
         ORDER BY e.created_at DESC, e.id DESC`,
        [req.userId]
    )
    res.json(r.rows.map((e) => ({ ...e, content: decrypt(e.content) })))
})

router.post('/', verifyToken, async (req, res) => {
    const { type, custom_type_id, content } = req.body
    if (typeof content !== 'string' || !content.trim() || content.length > 20000) {
        return res.status(400).json({ error: 'Please write something first.' })
    }

    let entryType = type
    let customId = null
    if (custom_type_id) {
        const owned = await db.query(
            'SELECT id FROM journal_entry_types WHERE id = $1 AND user_id = $2',
            [custom_type_id, req.userId]
        )
        if (owned.rows.length) { entryType = 'custom'; customId = custom_type_id }
    }
    if (entryType !== 'custom' && !BUILT_IN.includes(entryType)) entryType = 'brain_dump'

    await db.query(
        'INSERT INTO journal_entries (user_id, type, custom_type_id, content) VALUES ($1, $2, $3, $4)',
        [req.userId, entryType, customId, encrypt(content.trim())]
    )
    res.json({ message: 'Saved.' })
})

router.put('/:id', verifyToken, async (req, res) => {
    const { content } = req.body
    if (typeof content !== 'string' || !content.trim() || content.length > 20000) {
        return res.status(400).json({ error: 'Please write something first.' })
    }
    await db.query(
        'UPDATE journal_entries SET content = $1 WHERE id = $2 AND user_id = $3',
        [encrypt(content.trim()), req.params.id, req.userId]
    )
    res.json({ message: 'Updated.' })
})

router.delete('/:id', verifyToken, async (req, res) => {
    await db.query('DELETE FROM journal_entries WHERE id = $1 AND user_id = $2', [req.params.id, req.userId])
    res.json({ message: 'Deleted.' })
})

module.exports = router
