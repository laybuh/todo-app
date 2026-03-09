const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const db = require('../db')

router.post('/register', async (req, res) => {
    const { username, email, password } = req.body

    try {
        const hashedPassword = await bcrypt.hash(password, 10)
        await db.query('INSERT INTO users (email, password_hash, username) VALUES (?, ?, ?)',
            [email, hashedPassword, username])
        res.json({ message: 'User created successfully!' })
    } catch (err) {
        res.status(500).json({ error: 'Email already exists' })
    }
})

router.post('/login', async (req, res) => {
    const { email, password } = req.body

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email])
        if (rows.length === 0) return res.status(400).json({ error: 'User not found' })

        const validPassword = await bcrypt.compare(password, rows[0].password_hash)
        if (!validPassword) return res.status(400).json({ error: 'Wrong password' })

        const token = jwt.sign({ id: rows[0].id, username: rows[0].username }, process.env.SECRETEST_KEY)
        res.json({ token })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong' })
    }
})

router.put('/change-password', async (req, res) => {
    const token = req.headers['authorization']
    if (!token) return res.status(401).json({ error: 'No token provided' })

    try {
        const decoded = jwt.verify(token, process.env.SECRETEST_KEY)
        const { currentPassword, newPassword } = req.body

        const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [decoded.id])
        if (rows.length === 0) return res.status(400).json({ error: 'User not found' })

        const validPassword = await bcrypt.compare(currentPassword, rows[0].password_hash)
        if (!validPassword) return res.status(400).json({ error: 'Current password is incorrect' })

        const hashedPassword = await bcrypt.hash(newPassword, 10)
        await db.query('UPDATE users SET password_hash = ? WHERE id = ?', [hashedPassword, decoded.id])
        res.json({ message: 'Password updated successfully!' })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong' })
    }
})

module.exports = router