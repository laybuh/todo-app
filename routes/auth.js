const express = require('express')
const router = express.Router()
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const db = require('../db')

// Register
router.post('/register', async (req, res) => {
    const { email, password } = req.body

    try {
        const hashedPassword = await bcrypt.hash(password, 10)
        await db.query('INSERT INTO users (email, password_hash) VALUES (?, ?)',
            [email, hashedPassword])
        res.json({ message: 'User created successfully.' })
    } catch (err) {
        res.status(500).json({ error: 'Email already exists in the system.' })
    }
})

// Login
router.post('/login', async (req, res) => {
    const { email, password } = req.body

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email])
        if (rows.length === 0) return res.status(400).json({ error: 'User not found' })

        const validPassword = await bcrypt.compare(password, rows[0].password_hash)
        if (!validPassword) return res.status(400).json({ error: 'Wrong password.' })

        const token = jwt.sign({ id: rows[0].id }, process.env.JWT_SECRET)
        res.json({ token })
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong.' })
    }
})

module.exports = router