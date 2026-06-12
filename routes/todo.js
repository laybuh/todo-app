const express = require('express')
const router = express.Router()
const db = require('../db')
const jwt = require('jsonwebtoken')
const { encrypt, decrypt } = require('../encrypt')

const verifyToken = (req, res, next) => {
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

const ENERGY_LEVELS = ['low', 'medium', 'high']

// Normalize an incoming energy value to a valid level or null.
const cleanEnergy = (energy) => (ENERGY_LEVELS.includes(energy) ? energy : null)

// Parse an incoming unlock date to an ISO string, or null if absent/invalid.
const cleanUnlockDate = (value) => {
  if (!value) return null
  const d = new Date(value)
  return isNaN(d.getTime()) ? null : d.toISOString()
}

router.get('/', verifyToken, async (req, res) => {
  const result = await db.query('SELECT * FROM todos WHERE user_id = $1 ORDER BY id DESC', [req.userId])
  const now = Date.now()

  const todos = result.rows.map((todo) => {
    const locked = todo.unlock_date && new Date(todo.unlock_date).getTime() > now
    return {
      id: todo.id,
      completed: todo.completed,
      energy: todo.energy,
      unlock_date: todo.unlock_date,
      locked: !!locked,
      // A time-capsule todo never reveals its content before it unlocks —
      // enforced here on the server, not just hidden in the UI.
      title: locked ? null : decrypt(todo.title),
    }
  })

  res.json(todos)
})

router.post('/', verifyToken, async (req, res) => {
  const { title, energy, unlock_date } = req.body
  if (typeof title !== 'string' || !title.trim() || title.length > 2000) {
    return res.status(400).json({ error: 'Please enter a valid task.' })
  }

  const encryptedTitle = encrypt(title.trim())
  await db.query(
    'INSERT INTO todos (user_id, title, energy, unlock_date) VALUES ($1, $2, $3, $4)',
    [req.userId, encryptedTitle, cleanEnergy(energy), cleanUnlockDate(unlock_date)]
  )
  res.json({ message: 'Todo added!' })
})

router.delete('/:id', verifyToken, async (req, res) => {
  await db.query('DELETE FROM todos WHERE id = $1 AND user_id = $2', [req.params.id, req.userId])
  res.json({ message: 'Todo deleted!' })
})

router.put('/:id', verifyToken, async (req, res) => {
  await db.query('UPDATE todos SET completed = $1 WHERE id = $2 AND user_id = $3',
    [req.body.completed, req.params.id, req.userId])
  res.json({ message: 'Todo updated!' })
})

module.exports = router
