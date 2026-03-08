const express = require('express')
const router = express.Router()
const db = require('../db')
const jwt = require('jsonwebtoken')

const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']
  if (!token) return res.status(401).json({ error: 'No token provided' })

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)
    req.userId = decoded.id
    next()
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' })
  }
}

router.get('/', verifyToken, async (req, res) => {
  const [rows] = await db.query('SELECT * FROM todos WHERE user_id = ?', [req.userId])
  res.json(rows)
})

router.post('/', verifyToken, async (req, res) => {
  const { title } = req.body
  await db.query('INSERT INTO todos (user_id, title) VALUES (?, ?)', [req.userId, title])
  res.json({ message: 'Todo added!' })
})

router.delete('/:id', verifyToken, async (req, res) => {
  await db.query('DELETE FROM todos WHERE id = ? AND user_id = ?', [req.params.id, req.userId])
  res.json({ message: 'Todo deleted!' })
})

router.put('/:id', verifyToken, async (req, res) => {
  await db.query('UPDATE todos SET completed = ? WHERE id = ? AND user_id = ?', 
    [req.body.completed, req.params.id, req.userId])
  res.json({ message: 'Todo updated!' })
})

module.exports = router