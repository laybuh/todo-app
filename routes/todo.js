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
    res.status(401).json({ error: 'Invalid token' })
  }
}

router.get('/', verifyToken, async (req, res) => {
  const result = await db.query('SELECT * FROM todos WHERE user_id = $1', [req.userId])
  const decrypted = result.rows.map(todo => ({
    ...todo,
    title: decrypt(todo.title)
  }))
  res.json(decrypted)
})

router.post('/', verifyToken, async (req, res) => {
  const { title } = req.body
  const encryptedTitle = encrypt(title)
  await db.query('INSERT INTO todos (user_id, title) VALUES ($1, $2)', [req.userId, encryptedTitle])
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