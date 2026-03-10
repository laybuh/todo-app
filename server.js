const rateLimit = require('express-rate-limit')
const express = require('express')
const cors = require('cors')
require('dotenv').config()


const authRoutes = require('./routes/auth')
const todoRoutes = require('./routes/todo')
const db = require('./db')

const app = express()

app.use(cors())
app.use(express.json())

const authLimiter = rateLimit({
    windowMs: 10 * 60 * 1000,
    max: 3,
    message: { error: 'Too many attempts. Please try again in 10 minutes.' }
})

app.use('/auth/login', authLimiter)
app.use('/auth/register', authLimiter)
app.use('/auth/forgot-password', authLimiter)
app.use('/auth', authRoutes)
app.use('/todos', todoRoutes)

app.get('/', (req, res) => {
    res.json({ message: 'Server is running!' })
})

async function setupDatabase() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL
        )
    `)
    await db.query(`
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            title TEXT NOT NULL,
            completed BOOLEAN DEFAULT false
        )
    `)
    console.log('Database tables ready!')
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`)
    await setupDatabase()
})