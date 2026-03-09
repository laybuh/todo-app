const express = require('express')
const cors = require('cors')
require('dotenv').config()

const authRoutes = require('./routes/auth')
const todoRoutes = require('./routes/todo')

const app = express()

app.use(cors())
app.use(express.json())

app.use('/auth', authRoutes)
app.use('/todos', todoRoutes)

app.get('/', (req, res) => {
    res.json({ message: 'Server is running!' })
})

app.listen(5000, () => {
    console.log('Server running on port 5000')
})