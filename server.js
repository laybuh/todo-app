const express = require('express')
const cors = require('cors')
require('dotenv').config()

const authRoutes = require('./routes/auth')

const app = express()

app.use(cors())
app.use(express.json())

app.use('/auth', authRoutes)

app.get('/', (req, res) => {
  res.json({ message: 'Server is running!' })
})

app.listen(5000, () => {
  console.log('Server running on port 5000')
})