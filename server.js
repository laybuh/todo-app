const express = require('express')
const cors = require('cors')
const helmet = require('helmet')
const morgan = require('morgan')
const cookieParser = require('cookie-parser')
require('dotenv').config()

const authRoutes = require('./routes/auth')
const todoRoutes = require('./routes/todo')
const adminRoutes = require('./routes/admin')
const journalRoutes = require('./routes/journal')
const moodRoutes = require('./routes/mood')
const affirmationRoutes = require('./routes/affirmations')
const { globalLimiter } = require('./middleware/rateLimiters')
const db = require('./db')

const app = express()

// Render (and most hosts) sit behind a proxy — needed for correct client IPs
// in rate limiting and security logging.
app.set('trust proxy', 1)

// Security headers.
app.use(helmet())

// Lock CORS to known origins. Configure extra origins via ALLOWED_ORIGINS
// (comma-separated). Requests with no Origin (curl, same-origin) are allowed.
const allowedOrigins = [
    process.env.FRONTEND_URL,
    'https://lunev.vercel.app',
    'https://dospace.vercel.app',
    'http://localhost:5173',
    'http://localhost:3000',
    ...(process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',').map((s) => s.trim()) : []),
].filter(Boolean)

app.use(cors({
    origin(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true)
        return callback(new Error('Not allowed by CORS'))
    },
    credentials: true,
}))

// Request logging — method, path, status, timing only. Never logs request
// bodies, so passwords and encrypted user content stay out of logs (privacy).
app.use(morgan('tiny'))

// Cap body size to blunt large-payload abuse.
app.use(express.json({ limit: '64kb' }))
app.use(cookieParser())

// Catch-all flood protection.
app.use(globalLimiter)

app.use('/auth', authRoutes)
app.use('/todos', todoRoutes)
app.use('/admin', adminRoutes)
app.use('/journal', journalRoutes)
app.use('/moods', moodRoutes)
app.use('/affirmations', affirmationRoutes)

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

    // Reconcile schema drift: ensure every column the app uses exists.
    // Idempotent — safe to run on every boot.
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verified boolean DEFAULT false`)
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_token text`)
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS forgot_password_token text`)
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS forgot_password_expires bigint`)
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now()`)
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS onboarded boolean DEFAULT false`)
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS mfa_enabled boolean DEFAULT false`)

    await db.query(`
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            title TEXT NOT NULL,
            completed BOOLEAN DEFAULT false
        )
    `)
    // Phase 2: optional energy tag (low/medium/high) and time-capsule unlock date.
    await db.query(`ALTER TABLE todos ADD COLUMN IF NOT EXISTS energy text`)
    await db.query(`ALTER TABLE todos ADD COLUMN IF NOT EXISTS unlock_date timestamptz`)

    // Phase 3 wellness tables. All user content columns (content, note, text)
    // are AES-256 encrypted at rest. ON DELETE CASCADE so account deletion is clean.
    await db.query(`
        CREATE TABLE IF NOT EXISTS journal_entry_types (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            emoji TEXT,
            created_at timestamptz DEFAULT now()
        )
    `)
    await db.query(`
        CREATE TABLE IF NOT EXISTS journal_entries (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            type TEXT NOT NULL,
            custom_type_id INTEGER REFERENCES journal_entry_types(id) ON DELETE SET NULL,
            content TEXT NOT NULL,
            created_at timestamptz DEFAULT now()
        )
    `)
    await db.query(`
        CREATE TABLE IF NOT EXISTS moods (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            entry_date DATE NOT NULL,
            mood INTEGER NOT NULL,
            note TEXT,
            created_at timestamptz DEFAULT now(),
            UNIQUE (user_id, entry_date)
        )
    `)
    await db.query(`
        CREATE TABLE IF NOT EXISTS affirmations (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            text TEXT NOT NULL,
            archived BOOLEAN DEFAULT false,
            created_at timestamptz DEFAULT now()
        )
    `)

    // Email OTP codes for opt-in MFA. Codes are bcrypt-hashed, expire fast,
    // and cap attempts — never stored in plaintext.
    await db.query(`
        CREATE TABLE IF NOT EXISTS otp_codes (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            code_hash TEXT NOT NULL,
            expires_at BIGINT NOT NULL,
            attempts INTEGER DEFAULT 0,
            created_at timestamptz DEFAULT now()
        )
    `)

    // Rotating refresh tokens (hashed). family_id groups a session lineage so a
    // replayed/old token can be detected and the whole family revoked.
    await db.query(`
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            token_hash TEXT NOT NULL,
            family_id TEXT NOT NULL,
            revoked BOOLEAN DEFAULT false,
            expires_at BIGINT NOT NULL,
            created_at timestamptz DEFAULT now()
        )
    `)
    await db.query(`CREATE INDEX IF NOT EXISTS idx_refresh_token_hash ON refresh_tokens (token_hash)`)

    // Security events: type + coarse IP only, never user content (privacy).
    await db.query(`
        CREATE TABLE IF NOT EXISTS security_events (
            id SERIAL PRIMARY KEY,
            type TEXT NOT NULL,
            ip TEXT,
            created_at timestamptz DEFAULT now()
        )
    `)
    await db.query(`CREATE INDEX IF NOT EXISTS idx_security_events_type_time ON security_events (type, created_at)`)

    console.log('Database tables ready!')
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`)
    await setupDatabase()
})
