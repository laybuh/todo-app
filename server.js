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
const allowedOrigins = require('./allowedOrigins')
const db = require('./db')

const app = express()

// Render (and most hosts) sit behind a proxy — needed for correct client IPs
// in rate limiting and security logging.
app.set('trust proxy', 1)

// Security headers.
app.use(helmet())

// Lock CORS to known origins (see allowedOrigins.js). Requests with no Origin
// (curl, same-origin) are allowed.
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
    await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS verification_expires timestamptz`)

    // Heal a schema drift that bit us in production: on older databases
    // users.created_at exists as a bigint (epoch ms) from the original todo app,
    // so `created_at > now() - interval` threw `operator does not exist:
    // bigint > timestamp`. Convert it to a real timestamptz once. Idempotent —
    // the block only runs while the column is still bigint.
    await db.query(`
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM information_schema.columns
                WHERE table_name = 'users' AND column_name = 'created_at' AND data_type = 'bigint'
            ) THEN
                ALTER TABLE users ALTER COLUMN created_at DROP DEFAULT;
                ALTER TABLE users ALTER COLUMN created_at TYPE timestamptz
                    USING to_timestamp(created_at::double precision / 1000.0);
                ALTER TABLE users ALTER COLUMN created_at SET DEFAULT now();
            END IF;
        END $$;
    `)

    await db.query(`
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            completed BOOLEAN DEFAULT false
        )
    `)
    // Phase 2: optional energy tag (low/medium/high) and time-capsule unlock date.
    await db.query(`ALTER TABLE todos ADD COLUMN IF NOT EXISTS energy text`)
    await db.query(`ALTER TABLE todos ADD COLUMN IF NOT EXISTS unlock_date timestamptz`)

    // Older databases created the todos.user_id foreign key WITHOUT ON DELETE
    // CASCADE (every sibling table has it). Without it, deleting a user that owns
    // any todo fails with a FK violation, which breaks both account deletion and
    // the abandoned-signup sweep. Re-create the constraint with CASCADE once.
    // Idempotent — only runs while the cascade rule is still missing.
    await db.query(`
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM information_schema.referential_constraints rc
                JOIN information_schema.table_constraints tc
                    ON rc.constraint_name = tc.constraint_name
                WHERE tc.table_name = 'todos' AND rc.delete_rule = 'CASCADE'
            ) THEN
                ALTER TABLE todos DROP CONSTRAINT IF EXISTS todos_user_id_fkey;
                ALTER TABLE todos ADD CONSTRAINT todos_user_id_fkey
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
            END IF;
        END $$;
    `)

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

    // Defense in depth: if a column type ever drifts from what our SQL assumes,
    // say so loudly at boot instead of failing on some random request later.
    const drift = await db.query(
        `SELECT data_type FROM information_schema.columns
         WHERE table_name = 'users' AND column_name = 'created_at'`
    )
    if (drift.rows[0] && drift.rows[0].data_type !== 'timestamp with time zone') {
        console.warn(`[schema] WARNING: users.created_at is '${drift.rows[0].data_type}', expected timestamptz.`)
    }
}

// Sweep away accounts that signed up but never verified within 48 hours. Runs at
// boot and periodically — quietly, so a real user is never deleted mid-login.
//
// The `verification_expires IS NOT NULL` guard is critical: it is only set by the
// new registration flow, so it cleanly distinguishes a genuine abandoned signup
// from a legacy todo-app account that was backfilled to verified=false when the
// `verified` column was first added. Without it, this sweep would delete real
// original users.
async function cleanupAbandonedSignups() {
    try {
        const { rowCount } = await db.query(
            `DELETE FROM users
             WHERE verified = false
               AND verification_expires IS NOT NULL
               AND created_at < now() - interval '48 hours'`
        )
        if (rowCount) console.log(`[cleanup] removed ${rowCount} abandoned unverified account(s)`)
    } catch (err) {
        console.error('[cleanup] abandoned-signup sweep error:', err.message)
    }
}

const PORT = process.env.PORT || 5000;
app.listen(PORT, async () => {
    console.log(`Server running on port ${PORT}`)
    await setupDatabase()
    await cleanupAbandonedSignups()
    setInterval(cleanupAbandonedSignups, 6 * 60 * 60 * 1000)
})
