// Create or update the database schema. Idempotent; safe to run any time.
// Run after deploying schema changes: `npm run db:setup`
const { setupDatabase } = require('../server')
const db = require('../db')

setupDatabase()
    .then(() => db.end())
    .catch((err) => {
        console.error('[setup] failed:', err.message)
        process.exit(1)
    })
