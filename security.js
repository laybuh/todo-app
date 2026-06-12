// Security event recording + anomaly alerting.
//
// Privacy note: security_events stores ONLY an event type and a coarse IP — never
// emails, passwords, or any user content. Alerts to the owner are throttled so a
// sustained attack can't turn into an inbox flood.
const db = require('./db')
const { Resend } = require('resend')

const resend = new Resend(process.env.RESEND_API_KEY)

const ALERT_COOLDOWN_MS = 30 * 60 * 1000
const lastAlertAt = {} // subject -> timestamp

async function recordEvent(type, ip) {
    try {
        await db.query('INSERT INTO security_events (type, ip) VALUES ($1, $2)', [type, ip || null])
    } catch (err) {
        // Never let security logging break a user request.
        console.error('[security] failed to record event:', err.message)
    }
}

async function sendAdminAlert(subject, text) {
    const to = process.env.ADMIN_EMAIL
    if (!to) return

    const now = Date.now()
    if (lastAlertAt[subject] && now - lastAlertAt[subject] < ALERT_COOLDOWN_MS) return
    lastAlertAt[subject] = now

    try {
        await resend.emails.send({
            from: 'lunev alerts <noreply@layba.dev>',
            to,
            subject,
            text,
        })
    } catch (err) {
        console.error('[security] failed to send admin alert:', err.message)
    }
}

// Too many failed logins across the app in a short window → likely attack.
async function checkFailedLoginAnomaly(ip) {
    try {
        const { rows } = await db.query(
            `SELECT count(*)::int AS c FROM security_events
             WHERE type = 'failed_login' AND created_at > now() - interval '15 minutes'`
        )
        const count = rows[0].c
        if (count >= 20) {
            await sendAdminAlert(
                'lunev: unusual failed-login activity',
                `${count} failed logins in the last 15 minutes. Most recent source IP: ${ip || 'unknown'}.`
            )
        }
    } catch (err) {
        console.error('[security] failed-login anomaly check error:', err.message)
    }
}

// Unusual spike in new signups in the last hour → possible bot/abuse.
async function checkSignupSpike() {
    try {
        const { rows } = await db.query(
            `SELECT count(*)::int AS c FROM users WHERE created_at > now() - interval '1 hour'`
        )
        const count = rows[0].c
        if (count >= 15) {
            await sendAdminAlert(
                'lunev: unusual signup spike',
                `${count} new accounts created in the last hour.`
            )
        }
    } catch (err) {
        console.error('[security] signup-spike check error:', err.message)
    }
}

module.exports = { recordEvent, sendAdminAlert, checkFailedLoginAnomaly, checkSignupSpike }
