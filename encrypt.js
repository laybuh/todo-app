const crypto = require('crypto')

const ALGORITHM = 'aes-256-gcm'

// 32-byte key for AES-256. Required.
if (!process.env.ENCRYPTION_KEY) {
    throw new Error('ENCRYPTION_KEY is not set')
}
const key = Buffer.from(process.env.ENCRYPTION_KEY, 'utf8')
if (key.length !== 32) {
    throw new Error(`ENCRYPTION_KEY must be 32 bytes, got ${key.length}`)
}

// All data is AES-256-GCM authenticated encryption: "v3:<ivHex>:<authTagHex>:<cipherHex>".
// (Older v2/CBC and legacy static-IV formats were retired once the data store was
// reset — there are no longer any non-v3 records to read.)
const VERSION = 'v3'

// Encrypt a UTF-8 string with AES-256-GCM. Every call uses a fresh random 12-byte
// IV (GCM's recommended nonce size) so identical plaintexts differ, and emits an
// authentication tag verified on decrypt.
const encrypt = (text) => {
    if (text == null) return text
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv)
    let encrypted = cipher.update(String(text), 'utf8', 'hex')
    encrypted += cipher.final('hex')
    const authTag = cipher.getAuthTag().toString('hex')
    return `${VERSION}:${iv.toString('hex')}:${authTag}:${encrypted}`
}

// Decrypt a v3 value, verifying its authentication tag (tampering throws).
const decrypt = (stored) => {
    if (stored == null) return stored
    if (typeof stored !== 'string' || !stored.startsWith(`${VERSION}:`)) {
        throw new Error('Unrecognized ciphertext format (expected v3)')
    }
    const [, ivHex, authTagHex, cipherHex] = stored.split(':')
    const iv = Buffer.from(ivHex, 'hex')
    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv)
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'))
    let decrypted = decipher.update(cipherHex, 'hex', 'utf8')
    decrypted += decipher.final('utf8')
    return decrypted
}

// True if a stored value is in the current (v3, authenticated) format.
const isUpgraded = (stored) =>
    typeof stored === 'string' && stored.startsWith(`${VERSION}:`)

module.exports = { encrypt, decrypt, isUpgraded }
