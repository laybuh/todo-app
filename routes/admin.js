const express = require('express')
const router = express.Router()
const db = require('../db')
const adminAuth = require('../middleware/adminAuth')

// Aggregate stats only — never any user content. Everything users write is
// AES-256 encrypted at rest, so even here it stays unreadable.
router.get('/stats', adminAuth, async (req, res) => {
    try {
        const [users, verified, todos, signups, failed] = await Promise.all([
            db.query('SELECT count(*)::int AS c FROM users'),
            db.query('SELECT count(*)::int AS c FROM users WHERE verified = true'),
            db.query('SELECT count(*)::int AS c FROM todos'),
            db.query(
                `SELECT to_char(date(created_at), 'YYYY-MM-DD') AS d, count(*)::int AS c
                 FROM users
                 WHERE created_at > now() - interval '30 days'
                 GROUP BY d ORDER BY d`
            ),
            db.query(
                `SELECT count(*)::int AS c FROM security_events
                 WHERE type = 'failed_login' AND created_at > now() - interval '24 hours'`
            ),
        ])

        res.json({
            totalUsers: users.rows[0].c,
            verifiedUsers: verified.rows[0].c,
            totalEntries: todos.rows[0].c, // extend as journal/moods/affirmations ship
            failedLogins24h: failed.rows[0].c,
            signupsOverTime: signups.rows, // [{ d: 'YYYY-MM-DD', c }]
        })
    } catch (err) {
        res.status(500).json({ error: 'Could not load stats.' })
    }
})

// Public shell — contains NO secret. The owner enters the admin secret in the
// browser; it's sent as a header only when fetching /admin/stats.
router.get('/', (req, res) => {
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'"
    )
    res.type('html').send(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<meta name="robots" content="noindex"/>
<title>lunev admin</title>
<style>
  :root { --cream:#f7f2ea; --ink:#3f3a34; --sage:#7f936a; --sand:#e7ddcd; --surface:#fffdf8; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:Inter,system-ui,sans-serif; background:var(--cream); color:var(--ink); }
  .wrap { max-width:760px; margin:0 auto; padding:3rem 1.5rem; }
  h1 { font-family:Georgia,serif; font-weight:600; font-size:1.8rem; margin:0 0 .25rem; }
  p.sub { color:#8a8175; margin:0 0 2rem; font-size:.9rem; }
  .gate { display:flex; gap:.5rem; margin-bottom:2rem; }
  input { flex:1; padding:.7rem 1rem; border:1px solid var(--sand); border-radius:8px; background:var(--surface); font-size:.95rem; }
  button { padding:.7rem 1.3rem; border:none; border-radius:8px; background:var(--sage); color:#fff; font-weight:500; cursor:pointer; }
  button:hover { background:#6c7f59; }
  .grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:1rem; margin-bottom:2rem; }
  .card { background:var(--surface); border:1px solid var(--sand); border-radius:12px; padding:1.25rem; }
  .card .n { font-size:2rem; font-weight:600; font-family:Georgia,serif; }
  .card .l { font-size:.8rem; color:#8a8175; margin-top:.25rem; }
  .chart { background:var(--surface); border:1px solid var(--sand); border-radius:12px; padding:1.25rem; }
  .bar { display:flex; align-items:center; gap:.5rem; font-size:.78rem; margin:.15rem 0; }
  .bar .d { width:84px; color:#8a8175; flex-shrink:0; }
  .bar .fill { height:14px; background:var(--sage); border-radius:3px; min-width:2px; }
  .err { color:#b14b45; font-size:.85rem; }
  .muted { color:#8a8175; font-size:.85rem; }
</style></head>
<body><div class="wrap">
  <h1>lunev admin</h1>
  <p class="sub">Aggregate stats only. User content is encrypted and never readable here.</p>
  <div class="gate">
    <input id="secret" type="password" placeholder="Admin secret" autocomplete="off"/>
    <button id="go">View</button>
  </div>
  <div id="out"><p class="muted">Enter your admin secret to load stats.</p></div>
</div>
<script>
  const $ = (id) => document.getElementById(id);
  async function load() {
    const secret = $('secret').value;
    $('out').innerHTML = '<p class="muted">Loading…</p>';
    try {
      const r = await fetch('/admin/stats', { headers: { 'x-admin-secret': secret } });
      if (!r.ok) { $('out').innerHTML = '<p class="err">Unauthorized or unavailable.</p>'; return; }
      const s = await r.json();
      const max = Math.max(1, ...s.signupsOverTime.map(x => x.c));
      const bars = s.signupsOverTime.map(x =>
        '<div class="bar"><span class="d">' + x.d + '</span><span class="fill" style="width:' +
        (x.c / max * 100) + '%"></span><span>' + x.c + '</span></div>').join('') ||
        '<p class="muted">No signups in the last 30 days.</p>';
      $('out').innerHTML =
        '<div class="grid">' +
          card(s.totalUsers, 'Total users') +
          card(s.verifiedUsers, 'Verified') +
          card(s.totalEntries, 'Total entries') +
          card(s.failedLogins24h, 'Failed logins (24h)') +
        '</div>' +
        '<div class="chart"><div class="l" style="font-size:.8rem;color:#8a8175;margin-bottom:.75rem">Signups · last 30 days</div>' + bars + '</div>';
    } catch (e) { $('out').innerHTML = '<p class="err">Something went wrong.</p>'; }
  }
  function card(n, l) { return '<div class="card"><div class="n">' + n + '</div><div class="l">' + l + '</div></div>'; }
  $('go').addEventListener('click', load);
  $('secret').addEventListener('keydown', (e) => { if (e.key === 'Enter') load(); });
</script>
</body></html>`)
})

module.exports = router
