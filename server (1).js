const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '20kb' }));
app.get('/', (_, res) => res.sendFile(path.join(__dirname, 'index.html')));

const dbUrl = process.env.DATABASE_URL;
const pool = new Pool({
  connectionString: dbUrl,
  ssl: dbUrl && !/localhost|127\.0\.0\.1/.test(dbUrl) ? { rejectUnauthorized: false } : false,
});

pool.query(`
  CREATE TABLE IF NOT EXISTS responses (
    id SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    q1 TEXT, q2 TEXT, q3 TEXT[], q4 TEXT[], q5 TEXT,
    q6 TEXT[], q6_autre TEXT, q7 TEXT, q8 TEXT, contact TEXT
  )`).catch(e => console.error('Init DB:', e.message));

// ---------- Validation ----------
const OPT = {
  q1: ['masculin', 'feminin', 'les-deux'],
  q2: ['frais', 'boise', 'sucre', 'oriental-oud', 'intense', 'naturel'],
  q3: ['quotidien', 'etudes-travail', 'occasions', 'polyvalent'],
  q4: ['odeur', 'tenue', 'prix', 'flacon', 'originalite'],
  q5: ['20', '25', '30', '30+'],
  q6: ['bleu-de-chanel', 'dior-sauvage', 'azzaro', '1-million', 'oud-oriental', 'floraux', 'sucres-gourmands', 'autre'],
  q7: ['oui', 'non'],
};
const one = (v, k) => (OPT[k].includes(v) ? v : null);
const many = (v, k, max) => {
  if (!Array.isArray(v)) return null;
  const u = [...new Set(v)];
  return u.length >= 1 && u.length <= max && u.every(x => OPT[k].includes(x)) ? u : null;
};
const txt = (v, max) => (typeof v === 'string' ? v.trim().slice(0, max) : '');

// Anti-spam simple : 10 envois / heure / IP
const hits = new Map();
function limited(ip) {
  const now = Date.now();
  const arr = (hits.get(ip) || []).filter(t => now - t < 3600e3);
  arr.push(now);
  hits.set(ip, arr);
  return arr.length > 10;
}

app.post('/api/responses', async (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: 'Trop de tentatives, réessaie plus tard.' });
  const b = req.body || {};
  const r = {
    q1: one(b.q1, 'q1'), q2: one(b.q2, 'q2'), q3: many(b.q3, 'q3', 4), q4: many(b.q4, 'q4', 2),
    q5: one(b.q5, 'q5'), q6: many(b.q6, 'q6', 3), q7: one(b.q7, 'q7'),
    q6_autre: txt(b.q6_autre, 100), q8: txt(b.q8, 300), contact: txt(b.contact, 100),
  };
  const required = ['q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q7'];
  if (required.some(k => !r[k])) return res.status(400).json({ error: 'Réponses incomplètes.' });
  try {
    await pool.query(
      `INSERT INTO responses (q1,q2,q3,q4,q5,q6,q6_autre,q7,q8,contact) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [r.q1, r.q2, r.q3, r.q4, r.q5, r.q6, r.q6_autre, r.q7, r.q8, r.contact]
    );
    res.status(201).json({ ok: true });
  } catch (e) {
    console.error(e.message);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// ---------- Espace admin (protégé par mot de passe) ----------
function auth(req, res, next) {
  const pwd = process.env.ADMIN_PASSWORD;
  if (!pwd) return res.status(503).send('Définis ADMIN_PASSWORD pour activer /admin.');
  const given = Buffer.from((req.headers.authorization || '').replace(/^Basic /, ''), 'base64').toString().split(':').slice(1).join(':');
  const a = crypto.createHash('sha256').update(given).digest();
  const b = crypto.createHash('sha256').update(pwd).digest();
  if (crypto.timingSafeEqual(a, b)) return next();
  res.set('WWW-Authenticate', 'Basic realm="admin"').status(401).send('Accès refusé');
}
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

app.get('/admin', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM responses ORDER BY id DESC LIMIT 500');
  const tr = rows.map(r => `<tr><td>${r.id}</td><td>${esc(r.created_at.toISOString().slice(0, 16).replace('T', ' '))}</td><td>${esc(r.q1)}</td><td>${esc(r.q2)}</td><td>${esc(r.q3.join(', '))}</td><td>${esc(r.q4.join(', '))}</td><td>${esc(r.q5)}</td><td>${esc(r.q6.join(', '))}${r.q6_autre ? ' (' + esc(r.q6_autre) + ')' : ''}</td><td>${esc(r.q7)}</td><td>${esc(r.contact)}</td></tr>`).join('');
  res.send(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Réponses</title>
<style>body{font:14px system-ui;margin:20px}table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px;text-align:left;vertical-align:top}th{background:#f3e8ee}.w{overflow-x:auto}</style>
<h1>${rows.length} réponse(s)</h1><p><a href="/admin/export.csv">Télécharger en CSV</a></p>
<div class="w"><table><tr><th>#</th><th>Date</th><th>Type</th><th>Ambiance</th><th>Situations</th><th>Priorités</th><th>Prix 50ml</th><th>Références</th><th>Intéressé</th><th>Contact</th></tr>${tr}</table></div>`);
});

app.get('/admin/export.csv', auth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM responses ORDER BY id');
  const cell = v => {
    let s = Array.isArray(v) ? v.join(' | ') : v instanceof Date ? v.toISOString() : String(v ?? '');
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // protège contre les formules Excel
    return '"' + s.replace(/"/g, '""') + '"';
  };
  const cols = ['id', 'created_at', 'q1', 'q2', 'q3', 'q4', 'q5', 'q6', 'q6_autre', 'q7', 'q8', 'contact'];
  const csv = '\uFEFF' + [cols.join(','), ...rows.map(r => cols.map(c => cell(r[c])).join(','))].join('\n');
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="reponses-parfum.csv"' }).send(csv);
});

app.get('/healthz', (_, res) => res.send('ok'));
app.listen(process.env.PORT || 3000, () => console.log('Serveur prêt'));
