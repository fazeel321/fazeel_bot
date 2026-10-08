// StreamFinder server with login - no npm packages needed (Node 18+)
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------- .env ----------
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(line => {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
    if (m) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch (e) {}

const CLIENT_ID = process.env.TWITCH_CLIENT_ID;
const CLIENT_SECRET = process.env.TWITCH_CLIENT_SECRET;
const ADMIN_ID = (process.env.ADMIN_ID || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const PORT = process.env.PORT || 3000;
const DEFAULT_MAX_SUB = 10; // how many IDs an allowed member may create, until the admin changes it

// ---------- users (users.json) ----------
const USERS_FILE = path.join(__dirname, 'users.json');
let users = {};
try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { users = {}; }
const saveUsers = () => fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function checkPw(u, pw) {
  const h = crypto.scryptSync(pw, u.salt, 64);
  const b = Buffer.from(u.hash, 'hex');
  return b.length === h.length && crypto.timingSafeEqual(b, h);
}

// The admin account comes from .env (ADMIN_ID / ADMIN_PASSWORD).
// Changing the password in .env and restarting the server resets the admin password.
// There is only ever ONE admin. If an admin already exists, a different ADMIN_ID in .env is ignored.
const existingAdmin = Object.keys(users).find(k => users[k].role === 'admin');
if (ADMIN_ID && ADMIN_PASSWORD) {
  if (existingAdmin && existingAdmin !== ADMIN_ID) {
    console.log('Ignoring ADMIN_ID "' + ADMIN_ID + '" in .env: the admin "' + existingAdmin + '" already exists. Only one admin is allowed.');
  } else {
    const cur = users[ADMIN_ID];
    if (!cur || cur.role !== 'admin' || cur.disabled || !checkPw(cur, ADMIN_PASSWORD)) {
      users[ADMIN_ID] = { ...hashPw(ADMIN_PASSWORD), role: 'admin', disabled: false, created: (cur && cur.created) || Date.now() };
      saveUsers();
      console.log('Admin account "' + ADMIN_ID + '" is ready.');
    }
  }
}
const hasAdmin = () => Object.values(users).some(u => u.role === 'admin');
if (!hasAdmin()) {
  console.log('\n*** No admin account yet. Open http://localhost:' + (process.env.PORT || 3000) + ' in your browser and create it there (first-time setup).\n');
}

// ---------- sessions ----------
const SESSION_MS = 12 * 60 * 60 * 1000;
const sessions = new Map(); // token -> { id, exp }

function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function currentUser(req) {
  const token = parseCookies(req).sid;
  const s = token && sessions.get(token);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(token); return null; }
  const u = users[s.id];
  if (!u || u.disabled) { sessions.delete(token); return null; }
  return { id: s.id, role: u.role, canCreate: u.role === 'admin' || !!u.canCreate };
}
function dropSessionsOf(id) {
  for (const [t, s] of sessions) if (s.id === id) sessions.delete(t);
}

// Login throttle: 5 wrong tries => locked for 5 minutes
const attempts = new Map(); // key -> { n, until }

// ---------- saved streamers (saved.json): zero duplicates ----------
const SAVED_FILE = path.join(__dirname, 'saved.json');
let saved = {};
try { saved = JSON.parse(fs.readFileSync(SAVED_FILE, 'utf8')); } catch (e) { saved = {}; }
const seen = new Set(Object.keys(saved));
function persist() {
  try { fs.writeFileSync(SAVED_FILE, JSON.stringify(saved, null, 2)); } catch (e) { console.log('Could not write saved.json:', e.message); }
}

// ---------- Twitch ----------
let token = null;
let tokenExpiry = 0;

async function getToken() {
  if (token && Date.now() < tokenExpiry) return token;
  const r = await fetch('https://id.twitch.tv/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: CLIENT_ID, client_secret: CLIENT_SECRET, grant_type: 'client_credentials' })
  });
  const j = await r.json();
  if (!r.ok) throw new Error('Twitch key rejected: ' + (j.message || r.status));
  token = j.access_token;
  tokenExpiry = Date.now() + (j.expires_in - 300) * 1000;
  return token;
}

async function helix(p) {
  const t = await getToken();
  const r = await fetch('https://api.twitch.tv/helix/' + p, {
    headers: { 'Client-Id': CLIENT_ID, 'Authorization': 'Bearer ' + t }
  });
  if (!r.ok) throw new Error('Twitch API error ' + r.status);
  return r.json();
}

let searching = Promise.resolve(); // one search at a time, so two members never get the same streamer

async function search(q, who) {
  const minV = +q.minv || 0;
  const maxV = +q.maxv || Infinity;
  const maxA = +q.maxa || Infinity;
  const target = +q.target || 20;
  const cats = (q.cats || '').split(',').map(s => s.trim()).filter(Boolean);
  // Language codes (ISO 639-1, or "other"). Twitch itself filters by these.
  const langs = (q.langs || '').split(',').map(s => s.trim().toLowerCase()).filter(l => /^[a-z]{2,5}$/.test(l)).slice(0, 20);
  const langParam = langs.map(l => '&language=' + encodeURIComponent(l)).join('');

  let gameIds;
  if (cats.length) {
    gameIds = (await helix('games?' + cats.map(c => 'name=' + encodeURIComponent(c)).join('&'))).data.map(g => g.id);
  } else {
    gameIds = (await helix('games/top?first=20')).data.map(g => g.id);
  }

  const results = [];
  for (const gid of gameIds) {
    if (results.length >= target) break;
    let cursor = '';
    for (let page = 0; page < 40 && results.length < target; page++) {
      const resp = await helix('streams?first=100&game_id=' + gid + langParam + (cursor ? '&after=' + cursor : ''));
      const streams = resp.data;
      if (!streams.length) break;
      cursor = resp.pagination && resp.pagination.cursor;

      const cand = streams.filter(s => s.viewer_count >= minV && s.viewer_count <= maxV && !seen.has(s.user_id));
      if (cand.length) {
        const users_ = (await helix('users?' + cand.map(s => 'id=' + s.user_id).join('&'))).data;
        for (const s of cand) {
          if (results.length >= target) break;
          const u = users_.find(x => x.id === s.user_id);
          if (!u) continue;
          const age = Math.floor((Date.now() - new Date(u.created_at)) / 864e5);
          if (age > maxA) continue;
          seen.add(s.user_id);
          const rec = { name: s.user_name, login: s.user_login, game: s.game_name, lang: s.language || '', viewers: s.viewer_count, ageDays: age, by: who };
          saved[s.user_id] = rec;
          results.push(rec);
        }
        persist();
      }
      if (streams[streams.length - 1].viewer_count < minV) break;
      if (!cursor) break;
    }
  }
  return results;
}

// ---------- helpers ----------
const ID_RE = /^[a-z0-9_.-]{3,32}$/;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 10000) { reject(new Error('Body too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(new Error('Bad JSON')); } });
    req.on('error', reject);
  });
}

function sendPage(res, file) {
  fs.readFile(path.join(__dirname, file), (err, data) => {
    if (err) { res.writeHead(404); return res.end(file + ' not found'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(data);
  });
}

// ---------- server ----------
http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const json = (code, obj, headers) => {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(headers || {}) });
    res.end(JSON.stringify(obj));
  };
  const redirect = to => { res.writeHead(302, { Location: to }); res.end(); };

  try {
    const me = currentUser(req);

    // ----- pages -----
    if (req.method === 'GET' && p === '/login') return me ? redirect('/') : sendPage(res, 'login.html');
    if (req.method === 'GET' && p === '/admin') {
      if (!me) return redirect('/login');
      return me.canCreate ? sendPage(res, 'admin.html') : redirect('/');
    }
    if (req.method === 'GET' && p === '/') return me ? sendPage(res, 'index.html') : redirect('/login');

    if (!p.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }

    // POST bodies must be JSON (blocks cross-site form posts)
    if (req.method === 'POST' && !(req.headers['content-type'] || '').includes('application/json')) {
      return json(415, { error: 'JSON only' });
    }

    // ----- login / logout (no session needed) -----
    if (p === '/api/login' && req.method === 'POST') {
      const b = await readBody(req);
      const id = String(b.id || '').trim().toLowerCase();
      const pw = String(b.password || '');
      const key = req.socket.remoteAddress + '|' + id;
      const a = attempts.get(key) || { n: 0, until: 0 };
      if (a.until > Date.now()) return json(429, { error: 'Too many wrong tries. Wait 5 minutes.' });

      const u = users[id];
      const ok = u && !u.disabled && checkPw(u, pw);
      if (!ok) {
        a.n += 1;
        if (a.n >= 5) { a.until = Date.now() + 5 * 60 * 1000; a.n = 0; }
        attempts.set(key, a);
        // same message for wrong ID, wrong password and disabled account
        return json(401, { error: 'Wrong ID or password.' });
      }
      attempts.delete(key);
      const sid = crypto.randomBytes(32).toString('hex');
      sessions.set(sid, { id, exp: Date.now() + SESSION_MS });
      return json(200, { ok: true, role: u.role }, {
        'Set-Cookie': 'sid=' + sid + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + (SESSION_MS / 1000)
      });
    }
    if (p === '/api/logout' && req.method === 'POST') {
      const t = parseCookies(req).sid;
      if (t) sessions.delete(t);
      return json(200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
    }

    // ----- first-time setup: works only while no admin exists -----
    // The admin can only be created from the computer the server runs on, never over the network
    const ra = req.socket.remoteAddress || '';
    const fromThisComputer = ra === '127.0.0.1' || ra === '::1' || ra === '::ffff:127.0.0.1';
    if (p === '/api/setup-status') return json(200, { needsSetup: !hasAdmin() && fromThisComputer });
    if (p === '/api/setup' && req.method === 'POST') {
      if (hasAdmin()) return json(403, { error: 'Setup is already done.' });
      if (!fromThisComputer) return json(403, { error: 'The admin can only be created on the computer where the server runs.' });
      const b = await readBody(req);
      const id = String(b.id || '').trim().toLowerCase();
      const pw = String(b.password || '');
      if (!ID_RE.test(id)) return json(400, { error: 'ID must be 3-32 characters: letters, numbers, . _ -' });
      if (pw.length < 6) return json(400, { error: 'Password must be at least 6 characters.' });
      users[id] = { ...hashPw(pw), role: 'admin', disabled: false, created: Date.now() };
      saveUsers();
      console.log('Admin account "' + id + '" created from the setup page.');
      const sid = crypto.randomBytes(32).toString('hex');
      sessions.set(sid, { id, exp: Date.now() + SESSION_MS });
      return json(200, { ok: true }, {
        'Set-Cookie': 'sid=' + sid + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + (SESSION_MS / 1000)
      });
    }

    // ----- everything below needs a login -----
    if (!me) return json(401, { error: 'Please log in.' });
    const isAdmin = me.role === 'admin';

    if (p === '/api/me') return json(200, { id: me.id, role: me.role, canCreate: me.canCreate });

    if (p === '/api/status') {
      return json(200, { keyConfigured: !!(CLIENT_ID && CLIENT_SECRET), keyPreview: CLIENT_ID ? CLIENT_ID.slice(0, 6) + '...' : null, savedCount: seen.size });
    }
    if (p === '/api/saved') return json(200, { results: Object.values(saved) });

    if (p === '/api/search') {
      if (!CLIENT_ID || !CLIENT_SECRET) return json(400, { error: 'Missing keys. Fill in the .env file and restart the server.' });
      const run = searching.then(() => search(Object.fromEntries(url.searchParams), me.id));
      searching = run.catch(() => {});
      return json(200, { results: await run });
    }

    // ----- admin only -----
    if (p === '/api/reset') {
      if (!isAdmin) return json(403, { error: 'Admin only.' });
      if (req.method !== 'POST') return json(405, { error: 'POST only' });
      seen.clear(); saved = {}; persist();
      return json(200, { ok: true });
    }

    // ----- ID management: admin (all IDs) or a member the admin allowed to create IDs (own IDs only) -----
    if (p === '/api/users' || p.startsWith('/api/users/')) {
      if (!me.canCreate) return json(403, { error: 'You are not allowed to manage IDs.' });

      const subsOf = id => Object.keys(users).filter(k => users[k].createdBy === id);
      // admin may manage everyone except itself for risky actions; a member only the IDs it created
      const canManage = id => !!users[id] && (isAdmin ? true : users[id].createdBy === me.id);

      if (p === '/api/users' && req.method === 'GET') {
        const counts = {};
        Object.values(saved).forEach(s => { if (s.by) counts[s.by] = (counts[s.by] || 0) + 1; });
        const list = Object.entries(users)
          .filter(([id]) => isAdmin || users[id].createdBy === me.id)
          .map(([id, u]) => ({
            id, role: u.role, disabled: !!u.disabled, created: u.created,
            createdBy: u.createdBy || null,
            canCreate: u.role === 'admin' || !!u.canCreate,
            maxSub: u.maxSub == null ? DEFAULT_MAX_SUB : u.maxSub,
            subCount: subsOf(id).length,
            found: counts[id] || 0
          }));
        const mine = users[me.id];
        return json(200, {
          users: list,
          limit: isAdmin ? null : (mine.maxSub == null ? DEFAULT_MAX_SUB : mine.maxSub),
          used: subsOf(me.id).length
        });
      }

      if (p === '/api/users' && req.method === 'POST') {
        const b = await readBody(req);
        const id = String(b.id || '').trim().toLowerCase();
        const pw = String(b.password || '');
        if (!ID_RE.test(id)) return json(400, { error: 'ID must be 3-32 characters: letters, numbers, . _ -' });
        if (pw.length < 6) return json(400, { error: 'Password must be at least 6 characters.' });
        if (users[id]) return json(409, { error: 'This ID already exists.' });
        if (!isAdmin) {
          const limit = users[me.id].maxSub == null ? DEFAULT_MAX_SUB : users[me.id].maxSub;
          if (subsOf(me.id).length >= limit) return json(403, { error: 'You reached your limit of ' + limit + ' IDs. Ask the admin to raise it.' });
        }
        users[id] = { ...hashPw(pw), role: 'member', disabled: false, created: Date.now(), createdBy: me.id, canCreate: false, maxSub: DEFAULT_MAX_SUB };
        saveUsers();
        return json(200, { ok: true });
      }

      if (p === '/api/users/update' && req.method === 'POST') {
        const b = await readBody(req);
        const id = String(b.id || '').toLowerCase();
        if (!users[id]) return json(404, { error: 'No such user.' });
        if (!canManage(id) || (users[id].role === 'admin' && id !== me.id)) return json(403, { error: 'You can only manage the IDs you created.' });
        const u = users[id];
        if (typeof b.password === 'string') {
          if (b.password.length < 6) return json(400, { error: 'Password must be at least 6 characters.' });
          if (u.role === 'admin') return json(400, { error: 'Change the admin password in the .env file.' });
          Object.assign(u, hashPw(b.password));
          dropSessionsOf(id);
        }
        if (typeof b.disabled === 'boolean') {
          if (id === me.id) return json(400, { error: 'You cannot disable yourself.' });
          u.disabled = b.disabled;
          if (b.disabled) dropSessionsOf(id);
        }
        // Only the admin decides who may create IDs and how many
        if (typeof b.canCreate === 'boolean' || b.maxSub !== undefined) {
          if (!isAdmin) return json(403, { error: 'Only the admin can change this.' });
          if (u.role === 'admin') return json(400, { error: 'The admin can always create IDs.' });
          if (typeof b.canCreate === 'boolean') u.canCreate = b.canCreate;
          if (b.maxSub !== undefined) {
            const n = Math.floor(Number(b.maxSub));
            if (!(n >= 0 && n <= 1000)) return json(400, { error: 'Limit must be between 0 and 1000.' });
            u.maxSub = n;
          }
        }
        saveUsers();
        return json(200, { ok: true });
      }

      if (p === '/api/users/delete' && req.method === 'POST') {
        const b = await readBody(req);
        const id = String(b.id || '').toLowerCase();
        if (!users[id]) return json(404, { error: 'No such user.' });
        if (id === me.id) return json(400, { error: 'You cannot delete yourself.' });
        if (users[id].role === 'admin') return json(400, { error: 'The admin account cannot be deleted.' });
        if (!canManage(id)) return json(403, { error: 'You can only delete the IDs you created.' });
        // IDs created by the deleted user are passed up to its own creator, so nothing is left orphaned
        const parent = users[id].createdBy || Object.keys(users).find(k => users[k].role === 'admin');
        subsOf(id).forEach(k => { users[k].createdBy = parent; });
        delete users[id];
        dropSessionsOf(id);
        saveUsers();
        return json(200, { ok: true });
      }
    }

    return json(404, { error: 'Not found' });
  } catch (e) {
    return json(500, { error: e.message });
  }
}).listen(PORT, () => console.log('StreamFinder running at http://localhost:' + PORT));
