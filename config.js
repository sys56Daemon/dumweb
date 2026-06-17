/**
 * ╔══════════════════════════════════════════════════╗
 * ║        airIsLeaking — CONFIGURATION              ║
 * ║  Edit this file to change server settings.       ║
 * ╚══════════════════════════════════════════════════╝
 */

module.exports = {

  // ── Network ──────────────────────────────────────
  PORT: 8080,               // high port, no root needed in Termux

  // ── Admin Panel Credentials ───────────────────────
  // Change these before your demo!
  ADMIN_USERNAME: 'admin',
  ADMIN_PASSWORD: 'demo1234',

  // ── Session secret (used to sign the admin cookie) ─
  // Any random string is fine for a local demo.
  SESSION_SECRET: 'airIsLeaking-secret-42',

};
