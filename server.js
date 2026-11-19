/**
 * AFM — Afrique Football Management
 * Serveur de l'application de gestion du club.
 *
 * - Sans framework : uniquement les modules intégrés de Node.js (+ "pg" pour PostgreSQL).
 * - Base de données : PostgreSQL si DATABASE_URL est défini, sinon un fichier JSON local
 *   (pratique pour tester sur votre ordinateur, à ne pas utiliser en production sur Render).
 */
"use strict";
const http = require("node:http");
const fs = require("node:fs");
const fsp = require("node:fs/promises");
const path = require("node:path");
const crypto = require("node:crypto");

const PORT = Number(process.env.PORT) || 3000;
const SECRET = process.env.SESSION_SECRET || "";
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || "admin").trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const PUBLIC_DIR = path.join(__dirname, "public");
const SESSION_DAYS = 30;

if (!SECRET || SECRET.length < 16) {
  console.warn("⚠  SESSION_SECRET absent ou trop court (16 caractères minimum). Une clé temporaire est utilisée : les sessions seront perdues à chaque redémarrage.");
}
const KEY = SECRET && SECRET.length >= 16 ? SECRET : crypto.randomBytes(32).toString("hex");

/* ------------------------------------------------------------------ */
/* Stockage : une table de documents JSON (collection, id, data)       */
/* ------------------------------------------------------------------ */
// Collections gérées par l'administration
const ADMIN_COLS = ["players", "matches", "trainings", "finances", "annonces", "decisions"];
// Collections internes : users (comptes d'accès), comptes (demandes d'absence par utilisateur), settings
const ALL_COLS = [...ADMIN_COLS, "users", "comptes", "settings"];

function makeStore() {
  if (process.env.DATABASE_URL) {
    const { Pool } = require("pg");
    const ssl = /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) || process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false };
    const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl, max: 5 });
    return {
      kind: "postgres",
      async init() {
        await pool.query(`CREATE TABLE IF NOT EXISTS docs (
          col TEXT NOT NULL, id TEXT NOT NULL, data JSONB NOT NULL,
          updated_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (col, id))`);
      },
      async all(col) { const r = await pool.query("SELECT id, data FROM docs WHERE col = $1", [col]); return r.rows.map(x => ({ ...x.data, id: x.id })); },
      async get(col, id) { const r = await pool.query("SELECT data FROM docs WHERE col = $1 AND id = $2", [col, id]); return r.rows[0] ? { ...r.rows[0].data, id } : null; },
      async put(col, id, data) {
        await pool.query(`INSERT INTO docs (col, id, data, updated_at) VALUES ($1, $2, $3, now())
          ON CONFLICT (col, id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, [col, id, JSON.stringify(data)]);
      },
      async del(col, id) { await pool.query("DELETE FROM docs WHERE col = $1 AND id = $2", [col, id]); },
      async version() { const r = await pool.query("SELECT COALESCE(MAX(updated_at), 'epoch') AS v, COUNT(*) AS n FROM docs"); return r.rows[0].v.toISOString() + ":" + r.rows[0].n; },
    };
  }
  // Fichier JSON local (développement)
  const file = process.env.DATA_FILE || path.join(__dirname, "data", "afm-data.json");
  let db = {}; let ver = 0; let writing = Promise.resolve();
  const flush = () => { writing = writing.then(async () => { await fsp.mkdir(path.dirname(file), { recursive: true }); const tmp = file + ".tmp"; await fsp.writeFile(tmp, JSON.stringify(db)); await fsp.rename(tmp, file); }); return writing; };
  return {
    kind: "fichier local",
    async init() { try { db = JSON.parse(await fsp.readFile(file, "utf8")); } catch { db = {}; } },
    async all(col) { return Object.entries(db[col] || {}).map(([id, d]) => ({ ...d, id })); },
    async get(col, id) { const d = (db[col] || {})[id]; return d ? { ...d, id } : null; },
    async put(col, id, data) { (db[col] = db[col] || {})[id] = data; ver++; await flush(); },
    async del(col, id) { if (db[col]) delete db[col][id]; ver++; await flush(); },
    async version() { return String(ver); },
  };
}
const store = makeStore();

/* ------------------------------------------------------------------ */
/* Mots de passe & sessions                                            */
/* ------------------------------------------------------------------ */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(pw, salt, 64);
  return "scrypt$" + salt.toString("hex") + "$" + hash.toString("hex");
}
function checkPassword(pw, stored) {
  if (!stored || !stored.startsWith("scrypt$")) return false;
  const [, saltHex, hashHex] = stored.split("$");
  const hash = crypto.scryptSync(pw, Buffer.from(saltHex, "hex"), 64);
  const ref = Buffer.from(hashHex, "hex");
  return ref.length === hash.length && crypto.timingSafeEqual(ref, hash);
}
const sign = s => crypto.createHmac("sha256", KEY).update(s).digest("base64url");
function makeToken(user) {
  const exp = Date.now() + SESSION_DAYS * 864e5;
  const body = `${user.id}.${exp}.${user.tokenVersion || 0}`;
  return body + "." + sign(body);
}
function readToken(tok) {
  if (!tok) return null;
  const parts = tok.split(".");
  if (parts.length !== 4) return null;
  const body = parts.slice(0, 3).join(".");
  const expected = sign(body);
  if (expected.length !== parts[3].length || !crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(parts[3]))) return null;
  if (Number(parts[1]) < Date.now()) return null;
  return { uid: parts[0], tv: Number(parts[2]) };
}
const parseCookies = h => Object.fromEntries((h || "").split(";").map(c => c.trim().split("=")).filter(p => p[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join("="))]));
function sessionCookie(req, value, maxAge) {
  const secure = req.headers["x-forwarded-proto"] === "https" || req.socket.encrypted;
  return `afm_session=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure ? "; Secure" : ""}`;
}
async function currentUser(req) {
  const t = readToken(parseCookies(req.headers.cookie).afm_session);
  if (!t) return null;
  const u = await store.get("users", t.uid);
  if (!u || u.disabled || (u.tokenVersion || 0) !== t.tv) return null;
  return u;
}
const publicUser = u => ({ id: u.id, username: u.username, nom: u.nom || "", role: u.role, playerId: u.playerId || "" });

// Limitation des tentatives de connexion (par adresse IP)
const attempts = new Map();
function tooManyAttempts(ip) {
  const now = Date.now(); const a = (attempts.get(ip) || []).filter(t => now - t < 15 * 60e3);
  attempts.set(ip, a); return a.length >= 10;
}
const noteFailure = ip => attempts.set(ip, [...(attempts.get(ip) || []), Date.now()]);

/* ------------------------------------------------------------------ */
/* Utilitaires HTTP                                                    */
/* ------------------------------------------------------------------ */
function send(res, status, obj, headers = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(body);
}
const fail = (res, status, message) => send(res, status, { error: message });
function readBody(req, limit = 1e6) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on("data", c => { size += c.length; if (size > limit) { reject(Object.assign(new Error("Requête trop volumineuse"), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on("end", () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}); } catch { reject(Object.assign(new Error("JSON invalide"), { status: 400 })); } });
    req.on("error", reject);
  });
}
const isObj = v => v && typeof v === "object" && !Array.isArray(v);
const validId = id => typeof id === "string" && /^[A-Za-z0-9_-]{1,64}$/.test(id);
const newId = () => Date.now().toString(36) + crypto.randomBytes(4).toString("hex");
const clean = s => String(s ?? "").trim().slice(0, 2000);

const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".png": "image/png", ".jpg": "image/jpeg", ".svg": "image/svg+xml", ".ico": "image/x-icon", ".webmanifest": "application/manifest+json", ".json": "application/json" };
async function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname);
  if (rel === "/") rel = "/index.html";
  const file = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) return fail(res, 403, "Interdit");
  try {
    const st = await fsp.stat(file);
    if (!st.isFile()) throw new Error();
    const ext = path.extname(file).toLowerCase();
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream", "Cache-Control": ext === ".html" || ext === ".webmanifest" || path.basename(file) === "sw.js" ? "no-cache" : "public, max-age=86400", "X-Content-Type-Options": "nosniff" });
    fs.createReadStream(file).pipe(res);
  } catch {
    // Application monopage : toute autre adresse renvoie l'index
    if (!path.extname(rel)) return serveStatic(req, res, "/index.html");
    fail(res, 404, "Introuvable");
  }
}

/* ------------------------------------------------------------------ */
/* Données renvoyées selon le rôle                                     */
/* ------------------------------------------------------------------ */
async function stateFor(user) {
  const isAdmin = user.role === "admin";
  const out = {};
  const settings = await store.get("settings", "club");
  out.settings = settings ? (({ id, ...s }) => s)(settings) : null;
  for (const c of ADMIN_COLS) {
    if (c === "finances" && !isAdmin) continue;
    out[c] = await store.all(c);
  }
  const users = await store.all("users");
  if (isAdmin) {
    const comptes = await store.all("comptes");
    out.comptes = users.filter(u => u.role === "joueur").map(u => ({ id: u.id, playerId: u.playerId || "", demandes: (comptes.find(c => c.id === u.id) || {}).demandes || [] }));
    // On garde aussi les demandes d'anciens comptes supprimés
    comptes.filter(c => !users.some(u => u.id === c.id)).forEach(c => out.comptes.push({ id: c.id, playerId: c.playerId || "", demandes: c.demandes || [] }));
    out.users = users.map(publicUser);
  } else {
    const mine = await store.get("comptes", user.id);
    const demandes = (mine && mine.demandes) || [];
    out.comptes = [{ id: user.id, playerId: user.playerId || "", demandes }];
    const ids = new Set(demandes.map(d => d.id));
    out.decisions = out.decisions.filter(d => ids.has(d.id));
    // Les joueurs ne voient pas les coordonnées ni les notes des autres
    out.players = out.players.map(p => p.id === user.playerId ? p : (({ telephone, notes, naissance, ...rest }) => rest)(p));
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Routes de l'API                                                     */
/* ------------------------------------------------------------------ */
async function api(req, res, pathname) {
  const m = req.method;
  const seg = pathname.split("/").filter(Boolean).slice(1); // sans "api"

  if (m === "GET" && seg[0] === "health") return send(res, 200, { ok: true, stockage: store.kind });

  if (m === "POST" && seg[0] === "login") {
    const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress;
    if (tooManyAttempts(ip)) return fail(res, 429, "Trop de tentatives. Réessayez dans 15 minutes.");
    const b = await readBody(req);
    const username = clean(b.username).toLowerCase();
    const users = await store.all("users");
    const u = users.find(x => x.username === username);
    if (!u || u.disabled || !checkPassword(String(b.password || ""), u.passHash)) { noteFailure(ip); return fail(res, 401, "Identifiant ou mot de passe incorrect"); }
    return send(res, 200, { user: publicUser(u) }, { "Set-Cookie": sessionCookie(req, makeToken(u), SESSION_DAYS * 86400) });
  }
  if (m === "POST" && seg[0] === "logout") return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", 0) });

  const user = await currentUser(req);
  if (!user) return fail(res, 401, "Connexion requise");
  const isAdmin = user.role === "admin";

  if (m === "GET" && seg[0] === "me") return send(res, 200, { user: publicUser(user) });
  if (m === "GET" && seg[0] === "version") return send(res, 200, { v: await store.version() });
  if (m === "GET" && seg[0] === "state") return send(res, 200, { user: publicUser(user), ...(await stateFor(user)) });

  // Changer son propre mot de passe
  if (m === "POST" && seg[0] === "password") {
    const b = await readBody(req);
    if (!checkPassword(String(b.ancien || ""), user.passHash)) return fail(res, 400, "Mot de passe actuel incorrect");
    if (String(b.nouveau || "").length < 6) return fail(res, 400, "Le nouveau mot de passe doit contenir au moins 6 caractères");
    const u = { ...user, passHash: hashPassword(String(b.nouveau)), tokenVersion: (user.tokenVersion || 0) + 1 }; delete u.id;
    await store.put("users", user.id, u);
    return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, makeToken({ ...u, id: user.id }), SESSION_DAYS * 86400) });
  }

  // Le joueur enregistre ses propres demandes d'absence
  if (m === "PUT" && seg[0] === "mes-demandes") {
    if (isAdmin) return fail(res, 400, "Réservé aux comptes joueurs");
    const b = await readBody(req, 2e5);
    if (!Array.isArray(b.demandes) || b.demandes.length > 500) return fail(res, 400, "Format invalide");
    const decisions = new Set((await store.all("decisions")).map(d => d.id));
    const before = ((await store.get("comptes", user.id)) || {}).demandes || [];
    // Une demande déjà traitée ne peut plus être modifiée ni supprimée par le joueur
    const locked = before.filter(d => decisions.has(d.id));
    const editable = b.demandes.filter(d => isObj(d) && validId(d.id) && !decisions.has(d.id)).map(d => ({
      id: d.id, type: clean(d.type).slice(0, 40), eventId: validId(d.eventId) ? d.eventId : "",
      date: clean(d.date).slice(0, 10), dateFin: clean(d.dateFin).slice(0, 10), motif: clean(d.motif).slice(0, 60),
      details: clean(d.details), createdAt: clean(d.createdAt).slice(0, 30) || new Date().toISOString(),
    }));
    const demandes = [...locked, ...editable.filter(d => !locked.some(l => l.id === d.id))];
    await store.put("comptes", user.id, { playerId: user.playerId || "", demandes });
    return send(res, 200, { ok: true, demandes });
  }

  // ---- À partir d'ici : administration uniquement ----
  if (!isAdmin) return fail(res, 403, "Réservé à l'administration");

  // Paramètres du club
  if (m === "PUT" && seg[0] === "settings") {
    const b = await readBody(req);
    const s = { nom: clean(b.nom).slice(0, 80), saison: clean(b.saison).slice(0, 30), stade: clean(b.stade).slice(0, 120), devise: clean(b.devise).slice(0, 10), cotisation: Number(b.cotisation) || 0 };
    await store.put("settings", "club", s);
    return send(res, 200, { ok: true });
  }

  // Comptes d'accès
  if (seg[0] === "users") {
    const users = await store.all("users");
    if (m === "POST" && seg.length === 1) {
      const b = await readBody(req);
      const username = clean(b.username).toLowerCase();
      if (!/^[a-z0-9._-]{3,32}$/.test(username)) return fail(res, 400, "Identifiant : 3 à 32 caractères (lettres, chiffres, . _ -)");
      if (users.some(u => u.username === username)) return fail(res, 400, "Cet identifiant existe déjà");
      if (String(b.password || "").length < 6) return fail(res, 400, "Le mot de passe doit contenir au moins 6 caractères");
      const role = b.role === "admin" ? "admin" : "joueur";
      const id = newId();
      await store.put("users", id, { username, nom: clean(b.nom).slice(0, 80), role, playerId: role === "joueur" && validId(b.playerId) ? b.playerId : "", passHash: hashPassword(String(b.password)), tokenVersion: 0, createdAt: new Date().toISOString() });
      return send(res, 200, { ok: true, id });
    }
    const target = users.find(u => u.id === seg[1]);
    if (!target) return fail(res, 404, "Compte introuvable");
    if (m === "PUT") {
      const b = await readBody(req);
      const upd = { ...target }; delete upd.id;
      if (b.nom !== undefined) upd.nom = clean(b.nom).slice(0, 80);
      if (b.playerId !== undefined) upd.playerId = validId(b.playerId) ? b.playerId : "";
      if (b.role !== undefined && target.id !== user.id) upd.role = b.role === "admin" ? "admin" : "joueur";
      if (b.password) {
        if (String(b.password).length < 6) return fail(res, 400, "Le mot de passe doit contenir au moins 6 caractères");
        upd.passHash = hashPassword(String(b.password)); upd.tokenVersion = (target.tokenVersion || 0) + 1;
      }
      await store.put("users", target.id, upd);
      return send(res, 200, { ok: true });
    }
    if (m === "DELETE") {
      if (target.id === user.id) return fail(res, 400, "Vous ne pouvez pas supprimer votre propre compte");
      if (target.role === "admin" && users.filter(u => u.role === "admin").length <= 1) return fail(res, 400, "Il doit rester au moins un administrateur");
      await store.del("users", target.id);
      return send(res, 200, { ok: true });
    }
  }

  // Données du club : /api/data/:collection/:id
  if (seg[0] === "data" && ADMIN_COLS.includes(seg[1]) && validId(seg[2])) {
    if (m === "PUT") {
      const b = await readBody(req);
      if (!isObj(b)) return fail(res, 400, "Format invalide");
      const { id, ...data } = b;
      await store.put(seg[1], seg[2], data);
      return send(res, 200, { ok: true });
    }
    if (m === "DELETE") { await store.del(seg[1], seg[2]); return send(res, 200, { ok: true }); }
  }
  return fail(res, 404, "Route inconnue");
}

/* ------------------------------------------------------------------ */
/* Démarrage                                                           */
/* ------------------------------------------------------------------ */
async function ensureAdmin() {
  const users = await store.all("users");
  if (users.some(u => u.role === "admin")) return;
  if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 6) {
    console.warn("⚠  Aucun administrateur. Définissez ADMIN_USERNAME et ADMIN_PASSWORD (6 caractères min.) puis redémarrez.");
    return;
  }
  await store.put("users", newId(), { username: ADMIN_USERNAME, nom: "Administrateur", role: "admin", playerId: "", passHash: hashPassword(ADMIN_PASSWORD), tokenVersion: 0, createdAt: new Date().toISOString() });
  console.log(`✓ Compte administrateur « ${ADMIN_USERNAME} » créé.`);
}

const server = http.createServer(async (req, res) => {
  try {
    const { pathname } = new URL(req.url, "http://x");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("Referrer-Policy", "same-origin");
    if (pathname.startsWith("/api/")) {
      // Protection CSRF simple : les écritures doivent venir de l'application elle-même
      if (req.method !== "GET" && req.headers["x-afm"] !== "1") return fail(res, 403, "Requête refusée");
      return await api(req, res, pathname);
    }
    if (req.method !== "GET" && req.method !== "HEAD") return fail(res, 405, "Méthode non autorisée");
    return await serveStatic(req, res, pathname);
  } catch (e) {
    if (!res.headersSent) fail(res, e.status || 500, e.status ? e.message : "Erreur du serveur");
    if (!e.status) console.error(e);
  }
});

(async () => {
  await store.init();
  await ensureAdmin();
  server.listen(PORT, () => console.log(`AFM en ligne sur le port ${PORT} (stockage : ${store.kind})`));
})().catch(e => { console.error("Démarrage impossible :", e); process.exit(1); });
