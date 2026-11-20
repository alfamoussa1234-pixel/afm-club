/**
 * AFM — Afrique Football Management
 * Serveur de l'application de gestion du club.
 *
 * Rôles :
 *   admin     → tout, y compris finances, comptes d'accès et paramètres
 *   dirigeant → gère joueurs, matchs, entraînements, annonces, absences, bibliothèque (pas finances / comptes / paramètres)
 *   joueur    → son espace : annonces, calendrier, ses absences, bibliothèque
 *   fan       → vitrine : annonces publiques, calendrier et résultats, effectif, bibliothèque (inscription libre par téléphone)
 *
 * - Sans framework : modules intégrés de Node.js (+ "pg" pour PostgreSQL).
 * - Base de données : PostgreSQL si DATABASE_URL est défini, sinon des fichiers locaux (développement uniquement).
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
const MAX_IMAGE_BYTES = 1.5 * 1024 * 1024;

if (!SECRET || SECRET.length < 16) {
  console.warn("⚠  SESSION_SECRET absent ou trop court (16 caractères minimum). Une clé temporaire est utilisée : les sessions seront perdues à chaque redémarrage.");
}
const KEY = SECRET && SECRET.length >= 16 ? SECRET : crypto.randomBytes(32).toString("hex");

/* ------------------------------------------------------------------ */
/* Collections                                                         */
/* ------------------------------------------------------------------ */
const LIBRARY_COLS = ["histoire", "trophees", "membres", "galerie"];
// Gérées par l'administration ET les dirigeants
const STAFF_COLS = ["players", "matches", "trainings", "annonces", "decisions", ...LIBRARY_COLS];
// Gérées uniquement par l'administrateur
const ADMIN_ONLY_COLS = ["finances"];
const DATA_COLS = [...STAFF_COLS, ...ADMIN_ONLY_COLS];
const ROLES = ["admin", "dirigeant", "joueur", "fan"];
const isStaff = u => u.role === "admin" || u.role === "dirigeant";

/* ------------------------------------------------------------------ */
/* Stockage : documents JSON (collection, id, data) + images           */
/* ------------------------------------------------------------------ */
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
        await pool.query(`CREATE TABLE IF NOT EXISTS media (
          id TEXT PRIMARY KEY, mime TEXT NOT NULL, data BYTEA NOT NULL, created_at TIMESTAMPTZ NOT NULL DEFAULT now())`);
      },
      async all(col) { const r = await pool.query("SELECT id, data FROM docs WHERE col = $1", [col]); return r.rows.map(x => ({ ...x.data, id: x.id })); },
      async get(col, id) { const r = await pool.query("SELECT data FROM docs WHERE col = $1 AND id = $2", [col, id]); return r.rows[0] ? { ...r.rows[0].data, id } : null; },
      async put(col, id, data) {
        await pool.query(`INSERT INTO docs (col, id, data, updated_at) VALUES ($1, $2, $3, now())
          ON CONFLICT (col, id) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, [col, id, JSON.stringify(data)]);
      },
      async del(col, id) { await pool.query("DELETE FROM docs WHERE col = $1 AND id = $2", [col, id]); },
      async version() { const r = await pool.query("SELECT COALESCE(MAX(updated_at), 'epoch') AS v, COUNT(*) AS n FROM docs"); return r.rows[0].v.toISOString() + ":" + r.rows[0].n; },
      async putMedia(id, mime, buf) { await pool.query("INSERT INTO media (id, mime, data) VALUES ($1, $2, $3)", [id, mime, buf]); },
      async getMedia(id) { const r = await pool.query("SELECT mime, data FROM media WHERE id = $1", [id]); return r.rows[0] || null; },
      async delMedia(id) { await pool.query("DELETE FROM media WHERE id = $1", [id]); },
    };
  }
  // Fichiers locaux (développement)
  const dir = process.env.DATA_DIR || path.join(__dirname, "data");
  const file = path.join(dir, "afm-data.json");
  const mediaDir = path.join(dir, "media");
  let db = {}; let ver = 0; let writing = Promise.resolve();
  const flush = () => { writing = writing.then(async () => { await fsp.mkdir(dir, { recursive: true }); const tmp = file + ".tmp"; await fsp.writeFile(tmp, JSON.stringify(db)); await fsp.rename(tmp, file); }); return writing; };
  return {
    kind: "fichier local",
    async init() { try { db = JSON.parse(await fsp.readFile(file, "utf8")); } catch { db = {}; } await fsp.mkdir(mediaDir, { recursive: true }); },
    async all(col) { return Object.entries(db[col] || {}).map(([id, d]) => ({ ...d, id })); },
    async get(col, id) { const d = (db[col] || {})[id]; return d ? { ...d, id } : null; },
    async put(col, id, data) { (db[col] = db[col] || {})[id] = data; ver++; await flush(); },
    async del(col, id) { if (db[col]) delete db[col][id]; ver++; await flush(); },
    async version() { return String(ver); },
    async putMedia(id, mime, buf) { await fsp.writeFile(path.join(mediaDir, id), buf); await fsp.writeFile(path.join(mediaDir, id + ".type"), mime); },
    async getMedia(id) { try { return { data: await fsp.readFile(path.join(mediaDir, id)), mime: await fsp.readFile(path.join(mediaDir, id + ".type"), "utf8") }; } catch { return null; } },
    async delMedia(id) { await fsp.rm(path.join(mediaDir, id), { force: true }); await fsp.rm(path.join(mediaDir, id + ".type"), { force: true }); },
  };
}
const store = makeStore();

/* ------------------------------------------------------------------ */
/* Mots de passe, sessions, téléphones                                 */
/* ------------------------------------------------------------------ */
function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return "scrypt$" + salt.toString("hex") + "$" + crypto.scryptSync(pw, salt, 64).toString("hex");
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
  const body = `${user.id}.${Date.now() + SESSION_DAYS * 864e5}.${user.tokenVersion || 0}`;
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
const publicUser = u => ({ id: u.id, username: u.username, nom: u.nom || "", role: u.role, playerId: u.playerId || "", telephone: u.telephone || "" });

/** Normalise un numéro : chiffres seulement, indicatif 223 (Mali) ajouté aux numéros à 8 chiffres. */
function normalizePhone(input) {
  let s = String(input || "").replace(/[\s.\-()/]/g, "");
  if (s.startsWith("+")) s = s.slice(1); else if (s.startsWith("00")) s = s.slice(2);
  if (!/^\d+$/.test(s)) return null;
  if (s.length === 8) s = "223" + s;
  return s.length >= 9 && s.length <= 15 ? s : null;
}

// Limitation des tentatives (par adresse IP)
const buckets = new Map();
function limited(key, max, windowMs) {
  const now = Date.now(); const a = (buckets.get(key) || []).filter(t => now - t < windowMs);
  buckets.set(key, a); return a.length >= max;
}
const hit = key => buckets.set(key, [...(buckets.get(key) || []), Date.now()]);
const clientIp = req => (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || req.socket.remoteAddress;

/* ------------------------------------------------------------------ */
/* Utilitaires HTTP                                                    */
/* ------------------------------------------------------------------ */
function send(res, status, obj, headers = {}) {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
  res.end(JSON.stringify(obj));
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
    const noCache = ext === ".html" || ext === ".webmanifest" || path.basename(file) === "sw.js";
    res.writeHead(200, { "Content-Type": MIME[ext] || "application/octet-stream", "Cache-Control": noCache ? "no-cache" : "public, max-age=86400", "X-Content-Type-Options": "nosniff" });
    fs.createReadStream(file).pipe(res);
  } catch {
    if (!path.extname(rel)) return serveStatic(req, res, "/index.html");
    fail(res, 404, "Introuvable");
  }
}

/* ------------------------------------------------------------------ */
/* Données renvoyées selon le rôle                                     */
/* ------------------------------------------------------------------ */
const stripPrivatePlayer = p => (({ telephone, notes, naissance, cotisation, ...rest }) => rest)(p);
async function stateFor(user) {
  const out = {};
  const settings = await store.get("settings", "club");
  out.settings = settings ? (({ id, ...s }) => s)(settings) : null;
  for (const c of LIBRARY_COLS) out[c] = await store.all(c);
  out.presentation = await getPresentation();
  out.matches = await store.all("matches");
  out.players = await store.all("players");
  const annonces = await store.all("annonces");

  if (user.role === "fan") {
    out.annonces = annonces.filter(a => a.public === true);
    out.players = out.players.filter(p => p.statut !== "Inactif").map(p => (({ telephone, notes, naissance, cotisation, statut, ...rest }) => rest)(p));
    out.trainings = []; out.decisions = []; out.comptes = [];
    return out;
  }
  out.annonces = annonces;
  out.trainings = await store.all("trainings");
  out.decisions = await store.all("decisions");
  const users = await store.all("users");

  if (isStaff(user)) {
    const comptes = await store.all("comptes");
    out.comptes = users.filter(u => u.role === "joueur").map(u => ({ id: u.id, playerId: u.playerId || "", demandes: (comptes.find(c => c.id === u.id) || {}).demandes || [] }));
    comptes.filter(c => !users.some(u => u.id === c.id)).forEach(c => out.comptes.push({ id: c.id, playerId: c.playerId || "", demandes: c.demandes || [] }));
    if (user.role === "admin") {
      out.finances = await store.all("finances");
      out.users = users.map(publicUser);
    } else {
      // Les dirigeants voient qui a un accès joueur, sans gérer les comptes
      out.users = users.filter(u => u.role === "joueur").map(u => ({ id: u.id, username: u.username, role: u.role, playerId: u.playerId || "" }));
    }
    out.fansCount = users.filter(u => u.role === "fan").length;
    return out;
  }
  // joueur
  const mine = await store.get("comptes", user.id);
  const demandes = (mine && mine.demandes) || [];
  out.comptes = [{ id: user.id, playerId: user.playerId || "", demandes }];
  const ids = new Set(demandes.map(d => d.id));
  out.decisions = out.decisions.filter(d => ids.has(d.id));
  out.players = out.players.map(p => p.id === user.playerId ? p : stripPrivatePlayer(p));
  return out;
}

/* ------------------------------------------------------------------ */
/* Présentation du club (publique)                                     */
/* ------------------------------------------------------------------ */
const PRES_TEXT = { slogan: 120, accroche: 600, presentation: 6000, motPresident: 4000, presidentNom: 80, presidentTitre: 80, mission: 3000, valeurs: 1500, fondation: 10, couleurs: 120, siege: 300, stade: 200, telephone: 40, email: 120, whatsapp: 40 };
const PRES_URLS = ["facebook", "instagram", "tiktok", "youtube", "x", "site"];
const PRES_PHOTOS = ["couverture", "presidentPhoto"];
function cleanPresentation(b) {
  const p = {};
  for (const [k, max] of Object.entries(PRES_TEXT)) p[k] = String(b[k] ?? "").trim().slice(0, max);
  for (const k of PRES_URLS) { const u = String(b[k] ?? "").trim().slice(0, 300); p[k] = /^https?:\/\/[^\s<>"']+$/i.test(u) ? u : ""; }
  for (const k of PRES_PHOTOS) p[k] = validId(b[k]) ? b[k] : "";
  p.chiffres = (Array.isArray(b.chiffres) ? b.chiffres : []).slice(0, 6).map(c => ({ valeur: String((c && c.valeur) ?? "").trim().slice(0, 20), libelle: String((c && c.libelle) ?? "").trim().slice(0, 60) })).filter(c => c.valeur && c.libelle);
  p.updatedAt = new Date().toISOString();
  return p;
}
async function getPresentation() { const p = await store.get("presentation", "club"); if (!p) return {}; const { id, ...rest } = p; return rest; }

/* ------------------------------------------------------------------ */
/* Images (photos des joueurs, membres, trophées, galerie)             */
/* ------------------------------------------------------------------ */
function decodeImage(dataUrl) {
  const m = /^data:(image\/(?:jpeg|png|webp));base64,([A-Za-z0-9+/=]+)$/.exec(String(dataUrl || ""));
  if (!m) return null;
  const buf = Buffer.from(m[2], "base64");
  if (!buf.length || buf.length > MAX_IMAGE_BYTES) return null;
  // Vérifie la signature réelle du fichier
  const sig = buf.subarray(0, 12);
  const ok = (m[1] === "image/jpeg" && sig[0] === 0xff && sig[1] === 0xd8) ||
    (m[1] === "image/png" && sig[0] === 0x89 && sig[1] === 0x50) ||
    (m[1] === "image/webp" && sig.toString("ascii", 0, 4) === "RIFF" && sig.toString("ascii", 8, 12) === "WEBP");
  return ok ? { mime: m[1], buf } : null;
}
async function serveMedia(req, res, id) {
  if (!validId(id)) return fail(res, 404, "Introuvable");
  const user = await currentUser(req);
  let isPublic = false;
  if (!user) {
    // Seules les photos de la présentation publique sont visibles sans compte
    const p = await getPresentation();
    if (!PRES_PHOTOS.some(k => p[k] === id)) return fail(res, 401, "Connexion requise");
    isPublic = true;
  }
  const m = await store.getMedia(id);
  if (!m) return fail(res, 404, "Introuvable");
  res.writeHead(200, { "Content-Type": m.mime, "Cache-Control": (isPublic ? "public" : "private") + ", max-age=31536000, immutable", "X-Content-Type-Options": "nosniff" });
  res.end(m.data);
}

/* ------------------------------------------------------------------ */
/* Routes de l'API                                                     */
/* ------------------------------------------------------------------ */
async function api(req, res, pathname) {
  const m = req.method;
  const seg = pathname.split("/").filter(Boolean).slice(1); // sans "api"

  if (m === "GET" && seg[0] === "health") return send(res, 200, { ok: true, stockage: store.kind });

  if (m === "GET" && seg[0] === "public") {
    const s = (await store.get("settings", "club")) || {};
    return send(res, 200, { nom: s.nom || "AFM", fansOuverts: s.fansOuverts !== false });
  }
  if (m === "GET" && seg[0] === "presentation") {
    const s = (await store.get("settings", "club")) || {};
    return send(res, 200, { presentation: await getPresentation(), nom: s.nom || "AFM", saison: s.saison || "", fansOuverts: s.fansOuverts !== false });
  }

  if (m === "POST" && seg[0] === "login") {
    const ip = clientIp(req);
    if (limited("login:" + ip, 10, 15 * 60e3)) return fail(res, 429, "Trop de tentatives. Réessayez dans 15 minutes.");
    const b = await readBody(req);
    const ident = clean(b.username).toLowerCase();
    const phone = normalizePhone(ident);
    const users = await store.all("users");
    const u = users.find(x => x.username === ident) || (phone && users.find(x => x.telephone === phone));
    if (!u || u.disabled || !checkPassword(String(b.password || ""), u.passHash)) { hit("login:" + ip); return fail(res, 401, "Identifiant, téléphone ou mot de passe incorrect"); }
    return send(res, 200, { user: publicUser(u) }, { "Set-Cookie": sessionCookie(req, makeToken(u), SESSION_DAYS * 86400) });
  }
  if (m === "POST" && seg[0] === "logout") return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", 0) });

  // Inscription libre des fans (numéro de téléphone + mot de passe)
  if (m === "POST" && seg[0] === "register") {
    const s = (await store.get("settings", "club")) || {};
    if (s.fansOuverts === false) return fail(res, 403, "Les inscriptions des fans sont fermées pour le moment.");
    const ip = clientIp(req);
    if (limited("register:" + ip, 5, 60 * 60e3)) return fail(res, 429, "Trop d'inscriptions depuis cet appareil. Réessayez plus tard.");
    const b = await readBody(req);
    const nom = clean(b.nom).slice(0, 80);
    const phone = normalizePhone(b.telephone);
    const pw = String(b.password || "");
    if (nom.length < 2) return fail(res, 400, "Indiquez votre nom");
    if (!phone) return fail(res, 400, "Numéro de téléphone invalide (ex. 76 12 34 56)");
    if (pw.length < 6) return fail(res, 400, "Le mot de passe doit contenir au moins 6 caractères");
    const users = await store.all("users");
    if (users.some(u => u.telephone === phone || u.username === phone)) return fail(res, 400, "Ce numéro est déjà inscrit. Connectez-vous avec votre mot de passe.");
    hit("register:" + ip);
    const id = newId();
    const u = { username: phone, telephone: phone, nom, role: "fan", playerId: "", passHash: hashPassword(pw), tokenVersion: 0, createdAt: new Date().toISOString() };
    await store.put("users", id, u);
    return send(res, 200, { user: publicUser({ ...u, id }) }, { "Set-Cookie": sessionCookie(req, makeToken({ ...u, id }), SESSION_DAYS * 86400) });
  }

  const user = await currentUser(req);
  if (!user) return fail(res, 401, "Connexion requise");
  const staff = isStaff(user), admin = user.role === "admin";

  if (m === "GET" && seg[0] === "me") return send(res, 200, { user: publicUser(user) });
  if (m === "GET" && seg[0] === "version") return send(res, 200, { v: await store.version() });
  if (m === "GET" && seg[0] === "state") return send(res, 200, { user: publicUser(user), ...(await stateFor(user)) });

  if (m === "POST" && seg[0] === "password") {
    const b = await readBody(req);
    if (!checkPassword(String(b.ancien || ""), user.passHash)) return fail(res, 400, "Mot de passe actuel incorrect");
    if (String(b.nouveau || "").length < 6) return fail(res, 400, "Le nouveau mot de passe doit contenir au moins 6 caractères");
    const u = { ...user, passHash: hashPassword(String(b.nouveau)), tokenVersion: (user.tokenVersion || 0) + 1 }; delete u.id;
    await store.put("users", user.id, u);
    return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, makeToken({ ...u, id: user.id }), SESSION_DAYS * 86400) });
  }

  // Un fan peut supprimer son propre compte
  if (m === "DELETE" && seg[0] === "mon-compte" && user.role === "fan") {
    await store.del("users", user.id);
    return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", 0) });
  }

  if (m === "PUT" && seg[0] === "mes-demandes") {
    if (user.role !== "joueur") return fail(res, 400, "Réservé aux comptes joueurs");
    const b = await readBody(req, 2e5);
    if (!Array.isArray(b.demandes) || b.demandes.length > 500) return fail(res, 400, "Format invalide");
    const decisions = new Set((await store.all("decisions")).map(d => d.id));
    const before = ((await store.get("comptes", user.id)) || {}).demandes || [];
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

  // ---- Administration et dirigeants ----
  if (!staff) return fail(res, 403, "Accès réservé à la direction du club");

  // Présentation du club
  if (m === "PUT" && seg[0] === "presentation") {
    const b = await readBody(req, 2e5);
    if (!isObj(b)) return fail(res, 400, "Format invalide");
    const old = await getPresentation();
    const p = cleanPresentation(b);
    await store.put("presentation", "club", p);
    for (const k of PRES_PHOTOS) if (old[k] && old[k] !== p[k]) await store.delMedia(old[k]).catch(() => {});
    return send(res, 200, { ok: true, presentation: p });
  }

  // Envoi d'une image (déjà compressée par l'application)
  if (m === "POST" && seg[0] === "media") {
    const ip = clientIp(req);
    if (limited("media:" + user.id, 120, 60 * 60e3)) return fail(res, 429, "Trop d'images envoyées, réessayez plus tard");
    const b = await readBody(req, 2.2e6);
    const img = decodeImage(b.data);
    if (!img) return fail(res, 400, "Image invalide ou trop lourde (1,5 Mo maximum)");
    hit("media:" + user.id); void ip;
    const id = newId();
    await store.putMedia(id, img.mime, img.buf);
    return send(res, 200, { id });
  }

  // Données du club : /api/data/:collection/:id
  if (seg[0] === "data" && DATA_COLS.includes(seg[1]) && validId(seg[2])) {
    if (ADMIN_ONLY_COLS.includes(seg[1]) && !admin) return fail(res, 403, "Réservé à l'administrateur");
    const old = await store.get(seg[1], seg[2]);
    if (m === "PUT") {
      const b = await readBody(req);
      if (!isObj(b)) return fail(res, 400, "Format invalide");
      const { id, ...data } = b;
      if (data.photo !== undefined && data.photo !== "" && !validId(data.photo)) return fail(res, 400, "Photo invalide");
      await store.put(seg[1], seg[2], data);
      if (old && old.photo && old.photo !== data.photo) await store.delMedia(old.photo).catch(() => {});
      return send(res, 200, { ok: true });
    }
    if (m === "DELETE") {
      await store.del(seg[1], seg[2]);
      if (old && old.photo) await store.delMedia(old.photo).catch(() => {});
      return send(res, 200, { ok: true });
    }
  }

  // ---- Administrateur uniquement ----
  if (!admin) return fail(res, 403, "Réservé à l'administrateur");

  if (m === "PUT" && seg[0] === "settings") {
    const b = await readBody(req);
    const s = { nom: clean(b.nom).slice(0, 80), saison: clean(b.saison).slice(0, 30), stade: clean(b.stade).slice(0, 120), devise: clean(b.devise).slice(0, 10), cotisation: Number(b.cotisation) || 0, fansOuverts: b.fansOuverts !== false };
    await store.put("settings", "club", s);
    return send(res, 200, { ok: true });
  }

  if (seg[0] === "users") {
    const users = await store.all("users");
    if (m === "POST" && seg.length === 1) {
      const b = await readBody(req);
      const username = clean(b.username).toLowerCase();
      if (!/^[a-z0-9._-]{3,32}$/.test(username)) return fail(res, 400, "Identifiant : 3 à 32 caractères (lettres, chiffres, . _ -)");
      if (users.some(u => u.username === username)) return fail(res, 400, "Cet identifiant existe déjà");
      if (String(b.password || "").length < 6) return fail(res, 400, "Le mot de passe doit contenir au moins 6 caractères");
      const role = ROLES.includes(b.role) ? b.role : "joueur";
      const phone = b.telephone ? normalizePhone(b.telephone) : "";
      if (b.telephone && !phone) return fail(res, 400, "Numéro de téléphone invalide");
      if (phone && users.some(u => u.telephone === phone)) return fail(res, 400, "Ce numéro est déjà utilisé par un autre compte");
      const id = newId();
      await store.put("users", id, { username, nom: clean(b.nom).slice(0, 80), role, telephone: phone || "", playerId: role === "joueur" && validId(b.playerId) ? b.playerId : "", passHash: hashPassword(String(b.password)), tokenVersion: 0, createdAt: new Date().toISOString() });
      return send(res, 200, { ok: true, id });
    }
    const target = users.find(u => u.id === seg[1]);
    if (!target) return fail(res, 404, "Compte introuvable");
    if (m === "PUT") {
      const b = await readBody(req);
      const upd = { ...target }; delete upd.id;
      if (b.nom !== undefined) upd.nom = clean(b.nom).slice(0, 80);
      if (b.role !== undefined && target.id !== user.id && ROLES.includes(b.role)) {
        if (target.role === "admin" && b.role !== "admin" && users.filter(u => u.role === "admin").length <= 1) return fail(res, 400, "Il doit rester au moins un administrateur");
        upd.role = b.role;
      }
      if (b.playerId !== undefined || b.role !== undefined) upd.playerId = upd.role === "joueur" && validId(b.playerId) ? b.playerId : "";
      if (b.telephone !== undefined) {
        const phone = b.telephone ? normalizePhone(b.telephone) : "";
        if (b.telephone && !phone) return fail(res, 400, "Numéro de téléphone invalide");
        if (phone && users.some(u => u.id !== target.id && u.telephone === phone)) return fail(res, 400, "Ce numéro est déjà utilisé par un autre compte");
        upd.telephone = phone || "";
      }
      if (b.password) {
        if (String(b.password).length < 6) return fail(res, 400, "Le mot de passe doit contenir au moins 6 caractères");
        upd.passHash = hashPassword(String(b.password)); upd.tokenVersion = (target.tokenVersion || 0) + 1;
      }
      if (b.role !== undefined && upd.role !== target.role) upd.tokenVersion = (upd.tokenVersion || 0) + 1;
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
  await store.put("users", newId(), { username: ADMIN_USERNAME, nom: "Administrateur", role: "admin", playerId: "", telephone: "", passHash: hashPassword(ADMIN_PASSWORD), tokenVersion: 0, createdAt: new Date().toISOString() });
  console.log(`✓ Compte administrateur « ${ADMIN_USERNAME} » créé.`);
}

const server = http.createServer(async (req, res) => {
  try {
    const { pathname } = new URL(req.url, "http://x");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("Referrer-Policy", "same-origin");
    if (pathname.startsWith("/api/")) {
      if (req.method !== "GET" && req.headers["x-afm"] !== "1") return fail(res, 403, "Requête refusée");
      return await api(req, res, pathname);
    }
    if (pathname.startsWith("/media/") && req.method === "GET") return await serveMedia(req, res, pathname.slice(7));
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
