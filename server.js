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
/** Exécute les mises à jour d'un même document l'une après l'autre (évite de perdre un message). */
const locks = new Map();
function withLock(key, fn) {
  const prev = locks.get(key) || Promise.resolve();
  const next = prev.catch(() => {}).then(fn);
  locks.set(key, next.finally(() => { if (locks.get(key) === next) locks.delete(key); }));
  return next;
}
const MAX_MESSAGES = 500;
const fil = async uid => (await store.get("fils", uid)) || { messages: [], readStaff: "", readJoueur: "" };

/* IA (Claude) pour les textes d'affiches — facultatif : nécessite ANTHROPIC_API_KEY */
const AI_KEY = process.env.ANTHROPIC_API_KEY || "";
const AI_MODEL = process.env.ANTHROPIC_MODEL || "claude-haiku-5-5";
async function askClaude(prompt, maxTokens = 1200, timeoutMs = 45000) {
  const r = await fetch((process.env.ANTHROPIC_BASE_URL || "https://api.anthropic.com") + "/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json", "x-api-key": AI_KEY, "anthropic-version": "2023-06-01" },
    body: JSON.stringify({ model: AI_MODEL, max_tokens: maxTokens, messages: [{ role: "user", content: prompt }] }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) { console.error("IA :", r.status, d && d.error && d.error.message); throw Object.assign(new Error(r.status === 401 ? "Clé IA invalide : vérifiez ANTHROPIC_API_KEY sur Render." : r.status === 429 ? "L'IA est momentanément saturée, réessayez dans une minute." : "Le service d'IA ne répond pas, réessayez."), { status: 502 }); }
  return (d.content || []).filter(b => b.type === "text").map(b => b.text).join("\n");
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
    out.matches = out.matches.map(({ convoques, ...m }) => (m.compo && m.compo.public === false ? { ...m, compo: null } : m));
    out.suggestions = (await store.all("suggestions")).filter(s => s.userId === user.id).map(s => ({ id: s.id, categorie: s.categorie, texte: s.texte, date: s.date }));
    out.fils = [];
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
    out.fils = await store.all("fils");
    out.suggestions = (await store.all("suggestions")).map(s => user.role === "admin" ? s : (({ telephone, ...rest }) => rest)(s));
    out.iaDisponible = !!AI_KEY;
    out.stockage = store.kind;
    return out;
  }
  // joueur
  out.suggestions = [];
  out.matches = out.matches.map(m => (m.compo && m.compo.public === false ? { ...m, compo: null } : m));
  out.trainings = out.trainings.map(({ pointage, ...t }) => ({ ...t, pointe: !!((pointage && Object.keys(pointage).length) || (t.presents || []).length), pointage: pointage && pointage[user.playerId] ? { [user.playerId]: pointage[user.playerId] } : {}, presents: (t.presents || []).filter(id => id === user.playerId), seance: t.seance && t.seance.visibleJoueurs !== false ? t.seance : null }));
  const monFil = await store.get("fils", user.id);
  out.fils = monFil ? [monFil] : [];
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
/* Application Android (Play Store) : liaison site ↔ application        */
/* ------------------------------------------------------------------ */
// ANDROID_PACKAGE : identifiant du paquet (ex. com.onrender.afm_club.twa)
// ANDROID_SHA256  : empreinte(s) SHA-256 de la clé de signature, séparées par des virgules
function assetLinks() {
  const pkg = (process.env.ANDROID_PACKAGE || "").trim();
  const fps = (process.env.ANDROID_SHA256 || "").split(",").map(s => s.trim().toUpperCase()).filter(s => /^([0-9A-F]{2}:){31}[0-9A-F]{2}$/.test(s));
  if (!pkg || !fps.length) return [];
  return [{ relation: ["delegate_permission/common.handle_all_urls"], target: { namespace: "android_app", package_name: pkg, sha256_cert_fingerprints: fps } }];
}

/* ------------------------------------------------------------------ */
/* Politique de confidentialité et suppression de compte (publiques)   */
/* ------------------------------------------------------------------ */
const escHtml = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
async function privacyPage(req, res) {
  const p = await getPresentation();
  const s = (await store.get("settings", "club")) || {};
  const nom = escHtml(s.nom || "AFM");
  const contacts = [p.email && `par e-mail : <b>${escHtml(p.email)}</b>`, p.telephone && `par téléphone : <b>${escHtml(p.telephone)}</b>`, p.whatsapp && `sur WhatsApp : <b>${escHtml(p.whatsapp)}</b>`, p.siege && `ou au siège du club : ${escHtml(p.siege)}`].filter(Boolean);
  const contact = contacts.length ? contacts.join(", ") : "auprès de la direction du club";
  const html = `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Confidentialité — ${nom}</title><link rel="icon" href="/icon-192.png">
<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;max-width:760px;margin:0 auto;padding:24px 18px 60px;color:#151632;line-height:1.6}h1{color:#1e1882;line-height:1.2}h2{color:#1e1882;margin-top:28px;border-bottom:2px solid #c9a40e;padding-bottom:4px}header{display:flex;align-items:center;gap:12px}header img{width:64px}a{color:#1e1882}.box{background:#f4f5f9;border-radius:10px;padding:14px 16px}</style></head><body>
<header><img src="/logo.png" alt=""><div><b>${nom} — Afrique Football Management</b><br><small>Application de gestion du club</small></div></header>
<h1>Politique de confidentialité</h1>
<p>Cette politique explique quelles données l'application ${nom} collecte, pourquoi, et comment vous pouvez les faire supprimer. Elle s'applique au site et à l'application Android.</p>
<h2>Données collectées</h2>
<ul>
<li><b>Supporters (espace fans)</b> : nom, numéro de téléphone et mot de passe, fournis lors de l'inscription.</li>
<li><b>Joueurs</b> : nom, prénom, numéro de maillot, poste, date de naissance, téléphone, photo, statistiques sportives, présences aux entraînements et déclarations d'absence avec leur motif.</li>
<li><b>Dirigeants et administrateurs</b> : identifiant, nom, téléphone éventuel.</li>
<li><b>Photos</b> publiées par la direction du club (joueurs, membres, galerie, trophées).</li>
</ul>
<p>Les mots de passe sont chiffrés de manière irréversible (scrypt) : personne, pas même le club, ne peut les lire. L'application n'utilise ni publicité, ni outil de mesure d'audience, ni géolocalisation, et n'accède ni à vos contacts ni à votre appareil photo (les photos sont choisies volontairement par la direction).</p>
<h2>Utilisation des données</h2>
<p>Les données servent uniquement au fonctionnement du club : connexion à votre compte, organisation des matchs et des entraînements, communication des annonces, présentation de l'effectif et de l'histoire du club. Elles ne sont <b>jamais vendues</b> ni cédées à des tiers à des fins commerciales.</p>
<h2>Qui voit quoi</h2>
<ul>
<li>Le numéro de téléphone d'un supporter n'est visible que par l'administrateur du club.</li>
<li>Les supporters voient l'effectif (nom, poste, numéro, photo) mais jamais les coordonnées, dates de naissance ou cotisations des joueurs.</li>
<li>Un joueur ne voit que ses propres demandes d'absence.</li>
<li>Les finances ne sont visibles que par l'administrateur.</li>
</ul>
<h2>Hébergement et sécurité</h2>
<p>Les données sont transmises de façon chiffrée (HTTPS) et hébergées par des prestataires techniques (Render pour l'application, Neon pour la base de données), qui les stockent pour le compte du club. Les données sont conservées tant que le compte existe.</p>
<h2 id="suppression">Supprimer votre compte et vos données</h2>
<div class="box">
<p><b>Supporters :</b> dans l'application, touchez votre nom en haut de l'écran, puis <b>« Supprimer mon compte fan »</b>. Votre compte, votre nom et votre numéro sont effacés immédiatement.</p>
<p><b>Joueurs, dirigeants, ou si vous n'avez plus accès à l'application :</b> demandez la suppression ${contact}, en indiquant votre nom et votre numéro de téléphone ou identifiant. La demande est traitée sous 30 jours ; le compte et les données personnelles associées sont supprimés. Les résultats sportifs anonymes du club peuvent être conservés.</p>
</div>
<h2>Vos droits</h2>
<p>Vous pouvez à tout moment demander l'accès, la correction ou la suppression de vos données ${contact}.</p>
<h2>Mineurs</h2>
<p>Les comptes des joueurs mineurs sont créés par la direction du club, avec l'accord de leurs parents ou tuteurs.</p>
<p style="margin-top:32px"><small>Dernière mise à jour : ${new Date().toLocaleDateString("fr-FR", { year: "numeric", month: "long", day: "numeric" })}</small></p>
<p><a href="/">← Retour à l'application</a></p>
</body></html>`;
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" });
  res.end(html);
}

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

async function pushHooks(col, old, d, user) {
  const s = (await store.get("settings", "club")) || {}; const nom = s.nom || "AFM";
  if (col === "annonces" && !old) {
    const ids = await usersWhere(u => u.id !== user.id && (d.public === true || u.role !== "fan"));
    notify(ids, { title: `${d.priorite === "Urgent" ? "🚨" : "📢"} ${d.titre || "Nouvelle annonce"}`, body: String(d.message || "").slice(0, 140), url: "/#annonces" });
  }
  if (col === "decisions" && d.compteId && (!old || old.statut !== d.statut)) {
    notify([d.compteId], { title: d.statut === "Acceptée" ? "✅ Absence acceptée" : "❌ Absence refusée", body: d.commentaire ? `« ${d.commentaire} »` : "La direction a répondu à votre demande.", url: "/#absences" });
  }
  if (col === "matches" && old) {
    const pour = +d.butsPour || 0, contre = +d.butsContre || 0, oPour = +old.butsPour || 0, oContre = +old.butsContre || 0;
    const k = kickoffUtc(d), live = k && Date.now() >= k - 10 * 60000 && Date.now() - k < 150 * 60000 && !old.fin;
    if (live && (pour > oPour || contre > oContre)) {
      const g = (d.buts || [])[(d.buts || []).length - 1];
      const p = pour > oPour && g && g.playerId && g.playerId !== "csc" ? await store.get("players", g.playerId) : null;
      notify(await usersWhere(() => true), { title: pour > oPour ? `⚽ BUUUT ${nom} ! ${pour} - ${contre}` : `⚽ But de ${d.adversaire} : ${nom} ${pour} - ${contre}`, body: pour > oPour ? (p ? `${p.prenom} ${p.nom}${g.minute ? " (" + g.minute + "')" : ""}` : "Allez l'AFM !") : "Courage les gars !", url: "/#calendrier", tag: "match-" + d.id });
    }
    if (d.fin && !old.fin) {
      const flags = (await store.get("config", "pushflags")) || {}; flags["f:" + d.id] = 1; await store.put("config", "pushflags", flags);
      notify(await usersWhere(() => true), { title: `🏁 Fin du match : ${nom} ${pour} - ${contre} ${d.adversaire}`, body: pour > contre ? "Victoire ! Merci pour votre soutien 💙" : "Merci pour votre soutien !", url: "/#calendrier", tag: "match-" + d.id });
    }
  }
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
  if (seg[0] === "push") {
    if (m === "GET" && seg[1] === "key") return send(res, 200, { key: VAPID.publicKey });
    if (m === "POST" && seg[1] === "subscribe") {
      const b = await readBody(req, 1e4); const ep = String(b.endpoint || "");
      if (!pushHostOk(ep)) return fail(res, 400, "Service de notification non reconnu par ce téléphone");
      const id = crypto.createHash("sha256").update(ep).digest("hex").slice(0, 40);
      await store.put("push", id, { userId: user.id, endpoint: ep, createdAt: new Date().toISOString() });
      return send(res, 200, { ok: true });
    }
    if (m === "POST" && seg[1] === "unsubscribe") {
      const b = await readBody(req, 1e4); const id = crypto.createHash("sha256").update(String(b.endpoint || "")).digest("hex").slice(0, 40);
      const sub = await store.get("push", id); if (sub && sub.userId === user.id) await store.del("push", id);
      return send(res, 200, { ok: true });
    }
    if (m === "GET" && seg[1] === "inbox") {
      const items = await withLock("pushq:" + user.id, async () => { const q = await store.get("pushq", user.id); if (!q || !(q.items || []).length) return []; await store.put("pushq", user.id, { items: [] }); return q.items; });
      return send(res, 200, { items });
    }
    if (m === "POST" && seg[1] === "test") { notify([user.id], { title: "✅ Notifications activées", body: "Vous recevrez ici les nouvelles de l'AFM.", url: "/" }); return send(res, 200, { ok: true }); }
  }
  if (m === "GET" && seg[0] === "state") return send(res, 200, { user: publicUser(user), ...(await stateFor(user)) });

  if (m === "POST" && seg[0] === "password") {
    const b = await readBody(req);
    if (!checkPassword(String(b.ancien || ""), user.passHash)) return fail(res, 400, "Mot de passe actuel incorrect");
    if (String(b.nouveau || "").length < 6) return fail(res, 400, "Le nouveau mot de passe doit contenir au moins 6 caractères");
    const u = { ...user, passHash: hashPassword(String(b.nouveau)), tokenVersion: (user.tokenVersion || 0) + 1 }; delete u.id;
    await store.put("users", user.id, u);
    return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, makeToken({ ...u, id: user.id }), SESSION_DAYS * 86400) });
  }

  // Messagerie : le joueur écrit à la direction / marque comme lu
  if (seg[0] === "messages" && seg[1] === "moi" && user.role === "joueur") {
    if (m === "POST" && !seg[2]) {
      const b = await readBody(req, 2e4);
      const text = String(b.texte || "").trim().slice(0, 2000);
      if (!text) return fail(res, 400, "Message vide");
      if (limited("msg:" + user.id, 60, 60 * 60e3)) return fail(res, 429, "Trop de messages, patientez un peu");
      hit("msg:" + user.id);
      const f = await withLock("fil:" + user.id, async () => {
        const f = await fil(user.id); const now = new Date().toISOString();
        f.messages = [...(f.messages || []), { id: newId(), de: "joueur", auteur: user.nom || user.username, texte: text, date: now }].slice(-MAX_MESSAGES);
        f.dernier = now; f.readJoueur = now; f.playerId = user.playerId || "";
        const { id, ...body } = f; await store.put("fils", user.id, body); return { ...body, id: user.id };
      });
      notify(await staffIds(), { title: `💬 Message de ${user.nom || user.username}`, body: text.slice(0, 140), url: "/#messages", tag: "msg-" + user.id });
      return send(res, 200, { fil: f });
    }
    if (m === "POST" && seg[2] === "lu") {
      await withLock("fil:" + user.id, async () => { const f = await store.get("fils", user.id); if (!f) return; const { id, ...body } = f; body.readJoueur = new Date().toISOString(); await store.put("fils", user.id, body); });
      return send(res, 200, { ok: true });
    }
  }

  // Boîte à idées : un fan envoie une suggestion
  if (m === "POST" && seg[0] === "suggestions" && !seg[1] && user.role === "fan") {
    if (limited("sugg:" + user.id, 10, 24 * 3600e3)) return fail(res, 429, "Vous avez déjà envoyé beaucoup de suggestions aujourd'hui. Merci, réessayez demain !");
    const b = await readBody(req, 2e4);
    const texte = String(b.texte || "").trim().slice(0, 2000);
    const cats = ["Matchs et ambiance", "Communication", "Maillots et boutique", "Événements", "Club et formation", "Autre"];
    if (texte.length < 5) return fail(res, 400, "Écrivez votre suggestion (5 caractères minimum)");
    hit("sugg:" + user.id);
    const id = newId();
    const s = { userId: user.id, nom: user.nom || "Supporter", telephone: user.telephone || "", categorie: cats.includes(b.categorie) ? b.categorie : "Autre", texte, date: new Date().toISOString(), statut: "Nouvelle" };
    await store.put("suggestions", id, s);
    notify(await staffIds(), { title: `💡 Nouvelle idée de ${s.nom}`, body: texte.slice(0, 140), url: "/#idees" });
    return send(res, 200, { ok: true, suggestion: { id, categorie: s.categorie, texte, date: s.date } });
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
    const nouvelles = demandes.filter(d => !before.some(x => x.id === d.id));
    if (nouvelles.length) notify(await staffIds(), { title: `📋 Absence déclarée : ${user.nom || user.username}`, body: `${nouvelles[0].type} · ${nouvelles[0].date} · ${nouvelles[0].motif}`, url: "/#demandes" });
    return send(res, 200, { ok: true, demandes });
  }

  // ---- Administration et dirigeants ----
  if (!staff) return fail(res, 403, "Accès réservé à la direction du club");

  // Messagerie : la direction écrit à un joueur / marque comme lu
  if (seg[0] === "messages" && validId(seg[1]) && seg[1] !== "moi") {
    const target = await store.get("users", seg[1]);
    if (!target || target.role !== "joueur") return fail(res, 404, "Ce joueur n'a pas de compte d'accès");
    if (m === "POST" && !seg[2]) {
      const b = await readBody(req, 2e4);
      const text = String(b.texte || "").trim().slice(0, 2000);
      if (!text) return fail(res, 400, "Message vide");
      const f = await withLock("fil:" + target.id, async () => {
        const f = await fil(target.id); const now = new Date().toISOString();
        f.messages = [...(f.messages || []), { id: newId(), de: "staff", auteurId: user.id, auteur: user.nom || user.username, texte: text, date: now }].slice(-MAX_MESSAGES);
        f.dernier = now; f.readStaff = now; f.playerId = target.playerId || "";
        const { id, ...body } = f; await store.put("fils", target.id, body); return { ...body, id: target.id };
      });
      notify([target.id], { title: `💬 ${user.nom || "La direction"} (AFM)`, body: text.slice(0, 140), url: "/#messages", tag: "msg" });
      return send(res, 200, { fil: f });
    }
    if (m === "POST" && seg[2] === "lu") {
      await withLock("fil:" + target.id, async () => { const f = await store.get("fils", target.id); if (!f) return; const { id, ...body } = f; body.readStaff = new Date().toISOString(); await store.put("fils", target.id, body); });
      return send(res, 200, { ok: true });
    }
  }

  // Boîte à idées : la direction classe ou supprime
  if (seg[0] === "suggestions" && validId(seg[1])) {
    const s = await store.get("suggestions", seg[1]);
    if (!s) return fail(res, 404, "Suggestion introuvable");
    if (m === "PUT") {
      const b = await readBody(req);
      const statuts = ["Nouvelle", "Lue", "Retenue", "Archivée"];
      if (!statuts.includes(b.statut)) return fail(res, 400, "Statut invalide");
      const { id, ...body } = s; body.statut = b.statut;
      await store.put("suggestions", seg[1], body);
      return send(res, 200, { ok: true });
    }
    if (m === "DELETE") { await store.del("suggestions", seg[1]); return send(res, 200, { ok: true }); }
  }

  // IA : création d'une séance d'entraînement (ou d'un exercice) avec schémas tactiques
  if (m === "POST" && seg[0] === "ia" && seg[1] === "seance") {
    if (!AI_KEY) return fail(res, 503, "L'IA n'est pas encore activée : ajoutez la variable ANTHROPIC_API_KEY sur Render.");
    if (limited("ia-s:" + user.id, 20, 60 * 60e3)) return fail(res, 429, "Limite d'utilisation de l'IA atteinte pour l'heure, réessayez plus tard");
    const b = await readBody(req, 3e4);
    const t = (v, n = 300) => String(v ?? "").replace(/[\r\n]+/g, " ").trim().slice(0, n);
    const un = b.mode === "exercice";
    hit("ia-s:" + user.id);
    const prompt = `Tu es un entraîneur de football diplômé (licence CAF/UEFA), spécialiste de la formation des jeunes, au service du club AFM (Afrique Football Management, club de formation à Bamako, Mali). Tu conçois des ${un ? "exercices" : "séances"} d'entraînement concrets, réalistes et adaptés au niveau, en français simple.

DEMANDE DU COACH
- Objectif : ${t(b.objectif) || "à définir selon la catégorie"}
- Catégorie : ${t(b.categorie, 40) || "Seniors"} · Niveau : ${t(b.niveau, 40) || "intermédiaire"}
- ${un ? `Partie de séance : ${t(b.partie, 40) || "Partie principale"} · Durée de l'exercice : ${Number(b.duree) || 20} min` : `Durée totale : ${Number(b.duree) || 90} min`}
- Nombre de joueurs disponibles : ${t(b.joueurs, 40) || "18"} (dont gardiens : ${t(b.gardiens, 10) || "2"})
- Matériel disponible : ${t(b.materiel) || "plots, ballons, chasubles, mini-buts"}
${b.consigne ? `- Précisions du coach : ${t(b.consigne, 500)}` : ""}
${b.existants ? `- Exercices déjà prévus dans la séance (à ne pas répéter) : ${t(b.existants, 600)}` : ""}

SCHÉMAS : pour chaque exercice, dessine un schéma tactique avec des coordonnées en mètres.
- "terrain" : "entier" (105 x 68, x de 0 à 105, y de 0 à 68), "demi" (52.5 x 68 ; le but attaqué est à droite en x=52.5, y=34 ; la ligne médiane est en x=0) ou "zone" (40 x 30, pour les petits espaces, rondos, ateliers).
- "items" : éléments placés. Types :
  - "j" joueur AFM, "a" adversaire, "g" gardien : {"t":"j","x":..,"y":..,"n":"1"} (n = numéro court, 1 à 2 caractères)
  - "plot" : {"t":"plot","x":..,"y":..} ; "ballon" : {"t":"ballon","x":..,"y":..} ; "but" (mini-but) : {"t":"but","x":..,"y":..}
  - flèches : "course" (déplacement sans ballon), "conduite" (déplacement avec ballon), "passe", "tir" : {"t":"passe","x":..,"y":..,"x2":..,"y2":..,"e":1}
    "e" = numéro d'étape de l'animation (1, 2, 3…) : les flèches de même étape se jouent en même temps, puis l'étape suivante. Une passe part du joueur qui a le ballon (le ballon est posé à ses pieds au départ, décalé de 1 m). Une course ou une conduite part exactement de la position d'un joueur.
  - "zone" : rectangle {"t":"zone","x":..,"y":..,"x2":..,"y2":..} ; "texte" : {"t":"texte","x":..,"y":..,"n":"Zone 1"} (court)
- Reste dans les limites du terrain, espace les joueurs d'au moins 3 m, 6 à 22 éléments par schéma, 2 à 6 étapes de flèches cohérentes (enchaînement logique de l'action).

Réponds UNIQUEMENT avec un objet JSON valide, sans texte autour :
${un ? `{"exercice": EXERCICE}` : `{"objectif":"objectif de la séance en une phrase","materiel":"matériel total","exercices":[EXERCICE, ...]}`}
avec EXERCICE = {"partie":"Échauffement|Partie principale|Jeu / match|Retour au calme","titre":"…","duree":15,"joueurs":"ex. 10 (5 contre 5)","espace":"ex. 30 x 20 m","materiel":"…","objectif":"…","description":"organisation et déroulement en 2 à 4 phrases","consignes":"3 à 5 consignes, une par ligne","variantes":"1 ou 2 progressions","schema":{"terrain":"…","items":[…]}}
${un ? "" : `La séance contient 4 à 6 exercices dans l'ordre : un échauffement avec ballon, 1 à 3 exercices de partie principale progressifs vers l'objectif, un jeu / match à thème, un retour au calme court. La somme des durées est d'environ ${Number(b.duree) || 90} minutes.`}`;
    const txt = await askClaude(prompt, un ? 2500 : 9000, 120000);
    const mj = txt.match(/\{[\s\S]*\}/);
    let out; try { out = JSON.parse(mj ? mj[0] : txt); } catch { return fail(res, 502, "L'IA a renvoyé une réponse illisible, réessayez."); }
    const TER = { entier: [105, 68], demi: [52.5, 68], zone: [40, 30] };
    const PARTS = ["Échauffement", "Partie principale", "Jeu / match", "Retour au calme"];
    const TYPES = ["j", "a", "g", "plot", "ballon", "but", "course", "passe", "conduite", "tir", "zone", "texte"];
    const num = (v, max) => Math.round(Math.max(0, Math.min(max, Number(v) || 0)) * 10) / 10;
    const cleanEx = e => {
      if (!isObj(e)) return null;
      const sc = isObj(e.schema) ? e.schema : {}; const ter = TER[sc.terrain] ? sc.terrain : "demi"; const [W, H] = TER[ter];
      const items = (Array.isArray(sc.items) ? sc.items : []).filter(i => isObj(i) && TYPES.includes(i.t)).slice(0, 40).map(i => {
        const o = { id: newId(), t: i.t, x: num(i.x, W), y: num(i.y, H) };
        if (["course", "passe", "conduite", "tir", "zone"].includes(i.t)) { o.x2 = num(i.x2, W); o.y2 = num(i.y2, H); }
        if (["course", "passe", "conduite", "tir"].includes(i.t)) o.e = Math.max(1, Math.min(20, Math.round(Number(i.e) || 1)));
        if (["j", "a", "g", "texte"].includes(i.t) && i.n != null) o.n = String(i.n).slice(0, i.t === "texte" ? 30 : 3);
        return o;
      });
      const c = (v, n) => String(v ?? "").trim().slice(0, n);
      return { id: newId(), partie: PARTS.includes(e.partie) ? e.partie : "Partie principale", titre: c(e.titre, 80), duree: Math.max(0, Math.min(120, Math.round(Number(e.duree) || 0))), joueurs: c(e.joueurs, 40), espace: c(e.espace, 40), materiel: c(e.materiel, 120), objectif: c(e.objectif, 400), description: c(e.description, 1200), consignes: c(e.consignes, 1200), variantes: c(e.variantes, 600), schema: { terrain: ter, items }, ia: true };
    };
    if (un) { const ex = cleanEx(out.exercice || out); if (!ex) return fail(res, 502, "L'IA n'a pas proposé d'exercice, réessayez."); return send(res, 200, { exercice: ex }); }
    const exs = (Array.isArray(out.exercices) ? out.exercices : []).slice(0, 8).map(cleanEx).filter(Boolean);
    if (!exs.length) return fail(res, 502, "L'IA n'a pas proposé de séance, réessayez.");
    return send(res, 200, { objectif: String(out.objectif || "").slice(0, 300), materiel: String(out.materiel || "").slice(0, 300), exercices: exs });
  }

  // IA : textes d'une affiche de match
  if (m === "POST" && seg[0] === "ia" && seg[1] === "affiche") {
    if (!AI_KEY) return fail(res, 503, "L'IA n'est pas encore activée : ajoutez la variable ANTHROPIC_API_KEY sur Render.");
    if (limited("ia:" + user.id, 40, 60 * 60e3)) return fail(res, 429, "Limite d'utilisation de l'IA atteinte pour l'heure, réessayez plus tard");
    const b = await readBody(req, 2e4);
    const s = (await store.get("settings", "club")) || {};
    const pres = await getPresentation();
    const t = v => String(v ?? "").replace(/[\r\n]+/g, " ").slice(0, 200);
    const tons = { motivant: "motivant et fier", festif: "festif et populaire", officiel: "sobre et officiel", choc: "percutant, ambiance grand match" };
    const resultat = b.butsPour !== "" && b.butsPour != null && b.butsContre !== "" && b.butsContre != null;
    hit("ia:" + user.id);
    const prompt = `Tu es le community manager du club de football ${t(s.nom || "AFM")} (Afrique Football Management), club de formation fondé en 2021 à Bamako, Mali${pres.slogan ? `, slogan « ${t(pres.slogan)} »` : ""}. Les supporters sont maliens : écris en français simple et chaleureux, tu peux glisser une touche malienne avec mesure.
Rédige les textes d'une AFFICHE ${resultat ? "de RÉSULTAT" : "d'annonce"} pour ce match :
- Adversaire : ${t(b.adversaire)}
- Compétition : ${t(b.competition) || "Match"}
- Date : ${t(b.date)}${b.heure ? " à " + t(b.heure) : ""}
- Lieu : ${t(b.lieu)}${b.stade ? " (" + t(b.stade) + ")" : ""}
${resultat ? `- Score final : ${t(s.nom || "AFM")} ${t(b.butsPour)} - ${t(b.butsContre)} ${t(b.adversaire)}${b.buteurs ? ` (buteurs : ${t(b.buteurs)})` : ""}` : ""}
${b.joueur ? `- Joueur mis en avant sur l'affiche : ${t(b.joueur)}` : ""}
${b.consigne ? `- Consigne de la direction : ${t(b.consigne)}` : ""}
Ton souhaité : ${tons[b.ton] || tons.motivant}.
Réponds UNIQUEMENT avec un objet JSON valide, sans texte autour, de la forme :
{"accroche":"titre principal de l'affiche, 2 à 5 mots, percutant","sousTitre":"une phrase courte de 4 à 9 mots","legende":"publication pour Facebook/WhatsApp de 2 à 4 phrases avec 2 ou 3 emojis, rappelant les infos pratiques, puis 3 à 5 hashtags dont #AFM"}
N'invente aucune information (pas de prix, de sponsor ou de joueur non mentionnés).`;
    const txt = await askClaude(prompt);
    const mjson = txt.match(/\{[\s\S]*\}/);
    let out; try { out = JSON.parse(mjson ? mjson[0] : txt); } catch { return fail(res, 502, "L'IA a renvoyé une réponse illisible, réessayez."); }
    const cut = (v, n) => String(v || "").trim().slice(0, n);
    return send(res, 200, { accroche: cut(out.accroche, 60), sousTitre: cut(out.sousTitre, 100), legende: cut(out.legende, 1500) });
  }

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
      pushHooks(seg[1], old, { ...data, id: seg[2] }, user).catch(e => console.error("Push :", e.message));
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

  // Restaurer une sauvegarde (fichier copié depuis Paramètres → Données)
  if (m === "POST" && seg[0] === "import") {
    const b = await readBody(req, 15e6);
    const d = isObj(b.data) ? b.data : null;
    if (!d) return fail(res, 400, "Sauvegarde illisible : vérifiez que vous avez collé tout le texte copié.");
    const counts = {};
    const mediaOk = async id => validId(id) && !!(await store.getMedia(id));
    const photosPerdues = { n: 0 };
    for (const col of DATA_COLS) {
      const arr = Array.isArray(d[col]) ? d[col] : [];
      let n = 0;
      for (const it of arr) {
        if (!isObj(it) || !validId(it.id)) continue;
        const { id, ...body } = it;
        if (body.photo && !(await mediaOk(body.photo))) { photosPerdues.n++; if (col === "galerie") continue; body.photo = ""; }
        await store.put(col, id, body); n++;
      }
      if (n) counts[col] = n;
    }
    if (isObj(d.settings)) { const st = d.settings; await store.put("settings", "club", { nom: clean(st.nom).slice(0, 80) || "AFM", saison: clean(st.saison).slice(0, 30), stade: clean(st.stade).slice(0, 120), devise: clean(st.devise).slice(0, 10) || "FCFA", cotisation: Number(st.cotisation) || 0, fansOuverts: st.fansOuverts !== false }); counts.parametres = 1; }
    if (isObj(d.presentation) && Object.keys(d.presentation).length) {
      const p = cleanPresentation(d.presentation);
      for (const k of PRES_PHOTOS) if (p[k] && !(await mediaOk(p[k]))) { p[k] = ""; photosPerdues.n++; }
      await store.put("presentation", "club", p); counts.presentation = 1;
    }
    // Comptes d'accès (direction, joueurs, supporters) : recréés avec un mot de passe provisoire
    const existing = await store.all("users");
    const identifiants = [];
    const okUsers = new Set(existing.map(u => u.id));
    for (const u of Array.isArray(d.users) ? d.users : []) {
      if (!isObj(u) || !validId(u.id) || !ROLES.includes(u.role)) continue;
      const phone = u.telephone ? normalizePhone(u.telephone) : "";
      const username = u.role === "fan" ? (phone || "") : clean(u.username).toLowerCase();
      if (!/^[a-z0-9._-]{3,32}$/.test(username)) continue;
      if (existing.some(x => x.id === u.id || x.username === username || (u.role === "fan" && phone && x.telephone === phone))) continue;
      const pw = crypto.randomBytes(6).toString("base64url").replace(/[-_]/g, "x").slice(0, 8);
      await store.put("users", u.id, { username, nom: clean(u.nom).slice(0, 80), role: u.role, telephone: phone && !existing.some(x => x.telephone === phone) ? phone : "", playerId: u.role === "joueur" && validId(u.playerId) ? u.playerId : "", passHash: hashPassword(pw), tokenVersion: 0, createdAt: new Date().toISOString() });
      existing.push({ id: u.id, username, telephone: phone });
      okUsers.add(u.id); identifiants.push({ username, nom: u.nom || "", role: u.role, telephone: phone || "", password: pw });
    }
    if (identifiants.length) counts.comptes_acces = identifiants.length;
    let nd = 0;
    for (const c of Array.isArray(d.comptes) ? d.comptes : []) {
      if (!isObj(c) || !validId(c.id) || !okUsers.has(c.id) || !Array.isArray(c.demandes) || !c.demandes.length) continue;
      await store.put("comptes", c.id, { playerId: validId(c.playerId) ? c.playerId : "", demandes: c.demandes.filter(x => isObj(x) && validId(x.id)).slice(0, 500) }); nd++;
    }
    if (nd) counts.demandes_absence = nd;
    return send(res, 200, { ok: true, counts, identifiants, photosPerdues: photosPerdues.n });
  }

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
/* ------------------------------------------------------------------ */
/* Notifications push (Web Push + VAPID, sans dépendance externe)       */
/* ------------------------------------------------------------------ */
// Principe : on envoie une notification « vide » au service de push du téléphone ;
// le téléphone réveille l'application, qui vient chercher le contenu sur /api/push/inbox.
const b64u = buf => Buffer.from(buf).toString("base64url");
let VAPID = null;
async function initPush() {
  let v = await store.get("config", "vapid");
  if (!v || !v.privateJwk) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const jwk = privateKey.export({ format: "jwk" });
    const pub = publicKey.export({ format: "jwk" });
    const raw = Buffer.concat([Buffer.from([4]), Buffer.from(pub.x, "base64url"), Buffer.from(pub.y, "base64url")]);
    v = { privateJwk: jwk, publicKey: b64u(raw) };
    await store.put("config", "vapid", v);
  }
  VAPID = { key: crypto.createPrivateKey({ key: v.privateJwk, format: "jwk" }), publicKey: v.publicKey };
}
const PUSH_HOSTS = [/\.googleapis\.com$/, /(^|\.)push\.services\.mozilla\.com$/, /\.push\.apple\.com$/, /\.notify\.windows\.com$/, /(^|\.)push\.hicloud\.com$/];
const pushHostOk = u => { try { const x = new URL(u); if (process.env.PUSH_ALLOW_LOCAL === "1" && x.hostname === "localhost") return true; return x.protocol === "https:" && PUSH_HOSTS.some(r => r.test(x.hostname)); } catch { return false; } };
function vapidJwt(aud) {
  const head = b64u(JSON.stringify({ typ: "JWT", alg: "ES256" }));
  const body = b64u(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: process.env.PUSH_CONTACT || "mailto:contact@afm-club.app" }));
  const sig = crypto.sign("sha256", Buffer.from(head + "." + body), { key: VAPID.key, dsaEncoding: "ieee-p1363" });
  return head + "." + body + "." + b64u(sig);
}
async function sendPush(sub) {
  const aud = new URL(sub.endpoint).origin;
  const r = await fetch(sub.endpoint, { method: "POST", headers: { TTL: "86400", Urgency: "high", "Content-Length": "0", Authorization: `vapid t=${vapidJwt(aud)}, k=${VAPID.publicKey}` }, signal: AbortSignal.timeout(15000) });
  if (r.status === 404 || r.status === 410) await store.del("push", sub.id);
  return r.status;
}
/** Envoie une notification à une liste d'utilisateurs (ne bloque jamais la réponse) */
function notify(userIds, n) {
  const ids = [...new Set(userIds.filter(Boolean))]; if (!ids.length) return;
  (async () => {
    const subs = await store.all("push");
    for (const uid of ids) {
      await withLock("pushq:" + uid, async () => {
        const q = (await store.get("pushq", uid)) || { items: [] };
        const items = [...(q.items || []), { id: newId(), title: String(n.title).slice(0, 80), body: String(n.body || "").slice(0, 200), url: n.url || "/", tag: n.tag || "", date: new Date().toISOString() }].slice(-20);
        await store.put("pushq", uid, { items });
      });
      for (const sub of subs.filter(x => x.userId === uid)) { try { await sendPush(sub); } catch (e) { /* téléphone injoignable : on réessaiera au prochain événement */ } }
    }
  })().catch(e => console.error("Push :", e.message));
}
const usersWhere = async pred => (await store.all("users")).filter(u => !u.disabled && pred(u)).map(u => u.id);
const staffIds = () => usersWhere(isStaff);
// Coups d'envoi et fins de match automatiques (vérifiés chaque minute, heure du Mali = UTC)
const TZ_OFFSET_MIN = Number(process.env.TZ_OFFSET_MIN || 0);
const kickoffUtc = m => m.date && m.heure && /^\d{2}:\d{2}$/.test(m.heure) ? Date.parse(`${m.date}T${m.heure}:00Z`) - TZ_OFFSET_MIN * 60000 : null;
async function matchTicker() {
  try {
    const s = (await store.get("settings", "club")) || {}; const nom = s.nom || "AFM";
    const flags = (await store.get("config", "pushflags")) || {}; let changed = false; const now = Date.now();
    for (const m of await store.all("matches")) {
      if (m.statut === "Reporté" || m.statut === "Annulé") continue;
      const k = kickoffUtc(m); if (!k) continue;
      if (now >= k && now - k < 15 * 60000 && !flags["d:" + m.id]) { flags["d:" + m.id] = 1; changed = true; notify(await usersWhere(() => true), { title: `🔴 Coup d'envoi : ${nom} - ${m.adversaire}`, body: `Le match commence ! Suivez le score en direct dans l'application.`, url: "/#calendrier", tag: "match-" + m.id }); }
      const end = m.fin ? Date.parse(m.fin) : k + 120 * 60000;
      if (now >= end && now - end < 30 * 60000 && !flags["f:" + m.id]) { flags["f:" + m.id] = 1; changed = true;
        const sc = m.butsPour !== "" && m.butsPour != null ? ` : ${nom} ${m.butsPour} - ${m.butsContre || 0} ${m.adversaire}` : "";
        notify(await usersWhere(() => true), { title: `🏁 Fin du match${sc}`, body: sc ? "Merci pour votre soutien !" : `${nom} - ${m.adversaire} est terminé.`, url: "/#calendrier", tag: "match-" + m.id }); }
    }
    if (changed) await store.put("config", "pushflags", flags);
  } catch (e) { console.error("Ticker :", e.message); }
}

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
    if (pathname === "/.well-known/assetlinks.json") return send(res, 200, assetLinks(), { "Cache-Control": "public, max-age=300" });
    if (pathname === "/confidentialite" || pathname === "/confidentialite/" || pathname === "/suppression-compte") return await privacyPage(req, res);
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
  await initPush();
  setInterval(matchTicker, 60000);
  server.listen(PORT, () => console.log(`AFM en ligne sur le port ${PORT} (stockage : ${store.kind})`));
})().catch(e => { console.error("Démarrage impossible :", e); process.exit(1); });
