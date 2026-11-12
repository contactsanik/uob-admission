/**
 * UOB Admission Hub — Backend v1
 * Cloudflare Workers + D1. Single file, no dependencies.
 *
 * Ja kore:
 *   - Hub-er inquiry form theke asha message D1-te save kore
 *     (status 'new'), ar admin panel theke dekha / status bodlano /
 *     reply note lekha jay.
 *   - Form ta WhatsApp-eo jay (oita website-er code-e, public/index.html),
 *     kintu backend shudhu website-er copy-ta rakhe.
 *
 * ⚠️ SOTTO KOTHA (honest limit):
 *   Admin panel-er reply-note ta HATE likhte hoy. WhatsApp chat-e
 *   je reply diben, oita admin panel-e APNE APNI asbe NA — wa.me
 *   link diye WhatsApp-er reply sync kora jay na. Oitar jonno
 *   WhatsApp Business API lage, oita ei v1-er baire.
 *
 * Endpoints:
 *   GET   /api/health
 *   POST  /api/enquiry                     {name, phone, program, ssc_gpa, hsc_gpa, honours_cgpa, message}
 *   POST  /api/admin/login                 {email, password} -> session token
 *   POST  /api/admin/logout                (admin)
 *   GET   /api/admin/me                    (admin — session check)
 *   GET   /api/admin/enquiries?status=&limit=   (admin)
 *   PATCH /api/admin/enquiries/:id         {status, reply_note} (admin)
 *   GET   /admin  (embedded admin panel)
 *   GET   /       (public/index.html — ASSETS theke, na pele embedded copy)
 *
 * Setup — secrets, NEVER write real values in wrangler.toml:
 *   npx wrangler d1 create uob_admission_hub
 *   npx wrangler d1 execute uob_admission_hub --file=./migrations/0001_enquiries.sql --remote
 *   npx wrangler secret put ADMIN_EMAIL      (tomar login email — tumi thik korba)
 *   npx wrangler secret put ADMIN_PASSWORD   (tomar login password — tumi thik korba)
 *   npx wrangler secret put RESEND_API_KEY   (optional — email notification chaile)
 * Deploy: npx wrangler deploy
 * Local:  npx wrangler dev
 */

const STATUSES = new Set(["new", "replied", "done"]);

// --- Helpers ---
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}

function securityHeaders(headers = {}) {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "SAMEORIGIN",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    ...headers,
  };
}

// CORS: Hub ta GitHub Pages-e thake (contactsanik.github.io),
// tai POST /api/enquiry oi origin theke aste dite hobe.
// Onno kono site theke ashle browser block korbe.
function allowedOrigin(request, env) {
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  const allowed = new Set([
    env.ALLOWED_ORIGIN,
    "https://contactsanik.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8787",
    "http://127.0.0.1:8787",
  ]);
  return allowed.has(origin) ? origin : "null";
}

function corsHeaders(request, env) {
  const origin = allowedOrigin(request, env);
  if (origin === null) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
}

function clean(value, maxLength) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

// --- Auth: email + password login, D1 sessions (v8 template-er moto) ---
// Admin user ashe secrets ADMIN_EMAIL ar ADMIN_PASSWORD theke.
// Login korle random session token toiri hoy, tar SHA-256 hash D1-te
// `sessions` table-e thake (7 din), ar raw token ekbar return hoy.
// Admin route gulo Bearer session token ney. Kono email / password
// code-e ba wrangler.toml-e lekha hoy na.
function timingSafeEqual(a, b) {
  const x = String(a || "");
  const y = String(b || "");
  const len = Math.max(x.length, y.length);
  let diff = x.length === y.length ? 0 : 1;
  for (let i = 0; i < len; i++) {
    const cx = i < x.length ? x.charCodeAt(i) : 0;
    const cy = i < y.length ? y.charCodeAt(i) : 0;
    diff |= cx ^ cy;
  }
  return diff === 0;
}

async function sha256Hex(text) {
  const data = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(String(text))
  );
  return [...new Uint8Array(data)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function ensureSessionsSchema(env) {
  if (!env.DB || typeof env.DB.prepare !== "function") return false;
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS sessions (" +
      "token_hash TEXT PRIMARY KEY, created_at TEXT NOT NULL, " +
      "expires_at TEXT NOT NULL)"
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)"
  ).run();
  return true;
}

function bearerToken(request) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return "";
  return auth.slice("Bearer ".length).trim();
}

async function getAdminIdentity(request, env) {
  const token = bearerToken(request);
  if (!token) return null;
  if (env.ADMIN_TOKEN && timingSafeEqual(token, env.ADMIN_TOKEN)) {
    return { via: "token", email: env.ADMIN_EMAIL || null };
  }
  if (env.DB && typeof env.DB.prepare === "function") {
    try {
      await ensureSessionsSchema(env);
      const hash = await sha256Hex(token);
      const row = await env.DB.prepare(
        "SELECT token_hash, expires_at FROM sessions WHERE token_hash = ?1"
      ).bind(hash).first();
      if (row && String(row.expires_at) > new Date().toISOString()) {
        return { via: "session", email: env.ADMIN_EMAIL || null };
      }
    } catch (e) {
      console.error("session check failed:", String((e && e.message) || e).slice(0, 120));
    }
  }
  return null;
}

async function requireAdmin(request, env) {
  const hasLogin = Boolean(env.ADMIN_EMAIL && env.ADMIN_PASSWORD);
  if (!hasLogin && !env.ADMIN_TOKEN) {
    return json(
      { error: "Admin login is not set up yet — set ADMIN_EMAIL and ADMIN_PASSWORD secrets" },
      503
    );
  }
  const identity = await getAdminIdentity(request, env);
  if (identity) return null;
  return json({ error: "Unauthorized" }, 401);
}

// Login rate limit: 10 attempts / minute / IP (best effort, per isolate).
const loginHits = new Map();
function loginRateLimited(ip) {
  const now = Date.now();
  const entry = loginHits.get(ip) || { count: 0, start: now };
  if (now - entry.start > 60_000) { entry.count = 0; entry.start = now; }
  entry.count += 1;
  loginHits.set(ip, entry);
  if (loginHits.size > 5000) loginHits.clear();
  return entry.count > 10;
}

// Enquiry rate limit: 5 / minute / IP (best effort, per isolate).
const hits = new Map();
function rateLimited(ip) {
  const now = Date.now();
  const entry = hits.get(ip) || { count: 0, start: now };
  if (now - entry.start > 60_000) { entry.count = 0; entry.start = now; }
  entry.count += 1;
  hits.set(ip, entry);
  if (hits.size > 5000) hits.clear();
  return entry.count > 5;
}

// --- D1 schema ---
// migrations/0001_enquiries.sql-eo eki table ache — oita ekbar
// wrangler d1 execute diye chalalei hobe. ensureSchema() protibar
// write-er ageo CREATE chalaye, tai migration vulte geleo prothom
// enquiry-tei table toiri hoye jabe.
const NEW_COLUMNS = ["ssc_gpa TEXT", "hsc_gpa TEXT", "honours_cgpa TEXT", "reply_note TEXT", "updated_at TEXT"];

async function ensureSchema(env) {
  if (!env.DB || typeof env.DB.prepare !== "function") return false;
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS enquiries (" +
      "id TEXT PRIMARY KEY, name TEXT NOT NULL, phone TEXT NOT NULL, " +
      "program TEXT NOT NULL, ssc_gpa TEXT, hsc_gpa TEXT, honours_cgpa TEXT, message TEXT, " +
      "status TEXT NOT NULL DEFAULT 'new', reply_note TEXT, " +
      "created_at TEXT NOT NULL, updated_at TEXT)"
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_enquiries_status ON enquiries(status)"
  ).run();
  await env.DB.prepare(
    "CREATE INDEX IF NOT EXISTS idx_enquiries_created ON enquiries(created_at DESC)"
  ).run();
  for (const col of NEW_COLUMNS) {
    const name = col.split(" ")[0];
    try {
      await env.DB.prepare("ALTER TABLE enquiries ADD COLUMN " + col).run();
    } catch (e) {
      if (!String((e && e.message) || e).includes("duplicate column")) {
        console.log("[D1] alter " + name + " skipped:", String((e && e.message) || e).slice(0, 120));
      }
    }
  }
  return true;
}

// --- Email via Resend (optional, free) ---
// RESEND_API_KEY secret thakle ar NOTIFY_EMAIL [vars]-e bosano thakle
// notun enquiry ashle email jabe. Na thakle email skip hobe —
// enquiry tobuo save hobe, ar reply-te ok:true asbe.
// NOTIFY_EMAIL-e kono email baniye bosano hoy nai — tumi nijer
// Resend account-er email-ta wrangler.toml-e bosaba.
async function sendEnquiryEmail(env, enquiry) {
  if (!env.RESEND_API_KEY) {
    return { status: "skipped", reason: "RESEND_API_KEY secret is not set" };
  }
  if (!env.NOTIFY_EMAIL || String(env.NOTIFY_EMAIL).includes("PASTE_YOUR")) {
    return { status: "skipped", reason: "NOTIFY_EMAIL is not set in wrangler.toml [vars]" };
  }
  const from = env.FROM_EMAIL || "onboarding@resend.dev";
  const subject = "UOB Admission Hub — notun inquiry: " + (enquiry.program || "") + " — " + (enquiry.name || "No name");
  const text = [
    "Program: " + enquiry.program,
    "Name: " + (enquiry.name || "-"),
    "Phone: " + (enquiry.phone || "-"),
    enquiry.sscGpa ? "SSC GPA: " + enquiry.sscGpa : null,
    enquiry.hscGpa ? "HSC GPA: " + enquiry.hscGpa : null,
    enquiry.honoursCgpa ? "Honours CGPA: " + enquiry.honoursCgpa : null,
    "",
    "Question:",
    enquiry.message || "-",
    "",
    "Enquiry ID: " + enquiry.id,
    "Time: " + enquiry.createdAt,
  ].filter((l) => l !== null).join("\n");
  const html =
    "<h2>UOB Admission Hub — notun inquiry</h2>" +
    "<p><b>Program:</b> " + escapeHtml(enquiry.program || "-") + "<br>" +
    "<b>Name:</b> " + escapeHtml(enquiry.name || "-") + "<br>" +
    "<b>Phone:</b> " + escapeHtml(enquiry.phone || "-") + "<br>" +
    (enquiry.sscGpa ? "<b>SSC GPA:</b> " + escapeHtml(enquiry.sscGpa) + "<br>" : "") +
    (enquiry.hscGpa ? "<b>HSC GPA:</b> " + escapeHtml(enquiry.hscGpa) + "<br>" : "") +
    (enquiry.honoursCgpa ? "<b>Honours CGPA:</b> " + escapeHtml(enquiry.honoursCgpa) + "<br>" : "") + "</p>" +
    "<p><b>Question:</b><br>" + escapeHtml(enquiry.message || "-").replaceAll("\n", "<br>") + "</p>" +
    "<p><small>Enquiry ID: " + escapeHtml(enquiry.id) + "<br>Time: " + escapeHtml(enquiry.createdAt) + "</small></p>";
  try {
    const res = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: "Bearer " + env.RESEND_API_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ from, to: [env.NOTIFY_EMAIL], subject, html, text }),
      signal: AbortSignal.timeout(8000),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = String(data.message || data.error || res.status).slice(0, 300);
      return { status: "failed", reason: "Resend " + res.status + ": " + msg };
    }
    return { status: "sent", reason: "", resendId: data.id || null };
  } catch (e) {
    return { status: "failed", reason: String((e && e.message) || e).slice(0, 300) };
  }
}

// --- Handlers ---
function handleHealth(env) {
  return json({
    status: "ok",
    name: "UOB Admission Hub",
    backend: "cloudflare-workers",
    version: "v1-enquiries",
    storage: { d1: Boolean(env.DB) },
    auth: { emailPassword: Boolean(env.ADMIN_EMAIL && env.ADMIN_PASSWORD) },
    email: {
      configured: Boolean(env.RESEND_API_KEY && env.NOTIFY_EMAIL && !String(env.NOTIFY_EMAIL).includes("PASTE_YOUR")),
      provider: "resend",
    },
    environment: env.ENVIRONMENT || "production",
    time: new Date().toISOString(),
  });
}

async function handleEnquiry(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (rateLimited(ip)) {
    return json({ error: "Too many enquiries. Please wait a minute and try again." }, 429);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Request body must be valid JSON" }, 400);
  }
  const name = clean(body.name, 80);
  const phone = clean(body.phone, 40);
  const program = clean(body.program, 120);
  const sscGpa = clean(body.ssc_gpa, 40);
  const hscGpa = clean(body.hsc_gpa, 40);
  const honoursCgpa = clean(body.honours_cgpa, 40);
  const message = clean(body.message, 2000);
  if (!name || !phone || !program) {
    return json({ error: "name, phone and program are required" }, 400);
  }
  const enquiry = {
    id: crypto.randomUUID(),
    name, phone, program, sscGpa, hscGpa, honoursCgpa, message,
    createdAt: new Date().toISOString(),
    source: "admission-hub",
  };

  // 1) SAVE FIRST — email kokhono enquiry harate parbe na.
  if (!env.DB || typeof env.DB.prepare !== "function") {
    return json({ error: "D1 database is not bound yet" }, 503);
  }
  try {
    await ensureSchema(env);
    await env.DB.prepare(
      "INSERT INTO enquiries " +
        "(id, name, phone, program, ssc_gpa, hsc_gpa, honours_cgpa, message, status, created_at, updated_at) " +
        "VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'new', ?9, ?9)"
    ).bind(enquiry.id, name, phone, program, sscGpa, hscGpa, honoursCgpa, message, enquiry.createdAt).run();
  } catch (err) {
    console.error("saveEnquiry failed:", err);
    return json({ error: "Could not save your enquiry. Please try WhatsApp instead." }, 500);
  }

  // 2) EMAIL SECOND (optional) — fail korleo enquiry save thakbe.
  const emailResult = await sendEnquiryEmail(env, enquiry);

  return json(
    {
      ok: true,
      id: enquiry.id,
      email: emailResult.status,
      emailNote:
        emailResult.status === "sent"
          ? "Email notification sent."
          : emailResult.status === "failed"
            ? "Email failed (" + emailResult.reason + "). Enquiry is still saved in D1."
            : "Email skipped (" + emailResult.reason + "). Enquiry is still saved in D1.",
      received: { name: enquiry.name, phone: enquiry.phone, program: enquiry.program },
    },
    201
  );
}

function enquiryRow(r) {
  if (!r) return null;
  return {
    id: r.id,
    name: r.name,
    phone: r.phone,
    program: r.program,
    sscGpa: r.ssc_gpa || "",
    hscGpa: r.hsc_gpa || "",
    honoursCgpa: r.honours_cgpa || "",
    message: r.message || "",
    status: r.status || "new",
    replyNote: r.reply_note || "",
    createdAt: r.created_at || null,
    updatedAt: r.updated_at || null,
  };
}

async function handleListEnquiries(request, env, url) {
  const authErr = await requireAdmin(request, env);
  if (authErr) return authErr;
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "100", 10) || 100, 1), 200);
  const status = (url.searchParams.get("status") || "").trim().toLowerCase();
  if (status && !STATUSES.has(status)) {
    return json({ error: "status must be new, replied or done" }, 400);
  }
  if (!env.DB || typeof env.DB.prepare !== "function") {
    return json({
      count: 0,
      enquiries: [],
      note: "No storage is bound yet. Create the D1 database and bind it in wrangler.toml (see README.md).",
    });
  }
  try {
    await ensureSchema(env);
    const where = [];
    const args = [];
    if (status) { where.push("status = ?" + (args.length + 1)); args.push(status); }
    const sql =
      "SELECT id, name, phone, program, ssc_gpa, hsc_gpa, honours_cgpa, message, status, " +
      "reply_note, created_at, updated_at FROM enquiries" +
      (where.length ? " WHERE " + where.join(" AND ") : "") +
      " ORDER BY created_at DESC LIMIT ?" + (args.length + 1);
    args.push(limit);
    const { results } = await env.DB.prepare(sql).bind(...args).all();
    const items = (results || []).map(enquiryRow);
    return json({ count: items.length, enquiries: items });
  } catch (err) {
    console.error("listEnquiries failed:", err);
    return json({ error: "Could not read enquiries" }, 500);
  }
}

async function handleUpdateEnquiry(request, env, id) {
  const authErr = await requireAdmin(request, env);
  if (authErr) return authErr;
  if (!env.DB || typeof env.DB.prepare !== "function") {
    return json({ error: "D1 database is not bound yet" }, 503);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Request body must be valid JSON" }, 400);
  }
  const hasStatus = body.status !== undefined && body.status !== null && body.status !== "";
  const hasNote = body.reply_note !== undefined && body.reply_note !== null;
  if (!hasStatus && !hasNote) {
    return json({ error: "Send at least one of: status, reply_note" }, 400);
  }
  const status = hasStatus ? String(body.status).trim().toLowerCase() : null;
  if (status !== null && !STATUSES.has(status)) {
    return json({ error: "status must be new, replied or done" }, 400);
  }
  const replyNote = hasNote ? clean(body.reply_note, 2000) : null;
  await ensureSchema(env);
  const sets = [];
  const args = [];
  if (status !== null) { sets.push("status = ?" + (args.length + 1)); args.push(status); }
  if (replyNote !== null) { sets.push("reply_note = ?" + (args.length + 1)); args.push(replyNote); }
  sets.push("updated_at = ?" + (args.length + 1));
  args.push(new Date().toISOString());
  const key = decodeURIComponent(id);
  const result = await env.DB.prepare(
    "UPDATE enquiries SET " + sets.join(", ") + " WHERE id = ?" + (args.length + 1)
  ).bind(...args, key).run();
  if (!result.meta || result.meta.changes === 0) {
    return json({ error: "Enquiry not found" }, 404);
  }
  const row = await env.DB.prepare(
    "SELECT id, name, phone, program, ssc_gpa, hsc_gpa, honours_cgpa, message, status, reply_note, created_at, updated_at FROM enquiries WHERE id = ?1"
  ).bind(key).first();
  return json({ ok: true, enquiry: enquiryRow(row) });
}

async function handleLogin(request, env) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  if (loginRateLimited(ip)) {
    return json({ error: "Too many login attempts. Please wait a minute and try again." }, 429);
  }
  if (!env.ADMIN_EMAIL || !env.ADMIN_PASSWORD) {
    return json({ error: "Admin login is not set up yet — set ADMIN_EMAIL and ADMIN_PASSWORD secrets" }, 503);
  }
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Email or password is incorrect." }, 401);
  }
  const email = clean(body.email, 120).toLowerCase();
  const password = String(body.password || "");
  // Ekta generic message — konta vul, oita kokhono bolbo na.
  if (!email || !password || !timingSafeEqual(email, String(env.ADMIN_EMAIL).toLowerCase()) || !timingSafeEqual(password, String(env.ADMIN_PASSWORD))) {
    return json({ error: "Email or password is incorrect." }, 401);
  }
  if (!env.DB || typeof env.DB.prepare !== "function") {
    return json({ error: "D1 database is not bound yet" }, 503);
  }
  await ensureSessionsSchema(env);
  await env.DB.prepare("DELETE FROM sessions WHERE expires_at <= datetime('now')").run();
  const token = crypto.randomUUID();
  const hash = await sha256Hex(token);
  const now = new Date();
  const expires = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
  await env.DB.prepare(
    "INSERT INTO sessions (token_hash, created_at, expires_at) VALUES (?1, ?2, ?3)"
  ).bind(hash, now.toISOString(), expires.toISOString()).run();
  return json({ ok: true, token, email: env.ADMIN_EMAIL, expiresAt: expires.toISOString() });
}

async function handleLogout(request, env) {
  const token = bearerToken(request);
  if (token && env.DB && typeof env.DB.prepare === "function") {
    try {
      await ensureSessionsSchema(env);
      const hash = await sha256Hex(token);
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?1").bind(hash).run();
    } catch (e) { /* logout must still succeed */ }
  }
  return json({ ok: true, loggedOut: true });
}

async function handleMe(request, env) {
  const identity = await getAdminIdentity(request, env);
  if (!identity) return json({ error: "Unauthorized" }, 401);
  return json({ ok: true, email: identity.email || null, via: identity.via });
}

// --- Admin panel (embedded, v7/v8 pattern) ---
// /admin-e Worker-er vitorei embed kora — ASSETS diye serve hoy na,
// tai redirect loop hote pare na. Login email + password;
// session token shudhu ei tab-e thake (sessionStorage).
const ADMIN_HTML = `<!DOCTYPE html>
<html lang="bn">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Admin — UOB Admission Hub</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Noto+Serif+Bengali:wght@400;500;600;700&family=Hind+Siliguri:wght@400;500;600;700&family=Noto+Sans+Bengali:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
  :root{ --blue:#2c428b; --blue-2:#3a56a8; --gold:#f5b301; --gold-soft:#fdf3d0;
    --ink:#1d1d1a; --muted:#565b66; --line:#dfe3ee; --bg:#f6f7fb; --card:#ffffff;
    --red:#7a1f1a; --red-bg:#fdecea; --amber:#7a5b00; --amber-bg:#fff4ce; }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--ink);
    font-family:"Noto Serif Bengali","Hind Siliguri","Noto Sans Bengali",system-ui,sans-serif;
    font-size:16px;line-height:1.75}
  a{color:var(--blue-2)}
  .wrap{max-width:900px;margin:0 auto;padding:0 18px 40px}
  header{background:var(--blue);color:#fff;border-bottom:4px solid var(--gold)}
  .topbar{max-width:900px;margin:0 auto;padding:22px 18px;display:flex;gap:14px;align-items:center;flex-wrap:wrap}
  .mark{width:50px;height:50px;flex:0 0 50px;background:#fff;object-fit:cover;border-radius:10px}
  .topbar h1{margin:0;font-size:22px;line-height:1.3}
  .topbar p{margin:2px 0 0;color:#dde4f6;font-size:14px}
  .spacer{flex:1}
  .pill{display:inline-block;background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.35);
    color:#fff;border-radius:999px;padding:6px 12px;font-size:13px;font-weight:600;text-decoration:none;white-space:nowrap;cursor:pointer}
  .pill:hover{background:rgba(255,255,255,.24)}
  .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:22px;margin:16px 0}
  .card h2{margin:0 0 4px;font-size:19px;color:var(--blue)}
  .muted{color:var(--muted);font-size:14.5px}
  label{display:block;font-weight:600;margin:14px 0 5px}
  input,textarea,select{width:100%;padding:11px 12px;border:1px solid #c9cede;border-radius:9px;
    font:inherit;font-size:16px;background:#fbfcff}
  input:focus,textarea:focus,select:focus{outline:2px solid var(--gold);border-color:var(--gold)}
  textarea{min-height:64px;resize:vertical}
  button{cursor:pointer;border:none;border-radius:9px;padding:11px 18px;font-size:15px;font-weight:700}
  .btn-green{background:var(--blue);color:#fff}
  .btn-gold{background:var(--gold);color:#1d1d1a}
  .btn-ghost{background:#eef1f9;color:var(--ink)}
  .btn-small{padding:7px 12px;font-size:13px;margin:2px 4px 2px 0}
  .actions{margin-top:14px;display:flex;gap:8px;flex-wrap:wrap}
  .msg{padding:11px 13px;border-radius:9px;margin:12px 0;font-size:14px;display:none}
  .msg.err{display:block;background:var(--red-bg);color:var(--red)}
  .msg.ok{display:block;background:#e7ebf8;color:#1e3a6e}
  .msg.info{display:block;background:#e8f0fe;color:#174ea6}
  .item{border:1px solid var(--line);border-left:4px solid var(--blue);border-radius:10px;padding:15px;margin:12px 0;background:#fff}
  .item h3{margin:0 0 4px;font-size:17px}
  .item p{margin:4px 0;font-size:14.5px;color:#44506a}
  .badge{display:inline-block;font-size:12px;font-weight:700;padding:2px 10px;border-radius:20px;background:#e7ebf8;color:#1e3a6e}
  .badge.new{background:var(--amber-bg);color:var(--amber)}
  .badge.done{background:#e8f0fe;color:#174ea6}
  .hidden{display:none !important}
  .stats{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
  .stat{background:#fff;border:1px solid var(--line);border-radius:10px;padding:10px 16px;font-size:14px}
  .stat b{font-size:19px;color:var(--blue)}
  @media (max-width:640px){ .topbar h1{font-size:19px} .card{padding:18px 16px} .item{padding:13px} button{padding:13px 18px} }
</style>
</head>
<body>
<header>
  <div class="topbar">
    <img class="mark" src="/logo.jpg" alt="University of Brahmanbaria">
    <div>
      <h1>Admin — Admission Hub</h1>
      <p data-t="aSub">ব্রাহ্মণবাড়িয়া বিশ্ববিদ্যালয় — ভর্তির ইনকোয়ারি</p>
    </div>
    <div class="spacer"></div>
    <button class="pill" id="adminLangBtn" type="button">English</button>
    <a class="pill" href="/" target="_blank" rel="noopener" data-t="aView">ওয়েবসাইট দেখো</a>
    <button class="pill hidden" id="logoutBtn" type="button">Logout</button>
  </div>
</header>

<div class="wrap">

  <div class="card" id="loginCard">
    <h2 data-t="aLoginT">লগইন করো</h2>
    <label for="loginEmail">Email</label>
    <input id="loginEmail" type="email" placeholder="তোমার admin email" autocomplete="username" data-tph="aPhEmail">
    <label for="loginPassword">Password</label>
    <input id="loginPassword" type="password" placeholder="তোমার admin password" autocomplete="current-password" data-tph="aPhPass">
    <div class="actions"><button class="btn-green" id="loginBtn" type="button">Login</button></div>
    <div id="loginMsg" class="msg"></div>
  </div>

  <div id="app" class="hidden">
    <div class="card">
      <h2><span data-t="aEnqT">ইনকোয়ারি</span> (<span id="enquiryCount">0</span>)</h2>
      <div class="stats">
        <div class="stat"><span data-t="aStatNew">নতুন:</span> <b id="countNew">0</b></div>
        <div class="stat"><span data-t="aStatRep">উত্তর দেওয়া:</span> <b id="countReplied">0</b></div>
        <div class="stat"><span data-t="aStatDone">শেষ:</span> <b id="countDone">0</b></div>
      </div>
      <label for="enqFilter" data-t="aFilterLab">Status দিয়ে দেখো</label>
      <select id="enqFilter">
        <option value="" data-t="aOptAll">সবগুলো</option>
        <option value="new" data-t="aOptNew">new — নতুন</option>
        <option value="replied" data-t="aOptRep">replied — উত্তর দেওয়া</option>
        <option value="done" data-t="aOptDone">done — শেষ</option>
      </select>
      <div class="actions"><button class="btn-ghost btn-small" id="refreshBtn" type="button">↻ Refresh</button></div>
      <div id="enquiryList" style="margin-top:10px"><p class="muted" data-t="aLoading">লোড হচ্ছে...</p></div>
    </div>
  </div>

</div>

<script>
(function () {
  "use strict";
  var TOKEN_KEY = "uob_admin_session";
  var loginEmail = document.getElementById("loginEmail");
  var loginPassword = document.getElementById("loginPassword");
  var loginMsg = document.getElementById("loginMsg");

  function token() {
    try { return sessionStorage.getItem(TOKEN_KEY) || ""; } catch (e) { return ""; }
  }
  function saveToken(t) {
    try { sessionStorage.setItem(TOKEN_KEY, t); } catch (e) {}
  }
  function clearToken() {
    try { sessionStorage.removeItem(TOKEN_KEY); } catch (e) {}
  }
  function showMsg(el, text, kind) {
    el.textContent = text;
    el.className = "msg " + (kind || "info");
  }
  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  async function api(path, options) {
    options = options || {};
    var headers = { "Content-Type": "application/json" };
    if (token()) headers["Authorization"] = "Bearer " + token();
    var res;
    try {
      res = await fetch(path, {
        method: options.method || "GET",
        headers: headers,
        body: options.body ? JSON.stringify(options.body) : undefined
      });
    } catch (e) {
      throw new Error(AL("Backend-এ পৌঁছানো যাচ্ছে না। Backend deploy হয়েছে কিনা দেখো। (", "Cannot reach the backend. Check whether the backend is deployed. (") + e.message + ")");
    }
    var data = {};
    try { data = await res.json(); } catch (e) { data = {}; }
    if (res.status === 401) throw new Error(AL("Login হয় নাই — email / password দিয়ে আবার login করো।", "Not logged in — please log in again with your email / password."));
    if (res.status === 503) throw new Error(AL("Admin login / D1 এখনো Worker-এ set করা হয় নাই। আগে secret + D1 setup শেষ করো।", "Admin login / D1 is not set up on the Worker yet. Finish the secret + D1 setup first."));
    if (!res.ok) throw new Error(data.error || (AL("Request fail হয়েছে (HTTP ", "Request failed (HTTP ") + res.status + ")"));
    return data;
  }

  function showApp(loggedIn) {
    document.getElementById("loginCard").classList.toggle("hidden", loggedIn);
    document.getElementById("app").classList.toggle("hidden", !loggedIn);
    document.getElementById("logoutBtn").classList.toggle("hidden", !loggedIn);
    if (loggedIn) loadEnquiries();
  }

  async function doLogout() {
    try { await api("/api/admin/logout", { method: "POST" }); } catch (e) {}
    clearToken();
    loginPassword.value = "";
    showMsg(loginMsg, AL("Logout হয়েছে।", "Logged out."), "info");
    showApp(false);
  }

  document.getElementById("loginBtn").addEventListener("click", async function () {
    var email = loginEmail.value.trim();
    var password = loginPassword.value;
    if (!email || !password) { showMsg(loginMsg, AL("Email আর password — দুইটাই দাও।", "Please enter both email and password."), "err"); return; }
    showMsg(loginMsg, AL("Login হচ্ছে...", "Logging in..."), "info");
    try {
      var res = await fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email, password: password })
      });
      var data = {};
      try { data = await res.json(); } catch (e) { data = {}; }
      if (!res.ok) throw new Error(data.error || AL("Login হয় নাই।", "Login failed."));
      saveToken(data.token);
      loginPassword.value = "";
      showMsg(loginMsg, "", "info");
      showApp(true);
    } catch (e) {
      showMsg(loginMsg, "❌ " + e.message, "err");
    }
  });
  loginPassword.addEventListener("keydown", function (ev) {
    if (ev.key === "Enter") document.getElementById("loginBtn").click();
  });
  document.getElementById("logoutBtn").addEventListener("click", doLogout);

  (async function () {
    if (!token()) return;
    try {
      await api("/api/admin/me");
      showApp(true);
    } catch (e) { clearToken(); }
  })();

  // Admin language — Bangla / English, same pattern as the website toggle.
  // Original Bangla is captured from the page on load; choice is saved
  // in localStorage ("uob-lang", shared with the website).
  var ADMIN_EN = {
    "aSub": "University of Brahmanbaria — Admission Enquiries",
    "aView": "View Website",
    "aLoginT": "Login",
    "aEnqT": "Enquiries",
    "aStatNew": "New:",
    "aStatRep": "Replied:",
    "aStatDone": "Done:",
    "aFilterLab": "Filter by status",
    "aOptAll": "All",
    "aOptNew": "new — New",
    "aOptRep": "replied — Replied",
    "aOptDone": "done — Done",
    "aLoading": "Loading..."
  };
  var ADMIN_EN_PH = {
    "aPhEmail": "Your admin email",
    "aPhPass": "Your admin password"
  };
  var __aBn = {}, __aBnPh = {};
  function AL(bn, en){ return document.documentElement.lang === "en" ? en : bn; }
  function __aCapture(){
    document.querySelectorAll("[data-t]").forEach(function(el){ __aBn[el.getAttribute("data-t")] = el.innerHTML; });
    document.querySelectorAll("[data-tph]").forEach(function(el){ __aBnPh[el.getAttribute("data-tph")] = el.placeholder; });
  }
  function __aApply(lang){
    var en = (lang === "en");
    document.documentElement.lang = en ? "en" : "bn";
    document.querySelectorAll("[data-t]").forEach(function(el){
      var k = el.getAttribute("data-t");
      if (en && ADMIN_EN[k] !== undefined) el.innerHTML = ADMIN_EN[k];
      else if (__aBn[k] !== undefined) el.innerHTML = __aBn[k];
    });
    document.querySelectorAll("[data-tph]").forEach(function(el){
      var k = el.getAttribute("data-tph");
      if (en && ADMIN_EN_PH[k] !== undefined) el.placeholder = ADMIN_EN_PH[k];
      else if (__aBnPh[k] !== undefined) el.placeholder = __aBnPh[k];
    });
    var btn = document.getElementById("adminLangBtn");
    if (btn) btn.textContent = en ? "বাংলা" : "English";
    try { localStorage.setItem("uob-lang", en ? "en" : "bn"); } catch (e) {}
    if (!document.getElementById("app").classList.contains("hidden")) loadEnquiries();
  }
  __aCapture();
  (function(){
    var saved = null;
    try { saved = localStorage.getItem("uob-lang"); } catch (e) {}
    if (saved === "en") __aApply("en");
  })();
  document.getElementById("adminLangBtn").addEventListener("click", function(){
    __aApply(document.documentElement.lang === "en" ? "bn" : "en");
  });

  var cache = [];
  function statusLabel(s) {
    if (s === "new") return AL("new — নতুন", "new — New");
    if (s === "replied") return AL("replied — উত্তর দেওয়া", "replied — Replied");
    return AL("done — শেষ", "done — Done");
  }

  async function loadEnquiries() {
    var list = document.getElementById("enquiryList");
    var status = document.getElementById("enqFilter").value;
    try {
      var q = "/api/admin/enquiries?limit=100" + (status ? "&status=" + encodeURIComponent(status) : "");
      var data = await api(q);
      cache = data.enquiries || [];
      document.getElementById("enquiryCount").textContent = data.count || cache.length;
      var counts = { "new": 0, "replied": 0, "done": 0 };
      cache.forEach(function (e) { if (counts[e.status] !== undefined) counts[e.status] += 1; });
      document.getElementById("countNew").textContent = counts["new"];
      document.getElementById("countReplied").textContent = counts["replied"];
      document.getElementById("countDone").textContent = counts["done"];
      if (!cache.length) { list.innerHTML = "<p class='muted'>" + AL("কোনো inquiry নাই।", "No enquiries yet.") + "</p>"; return; }
      list.innerHTML = cache.map(function (e) {
        var time = "";
        try { time = new Date(e.createdAt).toLocaleString(AL("bn-BD", "en-US")); } catch (err) { time = e.createdAt || ""; }
        var digits = (e.phone || "").replace(/[^0-9]/g, "");
        var wa = digits;
        if (wa.indexOf("880") === 0) { /* already full international number */ }
        else if (wa.charAt(0) === "0") { wa = "88" + wa; }
        else if (wa) { wa = "880" + wa; }
        return "<div class='item' data-id='" + esc(e.id) + "'>" +
          "<h3>" + esc(e.name || "No name") + " · " + esc(e.program || "") + " " +
          "<span class='badge " + esc(e.status || "new") + "'>" + esc(statusLabel(e.status || "new")) + "</span></h3>" +
          "<p>" + esc(e.message || "") + "</p>" +
          "<p class='muted'>" +
          AL("ফোন:", "Phone:") + " <a href='tel:" + esc(e.phone || "") + "'>" + esc(e.phone || "") + "</a> · " +
          "<a href='https://wa.me/" + esc(wa) + "' target='_blank' rel='noopener'>" + AL("WhatsApp-এ লিখো", "Message on WhatsApp") + "</a><br>" +
          (e.sscGpa ? "SSC GPA: " + esc(e.sscGpa) + "<br>" : "") +
          (e.hscGpa ? "HSC GPA: " + esc(e.hscGpa) + "<br>" : "") +
          (e.honoursCgpa ? AL("অনার্স/CGPA: ", "Honours/CGPA: ") + esc(e.honoursCgpa) + "<br>" : "") +
          (time ? AL("সময়: ", "Time: ") + esc(time) : "") +
          "</p>" +
          "<label>Status</label>" +
          "<select class='st'>" +
          "<option value='new'" + (e.status === "new" ? " selected" : "") + ">" + statusLabel("new") + "</option>" +
          "<option value='replied'" + (e.status === "replied" ? " selected" : "") + ">" + statusLabel("replied") + "</option>" +
          "<option value='done'" + (e.status === "done" ? " selected" : "") + ">" + statusLabel("done") + "</option>" +
          "</select>" +
          AL("<label>Reply note — WhatsApp-এ কী উত্তর দিলা, এখানে লিখে রাখো</label>", "<label>Reply note — write here what you replied on WhatsApp</label>") +
          "<textarea class='note' placeholder='" + AL("যেমন: ফি জানানো হয়েছে, ১২ নভেম্বর ফোন করা হয়েছে...", "e.g. Fees shared, called on 12 November...") + "'>" + esc(e.replyNote || "") + "</textarea>" +
          "<div class='actions'><button class='btn-green btn-small saveBtn' type='button'>💾 Save</button></div>" +
          "<p class='muted saveMsg'></p>" +
          "</div>";
      }).join("");
    } catch (e) {
      list.innerHTML = "<p class='muted'>❌ " + esc(e.message) + "</p>";
    }
  }
  document.getElementById("refreshBtn").addEventListener("click", loadEnquiries);
  document.getElementById("enqFilter").addEventListener("change", loadEnquiries);

  document.getElementById("enquiryList").addEventListener("click", async function (ev) {
    var btn = ev.target.closest(".saveBtn");
    if (!btn) return;
    var card = btn.closest(".item");
    if (!card) return;
    var id = card.getAttribute("data-id");
    var status = card.querySelector(".st").value;
    var replyNote = card.querySelector(".note").value;
    var msgEl = card.querySelector(".saveMsg");
    msgEl.textContent = AL("Save হচ্ছে...", "Saving...");
    try {
      await api("/api/admin/enquiries/" + encodeURIComponent(id), {
        method: "PATCH", body: { status: status, reply_note: replyNote }
      });
      msgEl.textContent = AL("✓ Save হয়েছে।", "✓ Saved.");
      loadEnquiries();
    } catch (e) {
      msgEl.textContent = "❌ " + e.message;
    }
  });
})();
</script>
</body>
</html>`;

// --- Embedded Hub page (v8.2 pattern: ASSETS fallback) ---
// public/index.html-er hubuhu copy — ASSETS-e file ta thakle age
// oita dibe, na thakle ei copy dibe. public/index.html bodlale
// ei copy-tao bodlate hobe (niche INDEX_HTML constant-e index.html-er content bosano thake).
const INDEX_HTML = "<!doctype html>\n<html lang=\"bn\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>স্প্রিং ২০২৭ ভর্তি — ব্রাহ্মণবাড়িয়া বিশ্ববিদ্যালয়</title>\n<meta name=\"description\" content=\"ব্রাহ্মণবাড়িয়া বিশ্ববিদ্যালয়ে স্প্রিং ২০২৭ ভর্তি — প্রোগ্রাম, মোট ফি, আবেদনের ধাপ আর যোগাযোগ, এক পাতায়।\">\n<link rel=\"preconnect\" href=\"https://fonts.googleapis.com\">\n<link rel=\"preconnect\" href=\"https://fonts.gstatic.com\" crossorigin>\n<link href=\"https://fonts.googleapis.com/css2?family=Noto+Serif+Bengali:wght@400;500;600;700&family=Hind+Siliguri:wght@400;500;600;700&display=swap\" rel=\"stylesheet\">\n<style>\n  :root{\n    --blue:#2c428b; --blue-2:#3a56a8; --gold:#f5b301; --gold-soft:#fdf3d0;\n    --ink:#1d1d1a; --muted:#565b66; --line:#dfe3ee; --bg:#f6f7fb; --card:#ffffff;\n  }\n  *{box-sizing:border-box}\n  html{scroll-behavior:smooth}\n  #apply{scroll-margin-top:16px}\n  body{margin:0;background:var(--bg);color:var(--ink);-webkit-text-size-adjust:100%;\n    font-family:\"Noto Serif Bengali\",\"Hind Siliguri\",\"Noto Sans Bengali\",system-ui,sans-serif;\n    font-size:17px;line-height:1.85}\n  a{color:var(--blue-2)}\n  .wrap{max-width:960px;margin:0 auto;padding:0 20px}\n\n  /* উপরের ছোট বার */\n  .topbar{background:var(--blue);color:#dde4f6;font-size:14.5px}\n  .topbar .wrap{display:flex;justify-content:space-between;gap:12px;padding-top:8px;padding-bottom:8px;flex-wrap:wrap}\n  .topbar a{color:#fff;text-decoration:none;font-weight:600}\n\n  /* হেডার */\n  header.site{background:#fff;border-bottom:1px solid var(--line)}\n  header.site .wrap{display:flex;align-items:center;gap:14px;padding-top:16px;padding-bottom:16px}\n  .mark{width:52px;height:52px;flex:0 0 52px;background:#fff;object-fit:cover;\n    display:flex;align-items:center;justify-content:center;font-weight:700;font-size:19px;border-radius:10px;letter-spacing:.5px}\n  header.site h1{font-size:22px;line-height:1.35;margin:0}\n  header.site p{margin:2px 0 0;color:var(--muted);font-size:14.5px}\n  .head-cta{margin-left:auto;white-space:nowrap}\n  .btn{display:inline-block;padding:11px 20px;border-radius:9px;text-decoration:none;font-weight:700;font-size:16px;border:1px solid transparent;cursor:pointer}\n  .btn-gold{background:var(--gold);color:#1d1d1a}\n  .btn-gold:hover{background:#e5a800}\n  .btn-line{background:transparent;color:var(--blue);border-color:var(--blue)}\n  .btn-line:hover{background:#eef1f9}\n  .btn-green{background:var(--blue);color:#fff}\n  .btn-green:hover{background:var(--blue-2)}\n  span.btn{cursor:default}\n\n  /* হিরো — বাম দিকে লেখা, সাদামাটা */\n  .hero{background:var(--blue);color:#fff}\n  .hero .wrap{padding-top:52px;padding-bottom:56px}\n  .badge{display:inline-block;background:var(--gold);color:#1d1d1a;font-weight:700;font-size:14.5px;\n    padding:5px 13px;border-radius:999px;margin-bottom:16px}\n  .hero h2{font-size:38px;line-height:1.45;margin:0 0 12px;max-width:560px}\n  .hero p.lead{color:#d8e0f5;font-size:18px;line-height:1.8;margin:0 0 26px;max-width:620px}\n  .hero .actions{display:flex;gap:12px;flex-wrap:wrap}\n  .hero .btn-line{color:#fff;border-color:rgba(255,255,255,.55)}\n  .hero .btn-line:hover{background:rgba(255,255,255,.12)}\n  .hero .note{margin-top:20px;color:#bfc9ea;font-size:14.5px}\n\n  main section{padding:44px 0 8px}\n  h2.sec{font-size:26px;line-height:1.5;margin:0 0 6px;color:var(--blue)}\n  p.sub{color:var(--muted);margin:0 0 22px;max-width:680px}\n  .rule{width:56px;height:4px;background:var(--gold);border-radius:4px;margin:0 0 22px}\n\n  /* তিনটা সুবিধা */\n  .cols{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}\n  .card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:22px}\n  .card .no{font-size:13px;font-weight:700;letter-spacing:1px;color:#9a8a3a;text-transform:uppercase}\n  .card h3{font-size:19px;line-height:1.55;margin:8px 0 6px;color:var(--blue)}\n  .card p{margin:0;color:var(--muted);font-size:15.5px;line-height:1.8}\n\n  /* ফি টেবিল — মোবাইলে চাপবে না, দরকার হলে ডানে-বামে স্ক্রল হবে */\n  .table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch;background:#fff;\n    border:1px solid var(--line);border-radius:12px}\n  table{width:100%;border-collapse:collapse;background:#fff}\n  .table-wrap table{min-width:520px}\n  th,td{padding:13px 16px;text-align:left;border-bottom:1px solid var(--line);font-size:16px}\n  tr:last-child th,tr:last-child td{border-bottom:0}\n  th{background:var(--blue);color:#fff;font-size:15px}\n  td.fee{font-weight:700;color:var(--blue);white-space:nowrap}\n  .table-wrap td a{text-decoration:none}\n  .table-wrap td a:hover{text-decoration:underline}\n  .tbl-note{font-size:14.5px;color:var(--muted);margin-top:10px}\n  h3.tbl-title{font-size:19px;margin:28px 0 12px;color:var(--blue)}\n  h3.tbl-title:first-of-type{margin-top:0}\n\n  /* ধাপ */\n  .steps{list-style:none;margin:0;padding:0;counter-reset:step}\n  .steps li{counter-increment:step;display:flex;gap:16px;padding:16px 0;border-bottom:1px solid var(--line)}\n  .steps li:last-child{border-bottom:0}\n  .steps li::before{content:counter(step, bengali);flex:0 0 40px;height:40px;background:var(--gold-soft);\n    border:1px solid #ead98a;color:#7a6410;font-weight:700;font-size:19px;border-radius:50%;\n    display:flex;align-items:center;justify-content:center}\n  .steps strong{display:block;font-size:17.5px;color:var(--blue)}\n  .steps span{color:var(--muted);font-size:15.5px}\n\n  .two{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n  .two ul{margin:0;padding-left:20px;color:var(--muted)}\n  .two li{margin-bottom:8px}\n  .two h3{margin-top:0;color:var(--blue);font-size:19px}\n\n  /* ফর্ম */\n  .form-box{background:#fff;color:var(--ink);border:1px solid var(--line);border-radius:14px;padding:30px}\n  .form-box h2{margin-top:0}\n  label{display:block;font-weight:600;margin:16px 0 6px}\n  input,select,textarea{width:100%;padding:12px 14px;border:1px solid #c9cede;border-radius:9px;\n    font:inherit;font-size:16px;color:var(--ink);background:#fbfcff}\n  input:focus,select:focus,textarea:focus{outline:2px solid var(--gold);border-color:var(--gold)}\n  .row{display:grid;grid-template-columns:1fr 1fr;gap:16px}\n  .form-box button{margin-top:22px;width:100%;padding:14px;font:inherit;font-weight:700;font-size:17px}\n  .form-box button:disabled{opacity:.65;cursor:wait}\n  /* জমা সফল হলে সুন্দর সবুজ কার্ড */\n  .success-box{background:#e7ebf8;border:1px solid #b9c7e9;border-radius:12px;padding:28px 22px;text-align:center}\n  .success-box .tick{width:56px;height:56px;margin:0 auto;background:var(--blue);color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:28px;font-weight:700}\n  .success-box h3{margin:12px 0 6px;color:var(--blue);font-size:21px}\n  .success-box p{margin:0;color:var(--muted);font-size:15.5px}\n  .form-alt{text-align:center;color:var(--muted);margin:18px 0 0;font-size:15.5px}\n\n\n  /* FAQ */\n  details{background:#fff;border:1px solid var(--line);border-radius:10px;padding:16px 18px;margin-bottom:12px}\n  summary{font-weight:700;color:var(--blue);cursor:pointer;font-size:17px}\n  details p{margin:10px 0 0;color:var(--muted)}\n\n  footer{background:var(--blue);color:#d0d9f3;margin-top:56px}\n  footer .wrap{padding-top:36px;padding-bottom:36px;text-align:center}\n  footer strong{color:#fff;font-size:19px}\n  footer p{margin:8px 0;font-size:15.5px;overflow-wrap:anywhere}\n  footer small{color:#a3b1d9}\n\n  /* মোবাইলে নিচে আটকে থাকা বোতাম — ফর্ম অনেক নিচে, তাই সবসময় হাতের কাছে */\n  .mobile-cta{display:none}\n\n\n  /* ভাষা বোতাম — উপরের বারে, সব স্ক্রিনে দেখা যায় */\n  .lang-btn{background:rgba(255,255,255,.14);color:#fff;border:1px solid rgba(255,255,255,.45);\n    border-radius:999px;padding:2px 12px;font:inherit;font-size:13.5px;font-weight:700;cursor:pointer}\n  .lang-btn:hover{background:rgba(255,255,255,.25)}\n  html[lang=\"en\"] .steps li::before{content:counter(step, decimal)}\n  html[lang=\"en\"] body{font-family:Georgia,\"Noto Serif Bengali\",\"Hind Siliguri\",serif}\n\n  /* হিরোতে ফর্ম — ফর্মটাই মূল, তাই হিরোর ডান পাশে কার্ড আকারে */\n  .hero-grid{display:grid;grid-template-columns:1.05fr .95fr;gap:40px;align-items:start}\n  .hero .form-box{box-shadow:0 18px 40px rgba(0,0,0,.28)}\n  .hero .form-box h2{font-size:23px}\n  @media (max-width:720px){\n    body{font-size:16px;line-height:1.8}\n    .wrap{padding:0 16px}\n    .topbar{font-size:14px}\n    .topbar .wrap{justify-content:center;gap:2px 14px;padding-top:7px;padding-bottom:7px}\n    header.site .wrap{padding-top:12px;padding-bottom:12px;gap:12px}\n    .mark{width:44px;height:44px;flex-basis:44px;font-size:17px}\n    .hero .wrap{padding-top:36px;padding-bottom:40px}\n    .hero-grid{grid-template-columns:1fr;gap:28px}\n    .hero h2{font-size:27px;line-height:1.55}\n    .hero p.lead{font-size:17px;margin-bottom:22px}\n    h2.sec{font-size:23px}\n    main section{padding:32px 0 6px}\n    .card{padding:18px}\n    .cols,.two,.row{grid-template-columns:1fr}\n    .head-cta{display:none}\n    header.site h1{font-size:19px}\n    .form-box{padding:22px 18px}\n    th,td{padding:11px 12px;font-size:15px}\n    td.fee{white-space:nowrap}\n    input,select,textarea{padding:13px 14px}\n    .btn{padding:13px 20px}\n    .form-box button{padding:15px}\n    details{padding:14px 16px}\n    summary{font-size:16.5px}\n    footer .wrap{padding-bottom:112px}\n    .mobile-cta{display:flex;position:fixed;left:0;right:0;bottom:0;z-index:50;\n      background:#fff;border-top:1px solid var(--line);box-shadow:0 -4px 16px rgba(0,0,0,.08);\n      padding:10px 12px calc(10px + env(safe-area-inset-bottom));gap:10px}\n    .mobile-cta a{flex:1;text-align:center;padding:13px 10px;border-radius:9px;\n      font-weight:700;font-size:16px;text-decoration:none}\n    .mobile-cta a:first-child{background:var(--gold);color:#1d1d1a}\n    .mobile-cta a:last-child{background:var(--blue);color:#fff}\n  }\n  @media (max-width:520px){\n    .hero h2{font-size:26px}\n    .hero .actions{flex-direction:column}\n    .hero .actions .btn{width:100%;text-align:center;padding:14px 20px}\n    .hero .note{font-size:14px}\n    .steps li{gap:12px}\n    .steps li::before{flex-basis:36px;height:36px;font-size:17px}\n    .two ul{padding-left:18px}\n  }\n</style>\n</head>\n<body>\n\n<div class=\"topbar\">\n  <div class=\"wrap\">\n    <span data-t=\"topLeft\">স্প্রিং ২০২৭ — ভর্তি চলছে</span>\n    <span data-t=\"topHelp\">হেল্পলাইন: <a href=\"tel:01313430064\">০১৩১৩-৪৩০০৬৪</a></span>\n    <button type=\"button\" class=\"lang-btn\" id=\"langBtn\">English</button>\n  </div>\n</div>\n\n<header class=\"site\">\n  <div class=\"wrap\">\n    <img class=\"mark\" src=\"/logo.jpg\" alt=\"University of Brahmanbaria\">\n    <div>\n      <h1 data-t=\"siteName\">ব্রাহ্মণবাড়িয়া বিশ্ববিদ্যালয় (Admission Hub)</h1>\n      <p>University of Brahmanbaria</p>\n    </div>\n    <div class=\"head-cta\">\n      <span data-t=\"applyBtn\" class=\"btn btn-gold\">আবেদন করুন</span>\n    </div>\n  </div>\n</header>\n\n<section class=\"hero\">\n  <div class=\"wrap hero-grid\">\n    <div class=\"hero-copy\">\n      <span data-t=\"badge\" class=\"badge\">স্প্রিং ২০২৭ ভর্তি চলছে</span>\n      <h2 data-t=\"heroTitle\">ভর্তির সব তথ্য এক জায়গায় — ফি, প্রোগ্রাম আর আবেদনের নিয়ম।</h2>\n      <p data-t=\"heroLead\" class=\"lead\">কোন প্রোগ্রামে কত খরচ, কী কাগজ লাগবে, কীভাবে আবেদন করবেন — এই পাতায় সব লেখা আছে। আবেদন করবেন বিশ্ববিদ্যালয়ের অফিসিয়াল পোর্টালে, আর কিছু জানতে চাইলে ফর্মটা পূরণ করুন।</p>\n      <div class=\"actions\">\n        <span data-t=\"heroApply\" class=\"btn btn-gold\">অনলাইনে আবেদন করুন</span>\n        <a data-t=\"heroCall\" class=\"btn btn-line\" href=\"tel:01313430064\">ফোন করুন</a>\n      </div>\n      <p data-t=\"heroNote\" class=\"note\">ভর্তি সংক্রান্ত চূড়ান্ত তথ্যের জন্য Admission Office-এর সঙ্গে মিলিয়ে নিন।</p>\n    </div>\n    <div class=\"form-box\" id=\"apply\">\n      <h2 data-t=\"formT\" class=\"sec\">জানতে চান? লিখে পাঠান</h2>\n      <p data-t=\"formSub\" class=\"sub\">নাম আর ফোন নম্বর দিন — Admission টিম আপনার সঙ্গে যোগাযোগ করবে।</p>\n      <div id=\"form-success\" class=\"success-box\" hidden>\n        <div class=\"tick\">✓</div>\n        <h3 data-t=\"okT\">ধন্যবাদ! আপনার তথ্য পৌঁছে গেছে।</h3>\n        <p data-t=\"okP\">Admission টিম শীঘ্রই আপনার সঙ্গে যোগাযোগ করবে। WhatsApp-এ Send চাপলে আরও দ্রুত উত্তর পাবেন।</p>\n      </div>\n      <form id=\"inquiry-form\">\n        <label data-t=\"labName\" for=\"name\">আপনার নাম *</label>\n        <input id=\"name\" name=\"name\" type=\"text\" required autocomplete=\"name\" data-tph=\"phName\" placeholder=\"আপনার পুরো নাম লিখুন\">\n\n        <div class=\"row\">\n          <div>\n            <label data-t=\"labPhone\" for=\"phone\">মোবাইল / WhatsApp নম্বর *</label>\n            <input id=\"phone\" name=\"phone\" type=\"tel\" required inputmode=\"tel\" autocomplete=\"tel\" placeholder=\"017xxxxxxxx\">\n          </div>\n          <div>\n            <label data-t=\"labProg\" for=\"program\">পছন্দের প্রোগ্রাম *</label>\n            <select id=\"program\" name=\"program\" required>\n              <option value=\"\" data-t=\"optChoose\">— বেছে নিন —</option>\n              <option value=\"LLB (অনার্স)\" data-t=\"optLLB\">LLB (অনার্স)</option>\n              <option value=\"B.Sc. in CSE\">B.Sc. in CSE</option>\n              <option value=\"B.Sc. in EEE\">B.Sc. in EEE</option>\n              <option value=\"BBA\">BBA</option>\n              <option value=\"BA (Hons.) in English\">BA (Hons.) in English</option>\n              <option value=\"BSS (Hons.) in Sociology\">BSS (Hons.) in Sociology</option>\n              <option value=\"MBA / Masters\">MBA / Masters</option>\n              <option value=\"IELTS Preparation\">IELTS Preparation</option>\n            </select>\n          </div>\n        </div>\n\n        <div class=\"row\">\n          <div>\n            <label data-t=\"labSSC\" for=\"ssc\">SSC ফলাফল (GPA)</label>\n            <input id=\"ssc\" name=\"ssc\" type=\"text\" inputmode=\"decimal\" data-tph=\"phSSC\" placeholder=\"যেমন: 5.00\">\n          </div>\n          <div>\n            <label data-t=\"labHSC\" for=\"hsc\">HSC ফলাফল (GPA)</label>\n            <input id=\"hsc\" name=\"hsc\" type=\"text\" inputmode=\"decimal\" data-tph=\"phHSC\" placeholder=\"যেমন: 4.50\">\n          </div>\n        </div>\n\n        <label data-t=\"labHon\" for=\"honours\">অনার্স / ব্যাচেলর ফলাফল (CGPA) — শুধু MBA / Masters আবেদনকারীদের জন্য</label>\n        <input id=\"honours\" name=\"honours\" type=\"text\" inputmode=\"decimal\" data-tph=\"phHon\" placeholder=\"যেমন: CGPA 3.25\">\n\n        <label data-t=\"labMsg\" for=\"message\">আপনার প্রশ্ন থাকলে লিখুন</label>\n        <textarea id=\"message\" name=\"message\" rows=\"3\" data-tph=\"phMsg\" placeholder=\"ফি, স্কলারশিপ, ডে কেয়ার — যা জানতে চান লিখুন...\"></textarea>\n\n        <button data-t=\"submit\" class=\"btn btn-green\" type=\"submit\" id=\"submitBtn\">জমা দিন</button>\n        <p id=\"form-status\" style=\"text-align:center;font-size:15px;margin:10px 0 0;color:var(--blue);font-weight:600\"></p>\n      </form>\n    </div>\n  </div>\n</section>\n\n<main class=\"wrap\">\n\n\n  <section>\n    <h2 data-t=\"secBenefits\" class=\"sec\">এখানে ভর্তি হলে কী পাবেন</h2>\n    <div class=\"rule\"></div>\n    <div class=\"cols\">\n      <div class=\"card\">\n        <div data-t=\"ben1no\" class=\"no\">সুবিধা ০১</div>\n        <h3 data-t=\"ben1t\">মায়েদের জন্য ডে কেয়ার</h3>\n        <p data-t=\"ben1p\">নারী শিক্ষার্থীরা যাতে নিশ্চিন্তে ক্লাস করতে পারেন, ক্যাম্পাসে আছে আধুনিক ডে কেয়ার সেন্টার। পড়াশোনা আর মাতৃত্ব — দুটোই একসাথে চলবে।</p>\n      </div>\n      <div class=\"card\">\n        <div data-t=\"ben2no\" class=\"no\">সুবিধা ০২</div>\n        <h3 data-t=\"ben2t\">শিক্ষকদের জন্য ৭০% পর্যন্ত ছাড়</h3>\n        <p data-t=\"ben2p\">প্রাথমিক, মাধ্যমিক, কলেজ ও মাদ্রাসায় কর্মরত শিক্ষকদের মাস্টার্স প্রোগ্রামে (MBA, MA, MSS) টিউশন ফিতে ৭০% পর্যন্ত ছাড়, আর ক্লাস শুক্র-শনিবার।</p>\n      </div>\n      <div class=\"card\">\n        <div data-t=\"ben3no\" class=\"no\">সুবিধা ০৩</div>\n        <h3 data-t=\"ben3t\">স্কলারশিপ আর IELTS প্রস্তুতি</h3>\n        <p data-t=\"ben3p\">SSC ও HSC ফলাফলের ওপর স্কলারশিপের সুযোগ আছে। সাথে ব্রিটিশ কাউন্সিল-সার্টিফাইড শিক্ষকদের পরিচালনায় IELTS প্রস্তুতি কোর্স।</p>\n      </div>\n    </div>\n  </section>\n\n  <section>\n    <h2 data-t=\"secFees\" class=\"sec\">প্রোগ্রাম আর মোট ফি</h2>\n    <div class=\"rule\"></div>\n    <p data-t=\"secFeesSub\" class=\"sub\">নিচের ফিগুলো পুরো প্রোগ্রামের মোট খরচ। ভর্তির সময় ছাড় বা কিস্তির নিয়ম জানতে Admission Office-এ যোগাযোগ করুন।</p>\n\n    <h3 data-t=\"tblUG\" class=\"tbl-title\">আন্ডারগ্রাজুয়েট প্রোগ্রাম</h3>\n    <div class=\"table-wrap\">\n    <table>\n      <tr><th data-t=\"thProg\">প্রোগ্রাম</th><th data-t=\"thFee\">মোট ফি</th></tr>\n      <tr><td data-t=\"progLLB\">LLB (অনার্স)</td><td data-t=\"feeLLB\" class=\"fee\">৩,১৬,৪০০ টাকা</td></tr>\n      <tr><td>B.Sc. in CSE</td><td data-t=\"feeCSE\" class=\"fee\">৩,১৬,০০০ টাকা</td></tr>\n      <tr><td>B.Sc. in EEE</td><td data-t=\"feeEEE\" class=\"fee\">৩,১২,৬০০ টাকা</td></tr>\n      <tr><td>BBA</td><td data-t=\"feeBBA\" class=\"fee\">২,৬৬,৯০০ টাকা</td></tr>\n      <tr><td>BA (Hons.) in English</td><td data-t=\"feeEng\" class=\"fee\">২,৪৭,৬০০ টাকা</td></tr>\n      <tr><td>BSS (Hons.) in Sociology</td><td data-t=\"feeSoc\" class=\"fee\">১,৯০,৪০০ টাকা</td></tr>\n    </table>\n    </div>\n\n    <h3 data-t=\"tblPG\" class=\"tbl-title\">গ্রাজুয়েট ও অন্যান্য প্রোগ্রাম</h3>\n    <div class=\"table-wrap\">\n    <table>\n      <tr><th data-t=\"thProg\">প্রোগ্রাম</th><th data-t=\"thFee\">মোট ফি</th></tr>\n      <tr><td data-t=\"progMBA\">MBA (২ বছর / ১ বছর)</td><td data-t=\"feeMBA\" class=\"fee\">৯২,১০০ – ১,৪৭,৭০০ টাকা</td></tr>\n      <tr><td>MA in English Literature &amp; ELT</td><td data-t=\"feeMA\" class=\"fee\">৮০,৭০০ – ১,১৩,৩০০ টাকা</td></tr>\n      <tr><td>MSS in Sociology</td><td data-t=\"feeMSS\" class=\"fee\">৬৫,৯০০ – ৯৮,৭০০ টাকা</td></tr>\n      <tr><td>PGD in Library &amp; Information Science</td><td data-t=\"feePGD\" class=\"fee\">৪১,১০০ টাকা</td></tr>\n      <tr><td>IELTS Course (UOB Students)</td><td data-t=\"feeIELTS\" class=\"fee\">৮,০০০ টাকা</td></tr>\n    </table>\n    </div>\n    <p data-t=\"tblNote\" class=\"tbl-note\">ফি আর ছাড়ের শর্ত সময়ের সঙ্গে বদলাতে পারে — ভর্তির আগে অফিস থেকে জেনে নেওয়াই ভালো।</p>\n  </section>\n\n  <section>\n    <h2 data-t=\"secSteps\" class=\"sec\">আবেদন করবেন যেভাবে</h2>\n    <div class=\"rule\"></div>\n    <ol class=\"steps\">\n      <li><div><strong data-t=\"step1t\">অনলাইনে আবেদন করুন</strong><span data-t=\"step1d\">admission.uob.edu.bd-তে গিয়ে আবেদন করুন, অথবা Admission Office থেকে সরাসরি ফর্ম নিন।</span></div></li>\n      <li><div><strong data-t=\"step2t\">তথ্য যাচাই</strong><span data-t=\"step2d\">আপনার SSC ও HSC-এর তথ্য আর কাগজপত্র যাচাই করা হবে।</span></div></li>\n    </ol>\n  </section>\n\n  <section>\n    <div class=\"two\">\n      <div class=\"card\">\n        <h3 data-t=\"docsT\">কী কী কাগজ লাগবে</h3>\n        <ul>\n          <li data-t=\"doc1\">সব বোর্ড মার্কশিট আর টেস্টিমোনিয়াল / সার্টিফিকেটের সত্যায়িত ফটোকপি</li>\n          <li data-t=\"doc2\">সাম্প্রতিক রঙিন পাসপোর্ট সাইজ ছবি — ৩ কপি</li>\n          <li data-t=\"doc3\">O-Level / A-Level হলে সার্টিফিকেট আর A2 Statement of Entry-র সত্যায়িত কপি</li>\n          <li data-t=\"doc4\">মুক্তিযোদ্ধা কোটা হলে মন্ত্রণালয়ের সার্টিফিকেট আর গেজেটের সত্যায়িত কপি</li>\n        </ul>\n      </div>\n      <div class=\"card\">\n        <h3 data-t=\"eligT\">কে আবেদন করতে পারবে</h3>\n        <ul>\n          <li data-t=\"elig1\">CSE ও EEE: SSC + HSC মিলিয়ে GPA ৫ (দুটোতেই কমপক্ষে ২.৫), অথবা মোট ৬.০০ (একটায় কমপক্ষে ২.০০) — শুধু বিজ্ঞান ব্যাকগ্রাউন্ড</li>\n          <li data-t=\"elig2\">BBA, BA English, BSS Sociology: একই GPA নিয়ম — যেকোনো ব্যাকগ্রাউন্ড থেকে আবেদন করা যায়</li>\n          <li data-t=\"elig3\">MBA (রেগুলার): ৩ বছরের ব্যাচেলর ডিগ্রি, SSC + HSC-তে কমপক্ষে GPA ২.৫ আর ব্যাচেলরে CGPA ২.৫</li>\n        </ul>\n        <p data-t=\"eligSrc\" style=\"margin:10px 0 0\">সূত্র: admission.uob.edu.bd — Admission Requirements। বিস্তারিত সেখানেই দেখে নিন, অথবা অফিসে ফোন করুন — <a href=\"tel:01313430064\">০১৩১৩-৪৩০০৬৪</a></p>\n      </div>\n    </div>\n  </section>\n\n\n  <section>\n    <h2 data-t=\"faqT\" class=\"sec\">যা সবাই জিজ্ঞেস করে</h2>\n    <div class=\"rule\"></div>\n    <details>\n      <summary data-t=\"faq1q\">ভর্তির শেষ তারিখ কবে?</summary>\n      <p data-t=\"faq1a\">শেষ তারিখ Admission Office থেকে জেনে নিন — আসন সীমিত, তাই দেরি না করাই ভালো।</p>\n    </details>\n    <details>\n      <summary data-t=\"faq2q\">ফি কি একবারে দিতে হবে, না কিস্তিতে দেওয়া যায়?</summary>\n      <p data-t=\"faq2a\">কিস্তি আর ছাড়ের নিয়ম প্রোগ্রাম অনুযায়ী আলাদা। অফিসে ফোন করলে সঠিকটা জানিয়ে দেবে।</p>\n    </details>\n    <details>\n      <summary data-t=\"faq3q\">ক্লাস কবে থেকে শুরু?</summary>\n      <p data-t=\"faq3a\">ভর্তি নিশ্চিত হওয়ার পর ক্লাস শুরুর তারিখ জানিয়ে দেওয়া হবে।</p>\n    </details>\n  <section>\n    <h2 data-t=\"cTitle\" class=\"sec\">যোগাযোগ করুন</h2>\n    <div class=\"rule\"></div>\n    <p data-t=\"cSub\" class=\"sub\">ভর্তি বা প্রোগ্রাম নিয়ে জানতে সরাসরি ফোন করুন — নিচের নম্বরগুলো বিশ্ববিদ্যালয়ের অফিসিয়াল নম্বর।</p>\n\n    <h3 data-t=\"cG1\" class=\"tbl-title\">ভর্তি সংক্রান্ত</h3>\n    <div class=\"table-wrap\">\n    <table>\n      <tr><th data-t=\"cH1a\">অফিস</th><th data-t=\"cH1b\">মোবাইল নম্বর</th></tr>\n      <tr><td data-t=\"cN0\">এডমিশন অফিস (হেল্পলাইন)</td><td class=\"fee\"><a href=\"tel:01313430064\" data-t=\"cP0\">০১৩১৩-৪৩০০৬৪</a></td></tr>\n    </table>\n    </div>\n\n    <h3 data-t=\"cG2\" class=\"tbl-title\">বিভাগীয় প্রধান</h3>\n    <div class=\"table-wrap\">\n    <table>\n      <tr><th data-t=\"cH2a\">বিভাগ</th><th data-t=\"cH2b\">মোবাইল নম্বর</th></tr>\n      <tr><td data-t=\"cN1\">সিএসই</td><td class=\"fee\"><a href=\"tel:01347531690\" data-t=\"cP1\">০১৩৪৭৫৩১৬৯০</a></td></tr>\n      <tr><td data-t=\"cN2\">ইইই</td><td class=\"fee\"><a href=\"tel:01347531691\" data-t=\"cP2\">০১৩৪৭৫৩১৬৯১</a></td></tr>\n      <tr><td data-t=\"cN3\">ইংরেজি</td><td class=\"fee\"><a href=\"tel:01347531692\" data-t=\"cP3\">০১৩৪৭৫৩১৬৯২</a></td></tr>\n      <tr><td data-t=\"cN4\">সোস্যালজি</td><td class=\"fee\"><a href=\"tel:01347531693\" data-t=\"cP4\">০১৩৪৭৫৩১৬৯৩</a></td></tr>\n      <tr><td data-t=\"cN5\">ব্যবসায় প্রশাসন</td><td class=\"fee\"><a href=\"tel:01347531694\" data-t=\"cP5\">০১৩৪৭৫৩১৬৯৪</a></td></tr>\n      <tr><td data-t=\"cN6\">আইন</td><td class=\"fee\"><a href=\"tel:01347531695\" data-t=\"cP6\">০১৩৪৭৫৩১৬৯৫</a></td></tr>\n    </table>\n    </div>\n\n    <h3 data-t=\"cG3\" class=\"tbl-title\">ক্যাম্পাস সুবিধা</h3>\n    <div class=\"table-wrap\">\n    <table>\n      <tr><th data-t=\"cH3a\">সুবিধা</th><th data-t=\"cH3b\">মোবাইল নম্বর</th></tr>\n      <tr><td data-t=\"cN7\">ছাত্র কল্যাণ উপদেষ্টা</td><td class=\"fee\"><a href=\"tel:01347531697\" data-t=\"cP7\">০১৩৪৭৫৩১৬৯৭</a></td></tr>\n      <tr><td data-t=\"cN8\">ল্যাংগুয়েজ এন্ড স্কিল ডেভেলপমেন্ট ইনস্টিটিউট</td><td class=\"fee\"><a href=\"tel:01347531698\" data-t=\"cP8\">০১৩৪৭৫৩১৬৯৮</a></td></tr>\n      <tr><td data-t=\"cN9\">ডে-কেয়ার সেন্টার</td><td class=\"fee\"><a href=\"tel:01347531699\" data-t=\"cP9\">০১৩৪৭৫৩১৬৯৯</a></td></tr>\n    </table>\n    </div>\n    <p data-t=\"cEmail\" class=\"tbl-note\">ইমেইল: <a href=\"mailto:info@uob.edu.bd\">info@uob.edu.bd</a></p>\n  </section>\n\n  </section>\n\n</main>\n\n<footer>\n  <div class=\"wrap\">\n    <strong data-t=\"footName\">ব্রাহ্মণবাড়িয়া বিশ্ববিদ্যালয়</strong>\n    <p data-t=\"footAddr\">১০২০/১৫ বাইপাস রোড, দাতিয়ারা (সিজেএম কোর্ট / এলজিইডি অফিসের পাশে)</p>\n    <p data-t=\"footContact\">হেল্পলাইন: <a href=\"tel:01313430064\" style=\"color:#fff\">০১৩১৩-৪৩০০৬৪</a> &nbsp;|&nbsp; ইমেইল: info@uob.edu.bd &nbsp;|&nbsp; <a href=\"https://uob.edu.bd/\" style=\"color:#fff\">uob.edu.bd</a></p>\n    <p data-t=\"footHub\"><small>এটি ব্রাহ্মণবাড়িয়া বিশ্ববিদ্যালয়ের ভর্তি সহায়ক পাতা (Admission Hub) — বিশ্ববিদ্যালয়ের অফিসিয়াল ওয়েবসাইট <a href=\"https://uob.edu.bd/\" style=\"color:#fff\">uob.edu.bd</a></small></p>\n    <p data-t=\"footCopy\"><small>© ২০২৬ ব্রাহ্মণবাড়িয়া বিশ্ববিদ্যালয়। সর্বস্বত্ব সংরক্ষিত।</small></p>\n    <p><small>Developed By Sheikh Anik Hossain</small></p>\n  </div>\n</footer>\n\n<div class=\"mobile-cta\">\n  <a data-t=\"ctaAsk\" href=\"#apply\">জিজ্ঞেস করুন</a>\n  <a data-t=\"ctaCall\" href=\"tel:01313430064\">ফোন করুন</a>\n</div>\n\n\n<script>\n// Language toggle — Bangla / English. Bangla is the default.\n// Original Bangla is captured from the page on load, so toggling back\n// restores it exactly. Choice is saved in localStorage.\nvar I18N_EN = {\"topLeft\": \"Spring 2027 — Admission Open\", \"topHelp\": \"Helpline: <a href=\\\"tel:01313430064\\\">01313-430064</a>\", \"siteName\": \"University of Brahmanbaria (Admission Hub)\", \"applyBtn\": \"Apply Now\", \"badge\": \"Spring 2027 Admission Open\", \"heroTitle\": \"All admission info in one place — fees, programs and how to apply.\", \"heroLead\": \"How much each program costs, what documents you need, and how to apply — everything is on this page. You apply on the university's official portal, and if you want to ask something, fill in the form.\", \"heroApply\": \"Apply Online\", \"heroCall\": \"Call Now\", \"heroNote\": \"For final admission information, please check with the Admission Office.\", \"secBenefits\": \"What you get here\", \"ben1no\": \"Benefit 01\", \"ben1t\": \"Day care for mothers\", \"ben1p\": \"A modern day care centre on campus so women students can attend classes with peace of mind. Study and motherhood — both can go together.\", \"ben2no\": \"Benefit 02\", \"ben2t\": \"Up to 70% discount for teachers\", \"ben2p\": \"Teachers working in primary, secondary, college and madrasa get up to 70% off tuition fees in masters programs (MBA, MA, MSS), with classes on Friday and Saturday.\", \"ben3no\": \"Benefit 03\", \"ben3t\": \"Scholarships and IELTS preparation\", \"ben3p\": \"Scholarships are available based on SSC and HSC results. Plus an IELTS preparation course run by British Council-certified teachers.\", \"secFees\": \"Programs and total fees\", \"secFeesSub\": \"The fees below are the total cost of the whole program. For discounts or instalment rules at admission time, please contact the Admission Office.\", \"tblUG\": \"Undergraduate Programs\", \"thProg\": \"Program\", \"thFee\": \"Total Fee\", \"progLLB\": \"LLB (Honours)\", \"feeLLB\": \"BDT 316,400\", \"feeCSE\": \"BDT 316,000\", \"feeEEE\": \"BDT 312,600\", \"feeBBA\": \"BDT 266,900\", \"feeEng\": \"BDT 247,600\", \"feeSoc\": \"BDT 190,400\", \"tblPG\": \"Graduate and Other Programs\", \"progMBA\": \"MBA (2 years / 1 year)\", \"feeMBA\": \"BDT 92,100 – 147,700\", \"feeMA\": \"BDT 80,700 – 113,300\", \"feeMSS\": \"BDT 65,900 – 98,700\", \"feePGD\": \"BDT 41,100\", \"feeIELTS\": \"BDT 8,000\", \"tblNote\": \"Fees and discount terms can change over time — it is best to confirm with the office before admission.\", \"secSteps\": \"How to apply\", \"step1t\": \"Apply online\", \"step1d\": \"Apply at admission.uob.edu.bd, or collect a form directly from the Admission Office.\", \"step2t\": \"Verification\", \"step2d\": \"Your SSC and HSC information and documents will be verified.\", \"docsT\": \"Documents you will need\", \"doc1\": \"Attested photocopies of all board mark sheets and testimonials / certificates\", \"doc2\": \"Recent colour passport-size photos — 3 copies\", \"doc3\": \"For O-Level / A-Level: attested copies of certificates and the A2 Statement of Entry\", \"doc4\": \"For freedom fighter quota: attested copies of the ministry certificate and gazette\", \"eligT\": \"Who can apply\", \"elig1\": \"CSE and EEE: combined SSC + HSC GPA 5 (at least 2.5 in each), or a total of 6.00 (at least 2.00 in one) — science background only\", \"elig2\": \"BBA, BA English, BSS Sociology: the same GPA rules — you can apply from any background\", \"elig3\": \"MBA (Regular): a 3-year bachelor degree, at least GPA 2.5 in SSC + HSC and CGPA 2.5 in the bachelor degree\", \"eligSrc\": \"Source: admission.uob.edu.bd — Admission Requirements. See details there, or call the office — <a href=\\\"tel:01313430064\\\">01313-430064</a>\", \"formT\": \"Want to ask something? Write to us\", \"formSub\": \"Leave your name and phone number — the Admission team will contact you.\", \"okT\": \"Thank you! Your information has reached us.\", \"okP\": \"The Admission team will contact you soon. Pressing Send on WhatsApp will get you a faster reply.\", \"labName\": \"Your name *\", \"labPhone\": \"Mobile / WhatsApp number *\", \"labProg\": \"Preferred program *\", \"labSSC\": \"SSC result (GPA)\", \"labHSC\": \"HSC result (GPA)\", \"labHon\": \"Honours / Bachelor result (CGPA) — only for MBA / Masters applicants\", \"labMsg\": \"Write your question if you have one\", \"submit\": \"Submit\", \"faqT\": \"Frequently asked questions\", \"faq1q\": \"When is the last date for admission?\", \"faq1a\": \"Please confirm the last date from the Admission Office — seats are limited, so it is best not to delay.\", \"faq2q\": \"Do I have to pay the fee at once, or can I pay in instalments?\", \"faq2a\": \"Instalment and discount rules differ by program. Call the office and they will tell you the exact rules.\", \"faq3q\": \"When do classes start?\", \"faq3a\": \"The class start date will be shared after your admission is confirmed.\", \"footName\": \"University of Brahmanbaria\", \"footAddr\": \"1020/15 Bypass Road, Datiyara (beside CJM Court / LGED Office)\", \"footContact\": \"Helpline: <a href=\\\"tel:01313430064\\\" style=\\\"color:#fff\\\">01313-430064</a> &nbsp;|&nbsp; Email: info@uob.edu.bd &nbsp;|&nbsp; <a href=\\\"https://uob.edu.bd/\\\" style=\\\"color:#fff\\\">uob.edu.bd</a>\", \"footCopy\": \"© 2026 University of Brahmanbaria. All rights reserved.\", \"ctaAsk\": \"Ask us\", \"ctaCall\": \"Call Now\", \"optChoose\": \"— Choose —\", \"optLLB\": \"LLB (Honours)\", \"footHub\": \"This is the University of Brahmanbaria admission information page (Admission Hub) — the university’s official website is <a href=\\\"https://uob.edu.bd/\\\" style=\\\"color:#fff\\\">uob.edu.bd</a>\", \"cTitle\": \"Contact Us\", \"cSub\": \"Call directly to ask about admission or a program — the numbers below are the university's official numbers.\", \"cG1\": \"Admission\", \"cG2\": \"Department Heads\", \"cG3\": \"Campus Facilities\", \"cH1a\": \"Office\", \"cH1b\": \"Mobile Number\", \"cH2a\": \"Department\", \"cH2b\": \"Mobile Number\", \"cH3a\": \"Facility\", \"cH3b\": \"Mobile Number\", \"cN0\": \"Admission Office (Helpline)\", \"cN1\": \"CSE\", \"cN2\": \"EEE\", \"cN3\": \"English\", \"cN4\": \"Sociology\", \"cN5\": \"Business Administration\", \"cN6\": \"Law\", \"cN7\": \"Student Welfare Adviser\", \"cN8\": \"Language & Skill Development Institute\", \"cN9\": \"Day Care Centre\", \"cP0\": \"01313-430064\", \"cP1\": \"01347531690\", \"cP2\": \"01347531691\", \"cP3\": \"01347531692\", \"cP4\": \"01347531693\", \"cP5\": \"01347531694\", \"cP6\": \"01347531695\", \"cP7\": \"01347531697\", \"cP8\": \"01347531698\", \"cP9\": \"01347531699\", \"cEmail\": \"Email: <a href=\\\"mailto:info@uob.edu.bd\\\">info@uob.edu.bd</a>\"};\nvar I18N_EN_PH = {\"phName\": \"Write your full name\", \"phSSC\": \"e.g. 5.00\", \"phHSC\": \"e.g. 4.50\", \"phHon\": \"e.g. CGPA 3.25\", \"phMsg\": \"Fees, scholarships, day care — write what you want to know...\"};\nvar I18N_TITLE_EN = \"Spring 2027 Admission — University of Brahmanbaria\";\nvar I18N_DESC_EN = \"Spring 2027 admission at the University of Brahmanbaria — programs, total fees, application steps and contact, on one page.\";\nvar __bn = {}, __bnPh = {}, __bnTitle = \"\", __bnDesc = \"\";\nfunction __captureLang(){\n  __bnTitle = document.title;\n  var md = document.querySelector('meta[name=\"description\"]');\n  __bnDesc = md ? md.getAttribute(\"content\") : \"\";\n  document.querySelectorAll(\"[data-t]\").forEach(function(el){ __bn[el.getAttribute(\"data-t\")] = el.innerHTML; });\n  document.querySelectorAll(\"[data-tph]\").forEach(function(el){ __bnPh[el.getAttribute(\"data-tph\")] = el.placeholder; });\n}\nfunction __applyLang(lang){\n  var en = (lang === \"en\");\n  document.documentElement.lang = en ? \"en\" : \"bn\";\n  document.title = en ? I18N_TITLE_EN : __bnTitle;\n  var md = document.querySelector('meta[name=\"description\"]');\n  if (md) md.setAttribute(\"content\", en ? I18N_DESC_EN : __bnDesc);\n  document.querySelectorAll(\"[data-t]\").forEach(function(el){\n    var k = el.getAttribute(\"data-t\");\n    if (en && I18N_EN[k] !== undefined) el.innerHTML = I18N_EN[k];\n    else if (__bn[k] !== undefined) el.innerHTML = __bn[k];\n  });\n  document.querySelectorAll(\"[data-tph]\").forEach(function(el){\n    var k = el.getAttribute(\"data-tph\");\n    if (en && I18N_EN_PH[k] !== undefined) el.placeholder = I18N_EN_PH[k];\n    else if (__bnPh[k] !== undefined) el.placeholder = __bnPh[k];\n  });\n  var btn = document.getElementById(\"langBtn\");\n  if (btn) btn.textContent = en ? \"বাংলা\" : \"English\";\n  try { localStorage.setItem(\"uob-lang\", en ? \"en\" : \"bn\"); } catch (e) {}\n}\nfunction L(bn, en){ return document.documentElement.lang === \"en\" ? en : bn; }\nfunction setLang(lang){ __applyLang(lang); }\n__captureLang();\n(function(){\n  var saved = null;\n  try { saved = localStorage.getItem(\"uob-lang\"); } catch (e) {}\n  if (saved === \"en\") __applyLang(\"en\");\n})();\ndocument.getElementById(\"langBtn\").addEventListener(\"click\", function(){\n  __applyLang(document.documentElement.lang === \"en\" ? \"bn\" : \"en\");\n});\n</script>\n<script>\n// Admission Hub — inquiry form: website-e save + WhatsApp, ek sathe.\n// ⚠️ REPLACE-ME: niche WORKER_URL-e tomar asol Worker URL bosao.\n//    Worker deploy korar pore Cloudflare je URL dibe (jemon\n//    https://uob-admission-hub.<tomar-subdomain>.workers.dev), oita\n//    ekhane bosate hobe. Na bosale website-e save hobe na,\n//    kintu WhatsApp tobuo khulbe.\nconst WORKER_URL = 'https://uob-admission.contacts-anik1.workers.dev';\nconst WHATSAPP_NUMBER = '8801313430064'; // Admission helpline (01313-430064)\nconst GOOGLE_FORM_ID = '1FAIpQLSePUS4YvnCVvWkemgbiS22rDtKbh0pXRJ9-bLz04_vRI2gDsg';\n// Google Form field mapping (entry IDs from the form page):\n// নাম: entry.2038080391, WhatsApp নম্বর: entry.96188559, মোবাইল নম্বর: entry.69340549,\n// আগ্রহী প্রোগ্রাম: entry.200628859, SSC GPA: entry.1015442536, HSC GPA: entry.1030504305,\n// অনার্স / CGPA: entry.488845724, প্রশ্ন: entry.1791643754\n\ndocument.getElementById('inquiry-form').addEventListener('submit', function(e){\n  e.preventDefault();\n  // Double-click bondho — ekbar chaplei joma hobe, duibar joma hobe na.\n  var submitBtn = document.getElementById('submitBtn');\n  if (submitBtn) { submitBtn.disabled = true; submitBtn.textContent = L('পাঠানো হচ্ছে…', 'Submitting…'); }\n  var name = document.getElementById('name').value.trim();\n  var phone = document.getElementById('phone').value.trim();\n  var program = document.getElementById('program').value;\n  var ssc = document.getElementById('ssc').value.trim();\n  var hsc = document.getElementById('hsc').value.trim();\n  var honours = document.getElementById('honours').value.trim();\n  var message = document.getElementById('message').value.trim();\n  var lines = ['ভর্তি বিষয়ে জানতে চাই', 'নাম: ' + name, 'ফোন: ' + phone, 'পছন্দের প্রোগ্রাম: ' + program];\n  if (ssc) lines.push('SSC GPA: ' + ssc);\n  if (hsc) lines.push('HSC GPA: ' + hsc);\n  if (honours) lines.push('অনার্স/CGPA: ' + honours);\n  if (message) lines.push('প্রশ্ন: ' + message);\n\n  var statusEl = document.getElementById('form-status');\n\n  // 1) Website-e save korar chesta — 5 second er beshi wait korbo na,\n  //    ar fail korleo WhatsApp atke thakbe na.\n  var savePromise;\n  if (WORKER_URL.indexOf('REPLACE-ME') === -1) {\n    var controller = new AbortController();\n    var timeoutId = setTimeout(function(){ controller.abort(); }, 5000);\n    savePromise = fetch(WORKER_URL + '/api/enquiry', {\n      method: 'POST',\n      headers: { 'Content-Type': 'application/json' },\n      body: JSON.stringify({ name: name, phone: phone, program: program, ssc_gpa: ssc, hsc_gpa: hsc, honours_cgpa: honours, message: message }),\n      signal: controller.signal\n    }).then(function(res){ return res.ok; }).catch(function(){ return false; })\n      .then(function(ok){ clearTimeout(timeoutId); return ok; });\n  } else {\n    savePromise = Promise.resolve(false);\n  }\n\n  // 1b) Google Form-eo joma — backup copy. Eta fire-and-forget:\n  // Google no-cors-e kono confirmation dey na, tai success card\n  // sudhu website save-er upor nirvor korbe. Khali field-e \"N/A\"\n  // pathano hoy, karon Google Form-e CGPA required.\n  try {\n    var gform = new URLSearchParams();\n    gform.append('entry.2038080391', name);\n    gform.append('entry.96188559', phone);\n    gform.append('entry.69340549', phone);\n    gform.append('entry.200628859', program);\n    gform.append('entry.1015442536', ssc || 'N/A');\n    gform.append('entry.1030504305', hsc || 'N/A');\n    gform.append('entry.488845724', honours || 'N/A');\n    gform.append('entry.1791643754', message || 'N/A');\n    gform.append('fvv', '1');\n    gform.append('pageHistory', '0');\n    fetch('https://docs.google.com/forms/d/e/' + GOOGLE_FORM_ID + '/formResponse', {\n      method: 'POST', mode: 'no-cors', body: gform\n    }).catch(function(){});\n  } catch (e) {}\n\n  savePromise.then(function(ok){\n    if (ok) {\n      // Click-ei joma hoye geche — WhatsApp-e Send chapuk ba na chapuk,\n      // tothyo admin-e pouche geche. Form lukiye sundor success card dekhao.\n      var form = document.getElementById('inquiry-form');\n      var success = document.getElementById('form-success');\n      if (form) form.style.display = 'none';\n      if (success) { success.hidden = false; success.scrollIntoView({behavior:'smooth', block:'center'}); }\n    } else if (statusEl) {\n      if (submitBtn) { submitBtn.disabled = false; submitBtn.textContent = L('জমা দিন', 'Submit'); }\n      statusEl.style.color = '#7a1f1a';\n      statusEl.textContent = L('এইবার ওয়েবসাইটে জমা হয়নি — WhatsApp খুলছে, ওখানে Send চাপলেই আপনার মেসেজটি Admission টিমের কাছে যাবে। চাইলে আবার জমা দিন চাপতে পারেন।', 'It did not save on the website this time — WhatsApp is opening, press Send there and your message will reach the Admission team. You can press Submit again if you like.');\n    }\n  });\n\n  // 2) WhatsApp — sob somoy khulbe, save hok ba na hok.\n  window.open('https://wa.me/' + WHATSAPP_NUMBER + '?text=' + encodeURIComponent(lines.join('\\n')), '_blank');\n});\n</script>\n</body>\n</html>\n";

async function serveStatic(request, env, path) {
  if (!env.ASSETS || typeof env.ASSETS.fetch !== "function") return null;
  let assetPath = path;
  if (assetPath === "/") assetPath = "/index.html";
  const assetUrl = new URL(request.url);
  assetUrl.pathname = assetPath;
  return env.ASSETS.fetch(new Request(assetUrl.toString(), request));
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method.toUpperCase();
    const base = { ...corsHeaders(request, env) };

    try {
      if (method === "OPTIONS") {
        return new Response(null, { status: 204, headers: securityHeaders(base) });
      }

      // Admin panel — Worker-er vitore embed kora, ASSETS diye na,
      // tai redirect loop hote pare na.
      if ((method === "GET" || method === "HEAD") && (path === "/admin" || path === "/admin.html")) {
        const headers = securityHeaders({ ...base, "Content-Type": "text/html; charset=utf-8" });
        return new Response(method === "HEAD" ? null : ADMIN_HTML, { status: 200, headers });
      }

      let response;
      if (path === "/" && method === "GET") {
        const asset = await serveStatic(request, env, path);
        if (asset && asset.status === 200) {
          const headers = new Headers(asset.headers);
          for (const [k, v] of Object.entries(securityHeaders(base))) {
            if (!headers.has(k)) headers.set(k, v);
          }
          return new Response(asset.body, { status: 200, headers });
        }
        // ASSETS-e index.html na pele embedded copy dao.
        return new Response(INDEX_HTML, {
          status: 200,
          headers: securityHeaders({ ...base, "Content-Type": "text/html; charset=utf-8" }),
        });
      } else if (path === "/index.html" && method === "GET") {
        const asset = await serveStatic(request, env, path);
        if (asset && asset.status === 200) {
          const headers = new Headers(asset.headers);
          for (const [k, v] of Object.entries(securityHeaders(base))) {
            if (!headers.has(k)) headers.set(k, v);
          }
          return new Response(asset.body, { status: 200, headers });
        }
        return new Response(INDEX_HTML, {
          status: 200,
          headers: securityHeaders({ ...base, "Content-Type": "text/html; charset=utf-8" }),
        });
      } else if (path === "/api/health" && method === "GET") {
        response = handleHealth(env);
      } else if (path === "/api/enquiry" && method === "POST") {
        response = await handleEnquiry(request, env);
      } else if (path === "/api/admin/login" && method === "POST") {
        response = await handleLogin(request, env);
      } else if (path === "/api/admin/logout" && method === "POST") {
        response = await handleLogout(request, env);
      } else if (path === "/api/admin/me" && method === "GET") {
        response = await handleMe(request, env);
      } else if (path === "/api/admin/enquiries" && method === "GET") {
        response = await handleListEnquiries(request, env, url);
      } else if (path.startsWith("/api/admin/enquiries/") && method === "PATCH") {
        response = await handleUpdateEnquiry(request, env, path.slice("/api/admin/enquiries/".length));
      } else if (path.startsWith("/api/")) {
        response = json({ error: "Not found" }, 404);
      } else if (method === "GET" || method === "HEAD") {
        const asset = await serveStatic(request, env, path);
        if (asset && asset.status === 200) {
          const headers = new Headers(asset.headers);
          for (const [k, v] of Object.entries(securityHeaders(base))) {
            if (!headers.has(k)) headers.set(k, v);
          }
          return new Response(asset.body, { status: 200, headers });
        }
        response = json({ error: "Not found" }, 404);
      } else {
        response = json({ error: "Not found" }, 404);
      }

      const headers = new Headers(response.headers);
      for (const [k, v] of Object.entries(securityHeaders(base))) {
        headers.set(k, v);
      }
      return new Response(response.body, { status: response.status, headers });
    } catch (err) {
      console.error("Unhandled error:", err);
      return json({ error: "Internal server error" }, 500, securityHeaders(base));
    }
  },
};
