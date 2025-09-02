import {
  type Connection,
  Server,
  type WSMessage,
  routePartykitRequest,
} from "partyserver";

import type { ChatMessage, Message } from "../shared";

/* ===== helpers (cookie/json/hash) ===== */
const AUTH_COOKIE = "jh_session";

function parseCookies(req: Request): Record<string, string> {
  const hdr = req.headers.get("cookie") || "";
  const out: Record<string, string> = {};
  hdr.split(";").forEach((p) => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function makeCookie(
  name: string,
  value: string,
  opts: { path?: string; httpOnly?: boolean; secure?: boolean; sameSite?: "Lax" | "Strict" | "None"; maxAge?: number } = {},
) {
  const {
    path = "/",
    httpOnly = true,
    secure = true,
    sameSite = "Lax",
    maxAge,
  } = opts;
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    `Path=${path}`,
    `SameSite=${sameSite}`,
    httpOnly ? "HttpOnly" : "",
    secure ? "Secure" : "",
    typeof maxAge === "number" ? `Max-Age=${maxAge}` : "",
  ].filter(Boolean);
  return parts.join("; ");
}
function json(data: unknown, status = 200, extra?: HeadersInit) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json", ...(extra || {}) } });
}
function bad(msg: string, code = 400) {
  return json({ error: msg }, code);
}
async function sha256Hex(str: string) {
  const enc = new TextEncoder();
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function randomHex(n = 32) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/* ===== Chat Durable Object ===== */
export class Chat extends Server<Env> {
  static options = { hibernate: true };

  messages = [] as ChatMessage[];

  broadcastMessage(message: Message, exclude?: string[]) {
    this.broadcast(JSON.stringify(message), exclude);
  }

  onStart() {
    // Messages table
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, user TEXT, role TEXT, content TEXT)`,
    );
    this.messages = this.ctx.storage.sql.exec(`SELECT * FROM messages`).toArray() as ChatMessage[];

    // Auth tables
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE,
        salt TEXT,
        password_hash TEXT,
        created_at INTEGER
      )`,
    );
    this.ctx.storage.sql.exec(
      `CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        user_id TEXT,
        expires INTEGER
      )`,
    );
  }

  onConnect(connection: Connection) {
    connection.send(JSON.stringify({ type: "all", messages: this.messages } satisfies Message));
  }

  saveMessage(message: ChatMessage) {
    const existing = this.messages.find((m) => m.id === message.id);
    if (existing) {
      this.messages = this.messages.map((m) => (m.id === message.id ? message : m));
    } else {
      this.messages.push(message);
    }
    this.ctx.storage.sql.exec(
      `INSERT INTO messages (id, user, role, content) VALUES ('${
        message.id
      }', '${message.user}', '${message.role}', ${JSON.stringify(message.content)})
       ON CONFLICT (id) DO UPDATE SET content = ${JSON.stringify(message.content)}`,
    );
  }

  onMessage(_connection: Connection, message: WSMessage) {
    this.broadcast(message);
    const parsed = JSON.parse(message as string) as Message;
    if (parsed.type === "add" || parsed.type === "update") this.saveMessage(parsed as ChatMessage);
  }

  /* ---------- HTTP API inside DO ---------- */
  private async authApi(request: Request): Promise<Response | null> {
    const url = new URL(request.url);
    const path = url.pathname;
    const cookies = parseCookies(request);
    const sessionToken = cookies[AUTH_COOKIE];

    const readBody = async <T = any>() => {
      try {
        return (await request.json()) as T;
      } catch {
        return {} as T;
      }
    };

    // POST /auth/signup
    if (request.method === "POST" && path === "/auth/signup") {
      const { email, password } = await readBody<{ email: string; password: string }>();
      if (!email || !password) return bad("Email and password required.");
      if (String(password).length < 6) return bad("Password must be at least 6 characters.");

      try {
        const id = crypto.randomUUID?.() ?? randomHex(16);
        const salt = randomHex(16);
        const password_hash = await sha256Hex(`${salt}:${password}`);
        const created_at = Date.now();
        this.ctx.storage.sql.exec(
          `INSERT INTO users (id, email, salt, password_hash, created_at)
           VALUES (${JSON.stringify(id)}, ${JSON.stringify(email.toLowerCase())}, '${salt}', '${password_hash}', ${created_at})`,
        );
        const token = randomHex(32);
        const ttl = 60 * 60 * 24 * 7; // 7 days
        const expires = Date.now() + ttl * 1000;
        this.ctx.storage.sql.exec(
          `INSERT INTO sessions (token, user_id, expires) VALUES ('${token}', ${JSON.stringify(id)}, ${expires})`,
        );
        return json(
          { ok: true, user: { id, email: email.toLowerCase() } },
          200,
          { "set-cookie": makeCookie(AUTH_COOKIE, token, { maxAge: ttl }) },
        );
      } catch {
        return bad("Email already exists?", 409);
      }
    }

    // POST /auth/login
    if (request.method === "POST" && path === "/auth/login") {
      const { email, password } = await readBody<{ email: string; password: string }>();
      if (!email || !password) return bad("Email and password required.");

      const row = this.ctx.storage.sql
        .exec(
          `SELECT id, email, salt, password_hash FROM users WHERE email=${JSON.stringify(
            email.toLowerCase(),
          )} LIMIT 1`,
        )
        .toArray()[0] as { id: string; email: string; salt: string; password_hash: string } | undefined;

      if (!row) return bad("Invalid credentials.", 401);
      const check = await sha256Hex(`${row.salt}:${password}`);
      if (check !== row.password_hash) return bad("Invalid credentials.", 401);

      const token = randomHex(32);
      const ttl = 60 * 60 * 24 * 7;
      const expires = Date.now() + ttl * 1000;
      this.ctx.storage.sql.exec(
        `INSERT INTO sessions (token, user_id, expires) VALUES ('${token}', '${row.id}', ${expires})`,
      );
      return json(
        { ok: true, user: { id: row.id, email: row.email } },
        200,
        { "set-cookie": makeCookie(AUTH_COOKIE, token, { maxAge: ttl }) },
      );
    }

    // POST /auth/logout
    if (request.method === "POST" && path === "/auth/logout") {
      if (sessionToken) this.ctx.storage.sql.exec(`DELETE FROM sessions WHERE token='${sessionToken}'`);
      return json({ ok: true }, 200, { "set-cookie": makeCookie(AUTH_COOKIE, "", { maxAge: 0 }) });
    }

    // GET /auth/me
    if (request.method === "GET" && path === "/auth/me") {
      if (!sessionToken) return json({ user: null });
      const now = Date.now();
      const sess = this.ctx.storage.sql
        .exec(`SELECT token, user_id, expires FROM sessions WHERE token='${sessionToken}' LIMIT 1`)
        .toArray()[0] as { token: string; user_id: string; expires: number } | undefined;
      if (!sess || sess.expires < now) {
        if (sess) this.ctx.storage.sql.exec(`DELETE FROM sessions WHERE token='${sessionToken}'`);
        return json({ user: null }, 200, { "set-cookie": makeCookie(AUTH_COOKIE, "", { maxAge: 0 }) });
      }
      const user = this.ctx.storage.sql
        .exec(`SELECT id, email FROM users WHERE id='${sess.user_id}' LIMIT 1`)
        .toArray()[0] as { id: string; email: string } | undefined;
      return json({ user: user ?? null });
    }

    return null;
  }

  // Handle HTTP requests that reach the DO (non-WebSocket)
  async onRequest(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/auth/")) {
      const res = await this.authApi(request);
      if (res) return res;
      return new Response("Not found", { status: 404 });
    }
    return new Response("Not implemented", { status: 404 });
  }
}

/* ===== Worker entry: forward /auth/* to DO, else PartyServer/static ===== */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Binding name can be "chat" (recommended) or "Chat" (your current JSON).
    const chatBinding = (env as any).chat ?? (env as any).Chat;

    if (url.pathname.startsWith("/auth/")) {
      const id = chatBinding.idFromName("global");
      const stub = chatBinding.get(id);
      const res = await stub.fetch(request);
      if (res.status !== 404) return res;
    }

    const routed = await routePartykitRequest(request, { ...env });
    if (routed) return routed;

    return env.ASSETS.fetch(request);
  },
} satisfies ExportedHandler<Env>;
