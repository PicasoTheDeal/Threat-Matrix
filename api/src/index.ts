export interface Env {
  DB?: D1Database;
  NEWS_API_KEY?: string;
  TURNSTILE_SECRET_KEY?: string;
}

function sanitizeInputString(input: string): string {
  if (typeof input !== "string") return "";
  return input.replace(/[<>'"\\/;()]/g, "").trim();
}

async function verifyTurnstile(token: string, secret: string): Promise<boolean> {
  const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}`,
  });
  const data = await resp.json() as any;
  return data.success === true;
}

async function hashPassword(password: string): Promise<{ hash: string; salt: string }> {
  const encoder = new TextEncoder();
  const saltBuffer = crypto.getRandomValues(new Uint8Array(16));
  const passwordBuffer = encoder.encode(password);
  const combined = new Uint8Array(saltBuffer.length + passwordBuffer.length);
  combined.set(saltBuffer);
  combined.set(passwordBuffer, saltBuffer.length);
  const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  const saltHex = Array.from(saltBuffer).map(b => b.toString(16).padStart(2, "0")).join("");
  return { hash: hashHex, salt: saltHex };
}

async function verifyPassword(password: string, salt: string, storedHash: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const saltArray = new Uint8Array(salt.match(/.{1,2}/g)!.map(byte => parseInt(byte, 16)));
  const passwordBuffer = encoder.encode(password);
  const combined = new Uint8Array(saltArray.length + passwordBuffer.length);
  combined.set(saltArray);
  combined.set(passwordBuffer, saltArray.length);
  const hashBuffer = await crypto.subtle.digest("SHA-256", combined);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
  return hashHex === storedHash;
}

async function generateToken(): Promise<string> {
  const buffer = crypto.getRandomValues(new Uint8Array(32));
  return Array.from(buffer).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function getUserFromToken(db: D1Database, token: string): Promise<any> {
  const stmt = db.prepare("SELECT id, username FROM users WHERE token = ?").bind(token);
  const user = await stmt.first();
  return user || null;
}

async function getInteractionSnapshot(db: D1Database, logId: string, userId: number | null) {
  const likeRow = await db.prepare("SELECT COUNT(*) as cnt FROM headline_likes WHERE log_id = ?").bind(logId).first() as any;
  const likes = likeRow.cnt;
  let liked = false;
  if (userId) {
    const userLike = await db.prepare("SELECT 1 FROM headline_likes WHERE log_id = ? AND user_id = ?").bind(logId, userId).first();
    liked = !!userLike;
  }
  const commentsResult = await db.prepare(
    "SELECT hc.id, hc.content, hc.created_at, hc.user_id, u.username FROM headline_comments hc JOIN users u ON hc.user_id = u.id WHERE hc.log_id = ? ORDER BY hc.created_at ASC"
  ).bind(logId).all();
  return {
    likes,
    liked,
    comments: commentsResult.results.map((c: any) => ({
      id: c.id,
      content: c.content,
      created_at: c.created_at,
      user_id: c.user_id,
      username: c.username,
    })),
  };
}

async function ensureTables(db: D1Database) {
  await db.prepare("PRAGMA foreign_keys = ON").run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      token TEXT
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS user_parameters (
      user_id INTEGER PRIMARY KEY REFERENCES users(id),
      tags TEXT NOT NULL DEFAULT '[]'
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS headline_likes (
      user_id INTEGER NOT NULL,
      log_id TEXT NOT NULL,
      PRIMARY KEY (user_id, log_id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS headline_comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      log_id TEXT NOT NULL,
      user_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `).run();
}

//

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const ALLOWED_ORIGINS = [
      "https://threat-matrix.pages.dev",
    ];
    const origin = request.headers.get("Origin");
    const corsHeaders = {
      "Access-Control-Allow-Origin": ALLOWED_ORIGINS.includes(origin || "") ? origin! : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    if (!env.DB) {
      return new Response(JSON.stringify({ error: "Database not configured. Check D1 binding in wrangler.toml." }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    await ensureTables(env.DB);

    const url = new URL(request.url);
    const pathname = url.pathname;

    if (pathname === "/api/signup" && request.method === "POST") {
      try {
        const payload = await request.json() as any;
        const username = sanitizeInputString(payload?.username);
        const password = payload?.password;
        const turnstileToken = payload?.turnstileToken;

        if (!env.TURNSTILE_SECRET_KEY) {
          return new Response(JSON.stringify({ error: "Turnstile not configured." }), { status: 500, headers: corsHeaders });
        }
        if (!turnstileToken || !(await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY))) {
          return new Response(JSON.stringify({ error: "Turnstile verification failed." }), { status: 400, headers: corsHeaders });
        }

        if (!username || !password) {
          return new Response(JSON.stringify({ error: "Missing credential blocks." }), { status: 400, headers: corsHeaders });
        }

        if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
          return new Response(JSON.stringify({ error: "Username contains illegal characters." }), { status: 400, headers: corsHeaders });
        }

        const hasUpper = /[A-Z]/.test(password);
        const hasLower = /[a-z]/.test(password);
        const hasNumber = /[0-9]/.test(password);
        const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
        const isLongEnough = password.length >= 128;

        if (!isLongEnough || !hasUpper || !hasLower || !hasNumber || !hasSpecial) {
          return new Response(
            JSON.stringify({ error: "Password does not meet 128-character strict complexity standard." }),
            { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } }
          );
        }

        const { hash, salt } = await hashPassword(password);
        const token = await generateToken();

        const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
        if (existing) {
          return new Response(JSON.stringify({ error: "Username already registered." }), { status: 409, headers: corsHeaders });
        }

        await env.DB.prepare("INSERT INTO users (username, password_hash, salt, token) VALUES (?, ?, ?, ?)")
          .bind(username, hash, salt, token)
          .run();

        return new Response(
          JSON.stringify({ success: true, message: "Identity credentials registered to system core.", token }),
          { status: 201, headers: { "Content-Type": "application/json", ...corsHeaders } }
        );
      } catch (err: any) {
        return new Response(JSON.stringify({ error: `Internal signup error: ${err.message}` }), { status: 500, headers: corsHeaders });
      }
    }

    if (pathname === "/api/login" && request.method === "POST") {
      try {
        const payload = await request.json() as any;
        const username = sanitizeInputString(payload?.username);
        const password = payload?.password;
        const turnstileToken = payload?.turnstileToken;

        if (!env.TURNSTILE_SECRET_KEY) {
          return new Response(JSON.stringify({ error: "Turnstile not configured." }), { status: 500, headers: corsHeaders });
        }
        if (!turnstileToken || !(await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY))) {
          return new Response(JSON.stringify({ error: "Turnstile verification failed." }), { status: 400, headers: corsHeaders });
        }

        if (!username || !password) {
          return new Response(JSON.stringify({ error: "Missing identity blocks." }), { status: 400, headers: corsHeaders });
        }

        const user = await env.DB.prepare("SELECT id, password_hash, salt, token FROM users WHERE username = ?").bind(username).first() as any;
        if (!user) {
          return new Response(JSON.stringify({ error: "Invalid identity credentials." }), { status: 401, headers: corsHeaders });
        }

        const valid = await verifyPassword(password, user.salt, user.password_hash);
        if (!valid) {
          return new Response(JSON.stringify({ error: "Invalid identity credentials." }), { status: 401, headers: corsHeaders });
        }

        const token = user.token || (await generateToken());
        if (!user.token) {
          await env.DB.prepare("UPDATE users SET token = ? WHERE id = ?").bind(token, user.id).run();
        }

        return new Response(
          JSON.stringify({ success: true, token }),
          { status: 200, headers: { "Content-Type": "application/json", ...corsHeaders } }
        );
      } catch (err: any) {
        return new Response(JSON.stringify({ error: `Login error: ${err.message}` }), { status: 500, headers: corsHeaders });
      }
    }

    if (pathname === "/api/parameters" && request.method === "GET") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      if (!token) {
        return new Response(JSON.stringify({ error: "Authorization required." }), { status: 401, headers: corsHeaders });
      }
      const user = await getUserFromToken(env.DB, token);
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid token." }), { status: 401, headers: corsHeaders });
      }
      const row = await env.DB.prepare("SELECT tags FROM user_parameters WHERE user_id = ?").bind(user.id).first() as any;
      const tags = row ? JSON.parse(row.tags) : [];
      return new Response(JSON.stringify({ tags }), { headers: corsHeaders });
    }

    if (pathname === "/api/parameters" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      if (!token) {
        return new Response(JSON.stringify({ error: "Authorization required." }), { status: 401, headers: corsHeaders });
      }
      const user = await getUserFromToken(env.DB, token);
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid token." }), { status: 401, headers: corsHeaders });
      }
      try {
        const payload = await request.json() as any;
        const tags = Array.isArray(payload.tags) ? payload.tags : [];
        await env.DB.prepare("INSERT INTO user_parameters (user_id, tags) VALUES (?, ?) ON CONFLICT(user_id) DO UPDATE SET tags = ?")
          .bind(user.id, JSON.stringify(tags), JSON.stringify(tags))
          .run();
        return new Response(JSON.stringify({ success: true }), { headers: corsHeaders });
      } catch (err) {
        return new Response(JSON.stringify({ error: "Failed to update parameters." }), { status: 500, headers: corsHeaders });
      }
    }

    if (pathname === "/api/interact" && request.method === "GET") {
      const logIds = url.searchParams.get("log_ids");
      if (!logIds) {
        return new Response(JSON.stringify({ error: "log_ids required." }), { status: 400, headers: corsHeaders });
      }
      const ids = logIds.split(",").map(id => id.trim()).filter(id => id.length > 0);
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      let userId = null;
      if (token) {
        const user = await getUserFromToken(env.DB, token);
        userId = user ? user.id : null;
      }

      const result: any = {};
      for (const logId of ids) {
        result[logId] = await getInteractionSnapshot(env.DB, logId, userId);
      }
      return new Response(JSON.stringify(result), { headers: corsHeaders });
    }

    if (pathname === "/api/interact" && request.method === "POST") {
      const authHeader = request.headers.get("Authorization") || "";
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : "";
      if (!token) {
        return new Response(JSON.stringify({ error: "Authorization required." }), { status: 401, headers: corsHeaders });
      }
      const user = await getUserFromToken(env.DB, token);
      if (!user) {
        return new Response(JSON.stringify({ error: "Invalid token." }), { status: 401, headers: corsHeaders });
      }

      try {
        const payload = await request.json() as any;
        const { action, log_id, content, comment_id, turnstileToken } = payload;
        if (!log_id) {
          return new Response(JSON.stringify({ error: "log_id required." }), { status: 400, headers: corsHeaders });
        }

        if (action === "like") {
          await env.DB.prepare("INSERT OR IGNORE INTO headline_likes (user_id, log_id) VALUES (?, ?)").bind(user.id, log_id).run();
          const snapshot = await getInteractionSnapshot(env.DB, log_id, user.id);
          return new Response(JSON.stringify({ success: true, interaction: snapshot }), { headers: corsHeaders });
        } 
        else if (action === "unlike") {
          await env.DB.prepare("DELETE FROM headline_likes WHERE user_id = ? AND log_id = ?").bind(user.id, log_id).run();
          const snapshot = await getInteractionSnapshot(env.DB, log_id, user.id);
          return new Response(JSON.stringify({ success: true, interaction: snapshot }), { headers: corsHeaders });
        } 
        else if (action === "comment") {
          if (!env.TURNSTILE_SECRET_KEY) {
            return new Response(JSON.stringify({ error: "Turnstile not configured." }), { status: 500, headers: corsHeaders });
          }
          if (!turnstileToken || !(await verifyTurnstile(turnstileToken, env.TURNSTILE_SECRET_KEY))) {
            return new Response(JSON.stringify({ error: "Turnstile verification failed." }), { status: 400, headers: corsHeaders });
          }

          if (!content || content.trim() === "") {
            return new Response(JSON.stringify({ error: "Content required." }), { status: 400, headers: corsHeaders });
          }

          if (/https?:\/\//i.test(content)) {
            return new Response(JSON.stringify({ error: "Links are not allowed in comments." }), { status: 400, headers: corsHeaders });
          }

          await env.DB.prepare("INSERT INTO headline_comments (log_id, user_id, content) VALUES (?, ?, ?)").bind(log_id, user.id, content.trim()).run();
          const snapshot = await getInteractionSnapshot(env.DB, log_id, user.id);
          return new Response(JSON.stringify({ success: true, interaction: snapshot }), { headers: corsHeaders });
        } 
        else if (action === "edit_comment") {
          if (!comment_id || !content || content.trim() === "") {
            return new Response(JSON.stringify({ error: "comment_id and content required." }), { status: 400, headers: corsHeaders });
          }
          const existing = await env.DB.prepare("SELECT id FROM headline_comments WHERE id = ? AND user_id = ?").bind(comment_id, user.id).first();
          if (!existing) {
            return new Response(JSON.stringify({ error: "Comment not found or not owned by you." }), { status: 403, headers: corsHeaders });
          }
          await env.DB.prepare("UPDATE headline_comments SET content = ? WHERE id = ?").bind(content.trim(), comment_id).run();
          const snapshot = await getInteractionSnapshot(env.DB, log_id, user.id);
          return new Response(JSON.stringify({ success: true, interaction: snapshot }), { headers: corsHeaders });
        } 
        else if (action === "delete_comment") {
          if (!comment_id) {
            return new Response(JSON.stringify({ error: "comment_id required." }), { status: 400, headers: corsHeaders });
          }
          const existing = await env.DB.prepare("SELECT id FROM headline_comments WHERE id = ? AND user_id = ?").bind(comment_id, user.id).first();
          if (!existing) {
            return new Response(JSON.stringify({ error: "Comment not found or not owned by you." }), { status: 403, headers: corsHeaders });
          }
          await env.DB.prepare("DELETE FROM headline_comments WHERE id = ?").bind(comment_id).run();
          const snapshot = await getInteractionSnapshot(env.DB, log_id, user.id);
          return new Response(JSON.stringify({ success: true, interaction: snapshot }), { headers: corsHeaders });
        } 
        else {
          return new Response(JSON.stringify({ error: "Invalid action." }), { status: 400, headers: corsHeaders });
        }
      } catch (err: any) {
        return new Response(JSON.stringify({ error: `Interaction error: ${err.message}` }), { status: 500, headers: corsHeaders });
      }
    }

    if (pathname === "/api/logs" && request.method === "GET") {
      const safeFetch = async (targetUrl: string, init?: RequestInit): Promise<any> => {
        try {
          const res = await fetch(targetUrl, init);
          if (!res.ok) throw new Error(`Status ${res.status}`);
          return await res.json();
        } catch (e) {
          return undefined;
        }
      };

      try {
        const defaultHeaders = { "User-Agent": "ThreatMatrix/1.0 (Cloudflare Worker)" };
        const cisaPromise = safeFetch("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", { headers: defaultHeaders });
        const circlPromise = safeFetch("https://cve.circl.lu/api/last");

        const today = new Date().toISOString().split("T")[0];
        const twoDaysAgo = new Date(Date.now() - 2 * 86400000).toISOString().split("T")[0];
        const nvdPromise = safeFetch(
          `https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=${twoDaysAgo}T00:00:00.000&pubEndDate=${today}T23:59:59.999&resultsPerPage=10`
        );

        const [cisaData, circlData, nvdData] = (await Promise.all([
          cisaPromise, circlPromise, nvdPromise
        ])) as any[];

        const cisaLogs = Array.isArray(cisaData?.vulnerabilities) ? cisaData.vulnerabilities.slice(0, 15).map((v: any) => ({
          id: sanitizeInputString(v?.cveID || "UNKNOWN"),
          title: sanitizeInputString(v?.vulnerabilityName || "Unknown Vuln"),
          excerpt: sanitizeInputString(v?.shortDescription || "No description"),
          category: "Official CISA KEV",
          date: v?.dateAdded || "Unknown",
          source: "CISA",
          url: v?.cveID ? `https://nvd.nist.gov/vuln/detail/${v.cveID}` : "#",
          impact: "CRITICAL",
          readTime: 5,
        })) : [];

        const circlLogs = Array.isArray(circlData)
          ? circlData
              .filter((cve: any) => cve && typeof cve.id === "string")
              .slice(0, 10)
              .map((cve: any) => ({
                id: sanitizeInputString(cve.id),
                title: sanitizeInputString(cve.id),
                excerpt: sanitizeInputString(cve.summary?.slice(0, 200) || "No description"),
                category: "CVE Feed",
                date: cve.Published?.split("T")[0] || "Unknown",
                source: "CIRCL",
                url: cve.id.startsWith("GHSA-") ? `https://github.com/advisories/${cve.id}` : `https://nvd.nist.gov/vuln/detail/${cve.id}`,
                impact: "HIGH",
                readTime: 4,
              }))
          : [];

        const nvdLogs = Array.isArray(nvdData?.vulnerabilities)
          ? nvdData.vulnerabilities.slice(0, 10).map((item: any) => {
              const cve = item?.cve || {};
              const desc = cve.descriptions?.find((d: any) => d.lang === "en")?.value || "";
              return {
                id: sanitizeInputString(cve.id || "UNKNOWN"),
                title: sanitizeInputString(cve.id || "UNKNOWN"),
                excerpt: sanitizeInputString(desc.slice(0, 200)),
                category: "NVD Vulnerability",
                date: cve.published?.split("T")[0] || "Unknown",
                source: "NVD",
                url: cve.id ? `https://nvd.nist.gov/vuln/detail/${cve.id}` : "#",
                impact: "HIGH",
                readTime: 5,
              };
            })
          : [];

        const combinedLogs = [...cisaLogs, ...circlLogs, ...nvdLogs].sort((a, b) => {
          const dateA = Date.parse(a.date);
          const dateB = Date.parse(b.date);
          if (isNaN(dateA) && isNaN(dateB)) return 0;
          if (isNaN(dateA)) return 1;
          if (isNaN(dateB)) return -1;
          return dateB - dateA;
        });

        return new Response(JSON.stringify(combinedLogs), {
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      } catch (e: any) {
        return new Response(JSON.stringify({ error: `Aggregation failure: ${e.message}` }), {
          status: 500,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        });
      }
    }

    return new Response(JSON.stringify({ error: "Route unmapped" }), { status: 404, headers: corsHeaders });
  },
};