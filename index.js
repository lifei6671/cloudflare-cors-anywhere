/**
 * Cloudflare Workers CORS 代理（方案三：强约束 + 强限流 + 默认演示页）
 *
 * 安全策略：
 * 1) 默认拒绝：KV 白名单缺失/为空 → 403
 * 2) 只允许白名单 Origin（whitelistOrigins：正则数组）
 * 3) 只允许白名单 hostname（whitelistHostnames：字符串数组）
 * 4) OPTIONS 预检不转发：本地直接返回
 * 5) 强限流（Durable Object）：按 IP + Origin 计数，超限直接拒绝
 *
 * KV 绑定名：KV
 * - whitelistOrigins: JSON 数组（字符串正则），允许的前端 Origin
 * - whitelistHostnames: JSON 数组（字符串），允许的目标 hostname
 *
 * 环境变量：
 * - LIMIT_10M_PER_IP_ORIGIN: 每 10 分钟限流阈值 (默认 300)
 * - LIMIT_1D_PER_IP_ORIGIN: 每天限流阈值 (默认 5000)
 *
 * 使用：
 * - 推荐：/?url=<encodeURIComponent(targetUrl)>
 * - 兼容旧方式：/?<encodeURIComponent(encodeURIComponent(targetUrl))>
 */

/** CORS 预检缓存时间（秒） */
const PREFLIGHT_MAX_AGE = 600; // 10 分钟

/** 是否允许携带 cookie（credentials）。默认 false 更安全 */
const ALLOW_CREDENTIALS = false;

/** 是否强制要求 Origin 头存在。默认 true：没有 Origin 直接拒绝 */
const REQUIRE_ORIGIN_HEADER = true;

/** 限流阈值：按需调整 */
const DEFAULT_LIMIT_10M_PER_IP_ORIGIN = 300;   // 每 10 分钟：同一 IP + Origin 最多 300 次
const DEFAULT_LIMIT_1D_PER_IP_ORIGIN = 5000;  // 每天：同一 IP + Origin 最多 5000 次

async function kvGetJsonArray(kv, key) {
  if (!kv) return [];
  try {
    const v = await kv.get(key, { type: "json" });
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function compileRegexList(patterns) {
  const out = [];
  for (const p of patterns) {
    if (typeof p !== "string") continue;
    try {
      out.push(new RegExp(p));
    } catch {
      // 忽略非法正则
    }
  }
  return out;
}

function matchAny(text, regexList) {
  if (typeof text !== "string") return false;
  if (!regexList || regexList.length === 0) return false;
  return regexList.some((re) => re.test(text));
}

/** 解析目标 URL：优先 ?url=，否则走 legacy 双解码 */
function parseTargetUrl(requestUrl) {
  const u = new URL(requestUrl);

  // 推荐方式：?url=
  const urlParam = u.searchParams.get("url");
  if (urlParam) {
    try {
      return decodeURIComponent(urlParam);
    } catch {
      return null;
    }
  }

  // 兼容旧版：把 ? 后面的全部当作目标 URL，并双重解码
  if (u.search && u.search.startsWith("?") && u.search.length > 1) {
    const raw = u.search.slice(1);
    try {
      return decodeURIComponent(decodeURIComponent(raw));
    } catch {
      return null;
    }
  }

  return null;
}

/** 基础 SSRF 防护：只允许 http/https，禁 localhost/私网字面量 IP */
function isTargetUrlSafe(target) {
  let t;
  try {
    t = new URL(target);
  } catch {
    return false;
  }

  if (t.protocol !== "http:" && t.protocol !== "https:") return false;

  const host = t.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return false;

  // 禁止字面量 IPv4 私网/保留段
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    const parts = host.split(".").map(Number);
    if (parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;

    const [a, b] = parts;
    if (a === 10) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 127) return false;
    if (a === 169 && b === 254) return false;
  }

  return true;
}

/** 写入 CORS 头（白名单通过后才会调用） */
function applyCorsHeaders(headers, origin, isPreflight, req) {
  headers.set("Access-Control-Allow-Origin", origin);
  headers.set("Vary", "Origin");

  if (ALLOW_CREDENTIALS) headers.set("Access-Control-Allow-Credentials", "true");

  if (isPreflight) {
    const m = req.headers.get("access-control-request-method");
    const h = req.headers.get("access-control-request-headers");
    if (m) headers.set("Access-Control-Allow-Methods", m);
    if (h) headers.set("Access-Control-Allow-Headers", h);
    headers.set("Access-Control-Max-Age", String(PREFLIGHT_MAX_AGE));
  }

  return headers;
}

/** 构造转发请求头（过滤不该转发的头） */
function buildForwardHeaders(req) {
  const out = new Headers();

  for (const [k, v] of req.headers.entries()) {
    const key = k.toLowerCase();

    // 不转发来源相关头，避免泄露/干扰上游
    if (key === "origin") continue;
    if (key === "referer") continue;

    // 禁止伪造 Cloudflare/代理链路信息
    if (key.startsWith("cf-")) continue;
    if (key.startsWith("x-forwarded-")) continue;

    // hop-by-hop 头不应被代理转发
    if (["connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailers","transfer-encoding","upgrade"].includes(key)) {
      continue;
    }

    // 内部保留头
    if (key === "x-cors-headers") continue;

    out.set(k, v);
  }

  // 允许调用方通过 x-cors-headers 注入额外请求头（例如 Authorization）
  const extra = req.headers.get("x-cors-headers");
  if (extra) {
    try {
      const obj = JSON.parse(extra);
      if (obj && typeof obj === "object") {
        for (const [k, v] of Object.entries(obj)) {
          if (typeof k === "string" && typeof v === "string") out.set(k, v);
        }
      }
    } catch {
      // JSON 不合法则忽略
    }
  }

  return out;
}

/** HTML 转义，避免把输入内容直接注入页面 */
function esc(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

/**
 * 默认演示页面：给浏览器直接打开时展示
 * - 不做代理转发
 * - 展示推荐用法、JS/curl 示例
 */
function demoPage(request, extra = {}) {
  const u = new URL(request.url);
  const base = `${u.origin}/`;
  const sampleTarget = extra.sampleTarget || "https://api.example.com/data?x=1&y=2";
  const sampleUrl = `${base}?url=${encodeURIComponent(sampleTarget)}`;

  const ip = extra.ip || "";
  const origin = extra.origin || "";
  const note = extra.note || "";

  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>CORS Proxy Demo</title>
  <style>
    body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Arial;background:#f6f7fb;margin:0;padding:24px;color:#111}
    .card{max-width:920px;margin:0 auto;background:#fff;border-radius:16px;box-shadow:0 10px 30px rgba(0,0,0,.08);padding:22px}
    h1{margin:0 0 8px;font-size:22px}
    p{margin:10px 0;color:#444;line-height:1.6}
    .muted{color:#666}
    code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono","Courier New",monospace}
    pre{background:#f2f3f6;border-radius:12px;padding:14px;overflow:auto}
    .row{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px}
    .btn{display:inline-block;padding:10px 14px;border-radius:12px;background:#111;color:#fff;text-decoration:none;font-weight:600}
    .btn.secondary{background:#e9ecf2;color:#111}
    .tag{display:inline-block;background:#f2f3f6;border-radius:999px;padding:6px 10px;margin-right:8px;font-size:12px;color:#444}
    hr{border:none;border-top:1px solid #eee;margin:18px 0}
  </style>
</head>
<body>
  <div class="card">
    <h1>Cloudflare Worker CORS 代理</h1>
    <p class="muted">这是一个“默认拒绝”的受限 CORS 代理：仅允许来自白名单 Origin 的请求，并且只代理到白名单 hostname。</p>

    <div class="row">
      ${ip ? `<span class="tag">IP: ${esc(ip)}</span>` : ""}
      ${origin ? `<span class="tag">Origin: ${esc(origin)}</span>` : ""}
      ${note ? `<span class="tag">${esc(note)}</span>` : ""}
    </div>

    <hr />

    <p><b>推荐用法</b>：把目标 URL 放在 <code>?url=</code> 参数里（需要 URL 编码一次）</p>
    <pre>${esc(sampleUrl)}</pre>

    <div class="row">
      <a class="btn" href="${esc(sampleUrl)}" target="_blank" rel="noreferrer">打开示例请求</a>
      <a class="btn secondary" href="${esc(base)}" rel="noreferrer">刷新本页</a>
    </div>

    <hr />

    <p><b>浏览器 JS 示例</b></p>
    <pre>const proxy = ${JSON.stringify(base)};
const target = ${JSON.stringify(sampleTarget)};
const url = proxy + "?url=" + encodeURIComponent(target);

const resp = await fetch(url, { method: "GET" });
console.log("status:", resp.status);
console.log(await resp.text());</pre>

    <p><b>curl 示例</b></p>
    <pre>PROXY=${esc(base)}
TARGET=${esc(sampleTarget)}
curl -i "$PROXY?url=$(python -c 'import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1], safe=\"\"))' "$TARGET")"</pre>

    <p class="muted">
      如果返回 403：通常是 <code>Origin</code> 不在白名单，或目标域名不在 <code>whitelistHostnames</code> 中，或触发限流（429）。
    </p>

    <div class="row" style="margin-top: 24px; font-size: 13px; color: #666;">
      <span>GitHub:</span>
      <a href="https://github.com/lifei6671/cloudflare-cors-anywhere" target="_blank" style="color: #444;">Current Repo (lifei6671)</a>
      <span style="margin: 0 6px;">|</span>
      <a href="https://github.com/Zibri/cloudflare-cors-anywhere" target="_blank" style="color: #444;">Original Repo (Zibri)</a>
    </div>
  </div>
</body>
</html>`;
}

/**
 * Durable Object：限流器（固定窗口）
 * - 10 分钟窗口 + 日窗口
 * - key 由外部传入（例如 ip|origin）
 *
 * 自动过期清理策略：
 * - 10 分钟桶 key：写入时设置 TTL（默认 2 小时）
 * - 日桶 key：写入时设置 TTL（默认 2 天）
 * 这样 DO 存储会自动清理过期 key，避免长期累积占用存储。
 */
export class RateLimiterDO {
  constructor(state, env) {
    this.state = state;
    this.env = env;
  }

  async fetch(request) {
    if (request.method !== "POST") return new Response("Method Not Allowed", { status: 405 });

    const body = await request.json().catch(() => null);
    if (!body || typeof body.key !== "string") return new Response("Bad Request", { status: 400 });

    // 从 env 读取限流配置，如果未设置则使用默认值
    const limit10m =
      parseInt(this.env.LIMIT_10M_PER_IP_ORIGIN) || DEFAULT_LIMIT_10M_PER_IP_ORIGIN;
    const limit1d =
      parseInt(this.env.LIMIT_1D_PER_IP_ORIGIN) || DEFAULT_LIMIT_1D_PER_IP_ORIGIN;

    /**
     * 自动过期清理（TTL）配置：
     * - TTL_10M_BUCKET_TTL: 10 分钟窗口桶 key 的存活秒数（默认 2 小时）
     * - TTL_1D_BUCKET_TTL:  日窗口桶 key 的存活秒数（默认 2 天）
     *
     * 说明：
     * - 10 分钟桶虽然只需要 10 分钟，但建议保留更久一点（比如 2 小时），避免边界抖动导致误判/重复创建。
     * - 日桶建议 2 天，覆盖跨日边界并留少量排查窗口。
     */
    const ttl10m = Math.max(
      600, // 最低给 10 分钟，避免配置写成 0
      parseInt(this.env.TTL_10M_BUCKET_TTL) || 2 * 60 * 60
    );
    const ttl1d = Math.max(
      24 * 60 * 60, // 最低给 1 天
      parseInt(this.env.TTL_1D_BUCKET_TTL) || 2 * 24 * 60 * 60
    );

    const now = Date.now();
    const bucket10m = Math.floor(now / 600000);
    const bucket1d = Math.floor(now / 86400000);

    const k10 = `10m:${body.key}:${bucket10m}`;
    const k1d = `1d:${body.key}:${bucket1d}`;

    const c10 = (await this.state.storage.get(k10)) || 0;
    const c1d = (await this.state.storage.get(k1d)) || 0;

    const n10 = c10 + 1;
    const n1d = c1d + 1;

    // ✅ 关键：写入时设置 expirationTtl（自动过期清理）
    await this.state.storage.put(k10, n10, { expirationTtl: ttl10m });
    await this.state.storage.put(k1d, n1d, { expirationTtl: ttl1d });

    const limited = (n10 > limit10m) || (n1d > limit1d);

    return new Response(JSON.stringify({ n10, n1d, limited }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }
}

export default {
  async fetch(request, env, ctx) {
    const isPreflight = request.method === "OPTIONS";
    const origin = request.headers.get("Origin");
    const ip = request.headers.get("CF-Connecting-IP") || "";

    // 0) 先解析目标 URL。没有目标 URL 时，直接返回演示页（不做代理）
    const targetUrl = parseTargetUrl(request.url);
    if (!targetUrl) {
      return new Response(demoPage(request, { ip, origin, note: "未提供目标 url，显示演示页" }), {
        status: 200,
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }

    // 1) 强制要求 Origin（更贴合“只服务你的前端”）
    if (REQUIRE_ORIGIN_HEADER && !origin) {
      return new Response("Forbidden: Missing Origin", { status: 403 });
    }

    // 2) 读取白名单（默认拒绝：为空就拒绝）
    const originPatterns = await kvGetJsonArray(env.KV, "whitelistOrigins");
    const hostnames = await kvGetJsonArray(env.KV, "whitelistHostnames");

    const whitelistOrigins = compileRegexList(originPatterns);
    const whitelistHostnames = hostnames
      .filter((x) => typeof x === "string")
      .map((x) => x.toLowerCase());

    if (whitelistOrigins.length === 0 || whitelistHostnames.length === 0) {
      return new Response("Forbidden: whitelist not configured", { status: 403 });
    }

    // 3) 白名单校验：Origin 必须命中
    if (!matchAny(origin, whitelistOrigins)) {
      return new Response("Forbidden: Origin not allowed", { status: 403 });
    }

    // 4) 目标 URL 基础安全校验（SSRF 基础防护）
    if (!isTargetUrlSafe(targetUrl)) {
      return new Response("Forbidden: target rejected by safety policy", { status: 403 });
    }

    // 5) hostname 白名单校验：只允许特定域名
    let target;
    try {
      target = new URL(targetUrl);
    } catch {
      return new Response("Forbidden: invalid target url", { status: 403 });
    }

    const th = target.hostname.toLowerCase();
    if (!whitelistHostnames.includes(th)) {
      return new Response("Forbidden: target hostname not allowed", { status: 403 });
    }

    // 6) 强限流：按 IP + Origin
    //    注意：脚本客户端可以伪造 Origin，但配合 hostname 白名单与阈值，滥用成本会显著升高
    const rlKey = `${ip || "0.0.0.0"}|${origin}`;

    const id = env.RATE_LIMITER.idFromName(rlKey);
    const stub = env.RATE_LIMITER.get(id);

    const rlResp = await stub.fetch("https://rate-limiter/check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ key: rlKey }),
    });

    const rl = await rlResp.json().catch(() => ({ limited: true }));
    if (rl.limited) {
      return new Response("Too Many Requests", { status: 429 });
    }

    // 7) 预检 OPTIONS：不转发，直接返回
    if (isPreflight) {
      const h = new Headers();
      applyCorsHeaders(h, origin, true, request);
      return new Response(null, { status: 204, headers: h });
    }

    // 8) 实际请求：转发到上游
    const forwardHeaders = buildForwardHeaders(request);

    const upstreamReq = new Request(targetUrl, {
      method: request.method,
      headers: forwardHeaders,
      body: request.body,
      redirect: "follow",
    });

    const upstreamResp = await fetch(upstreamReq);

    // 9) 注入 CORS 头（以 Worker 为准，避免与上游冲突）
    const respHeaders = new Headers(upstreamResp.headers);
    respHeaders.delete("access-control-allow-origin");
    respHeaders.delete("access-control-allow-credentials");
    respHeaders.delete("access-control-expose-headers");

    applyCorsHeaders(respHeaders, origin, false, request);

    return new Response(upstreamResp.body, {
      status: upstreamResp.status,
      statusText: upstreamResp.statusText,
      headers: respHeaders,
    });
  },
};
