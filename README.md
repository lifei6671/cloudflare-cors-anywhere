# Cloudflare Worker CORS Proxy

**English** | [中文](README_ZH.md)

A secure, high-performance CORS proxy built on Cloudflare Workers, designed for production use with strict security controls. Unlike generic "open" proxies, this solution enforces strict whitelisting and distributed rate limiting to protect your resources.

## Features

- **Strict Whitelisting**:
  - **Origin Whitelist**: Only allow requests from your specific frontend domains (supports Regex).
  - **Hostname Whitelist**: Only allow proxying to specific target APIs (exact match).
  - *Powered by Cloudflare KV for dynamic updates without redeployment.*
- **Advanced Rate Limiting**:
  - **Distributed Counting**: Uses **Cloudflare Durable Objects** for accurate, global rate limiting.
  - **Granular Control**: Limits requests based on unique `IP + Origin` pairs.
  - **Dual Windows**: Enforces both short-term (10-minute) and long-term (24-hour) quotas.
  - **Configurable**: Thresholds adjustable via Environment Variables.
- **Security First**:
  - **SSRF Protection**: Automatically blocks localhost, private IPs, and non-HTTP/HTTPS protocols.
  - **Header Sanitization**: Strips sensitive headers (Cookies, Referer, CF-headers) before forwarding to upstream.
  - **Preflight Handling**: Caches `OPTIONS` requests directly at the edge (no upstream forwarding) to reduce latency and load.
- **User Friendly**:
  - **Demo Page**: Accessing the root URL displays a styled usage guide and test tool.
  - **Simple API**: Standardized query parameter `?url=` for proxying.

## Prerequisites

- **Cloudflare Account**: Requires a **Workers Paid Plan** ($5/mo) to use Durable Objects.
- **Node.js**: Version 16.13.0 or later.
- **Wrangler CLI**: Installed globally (`npm install -g wrangler`).

## Deployment Guide

### 1. Clone & Install
```bash
git clone https://github.com/lifei6671/cloudflare-cors-anywhere.git
cd cloudflare-cors-anywhere
npm install
```

### 2. Configure KV Namespace
Create a KV namespace to store your security whitelists:

```bash
wrangler kv:namespace create KV
```

Copy the `id` from the output and update your `wrangler.toml`:

```toml
[[kv_namespaces]]
binding = "KV"
id = "YOUR_KV_ID_HERE" # Replace with your actual KV ID
```

### 3. Set Up Whitelists (Crucial)
You must configure the KV store with allowed Origins and Hostnames, otherwise **all requests will be rejected (403)**.

**Step A: Allow Frontend Origins (Regex JSON Array)**
Allow your frontend domains. Use `.*` for development (careful!) or specific regex for production.

```bash
# Example: Allow localhost and any subdomain of my-app.com
wrangler kv:key put whitelistOrigins '["^http://localhost:[0-9]+$", "^https://.*\\.my-app\\.com$"]' --binding KV
```

**Step B: Allow Target Hostnames (String JSON Array)**
Allow the APIs you intend to call.

```bash
# Example: Allow Google and GitHub APIs
wrangler kv:key put whitelistHostnames '["www.google.com", "api.github.com"]' --binding KV
```

### 4. Deploy
Deploy the worker to Cloudflare. Wrangler will handle the Durable Object migration automatically.

```bash
wrangler deploy
```

## Configuration

### Rate Limit Thresholds
You can adjust the rate limits using Environment Variables in `wrangler.toml` or the Cloudflare Dashboard.

| Variable | Default | Description |
|----------|---------|-------------|
| `LIMIT_10M_PER_IP_ORIGIN` | 300 | Max requests per IP+Origin in 10 minutes |
| `LIMIT_1D_PER_IP_ORIGIN` | 5000 | Max requests per IP+Origin in 24 hours |

**Example `wrangler.toml` configuration:**
```toml
[vars]
LIMIT_10M_PER_IP_ORIGIN = "1000"
LIMIT_1D_PER_IP_ORIGIN = "10000"
```

### Static Settings (`index.js`)
You can modify these constants directly in the code if needed:
- `PREFLIGHT_MAX_AGE`: Browser cache time for CORS preflight (default `600` seconds).
- `ALLOW_CREDENTIALS`: Whether to allow cookies/auth headers (default `false` for security).
- `REQUIRE_ORIGIN_HEADER`: Reject requests without an Origin header (default `true`).

## Usage

### API Format
```
GET https://<your-worker-domain>/?url=<encoded-target-url>
```

### JavaScript Example
```javascript
const proxy = "https://your-worker.workers.dev/";
const target = "https://api.github.com/users/lifei6671";
const url = proxy + "?url=" + encodeURIComponent(target);

fetch(url)
  .then(res => res.json())
  .then(data => console.log(data));
```

### Sending Custom Headers
To send headers (like `Authorization`) to the target API, wrap them in the `x-cors-headers` header. The proxy will extract and forward them.

```javascript
fetch(url, {
  headers: {
    "x-cors-headers": JSON.stringify({
      "Authorization": "Bearer my-secret-token",
      "Content-Type": "application/json"
    })
  }
});
```

## License

MIT License. Based on the original concept by Zibri, but rewritten for modern Cloudflare Workers features (Durable Objects, KV).
