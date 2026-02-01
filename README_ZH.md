# Cloudflare Worker CORS Proxy

[English](README.md) | **中文**

基于 Cloudflare Workers 构建的安全、高性能 CORS 代理，专为生产环境设计，提供严格的安全控制。与通用的“开放式”代理不同，本方案强制执行严格的白名单机制和分布式限流，以保护您的资源。

## 功能特性

- **严格的白名单机制**：
  - **Origin 白名单**：仅允许来自您特定前端域名的请求（支持正则）。
  - **Hostname 白名单**：仅允许代理到特定的目标 API（精确匹配）。
  - *基于 Cloudflare KV，支持动态更新无需重新部署。*
- **高级限流**：
  - **分布式计数**：使用 **Cloudflare Durable Objects** 实现精确的全局限流。
  - **细粒度控制**：基于唯一的 `IP + Origin` 组合进行限制。
  - **双重窗口**：同时执行短期（10分钟）和长期（24小时）配额限制。
  - **可配置**：可通过环境变量调整阈值。
- **安全优先**：
  - **SSRF 防护**：自动拦截 localhost、私有 IP 和非 HTTP/HTTPS 协议。
  - **请求头清洗**：在转发给上游之前，剥离敏感头（Cookies, Referer, CF-headers）。
  - **预检处理**：在边缘直接缓存 `OPTIONS` 请求（不转发给上游），降低延迟和负载。
- **用户友好**：
  - **演示页面**：访问根 URL 会显示带样式的用法指南和测试工具。
  - **简单 API**：标准化的 `?url=` 查询参数用于代理。

## 前置要求

- **Cloudflare 账户**：免费账户即可（Durable Objects 现已支持免费计划）。
- **Node.js**：版本 16.13.0 或更高。
- **Wrangler CLI**：全局安装 (`npm install -g wrangler`)。

## 部署指南

### 1. 克隆与安装
```bash
git clone https://github.com/lifei6671/cloudflare-cors-anywhere.git
cd cloudflare-cors-anywhere
npm install
```

### 2. 配置 KV Namespace
创建一个 KV namespace 用于存储安全白名单：

```bash
wrangler kv:namespace create KV
```

复制输出中的 `id` 并更新您的 `wrangler.toml`：

```toml
[[kv_namespaces]]
binding = "KV"
id = "YOUR_KV_ID_HERE" # 替换为您的实际 KV ID
```

### 3. 设置白名单（关键）
您必须在 KV 存储中配置允许的 Origin 和 Hostname，否则 **所有请求都将被拒绝 (403)**。

**步骤 A: 允许前端 Origin (正则 JSON 数组)**
允许您的前端域名。开发环境可使用 `.*`（请谨慎！），生产环境建议使用具体正则。

```bash
# 示例：允许 localhost 和 my-app.com 的所有子域名
wrangler kv:key put whitelistOrigins '["^http://localhost:[0-9]+$", "^https://.*\\.my-app\\.com$"]' --binding KV
```

**步骤 B: 允许目标 Hostname (字符串 JSON 数组)**
允许您打算调用的 API 域名。

```bash
# 示例：允许 Google 和 GitHub API
wrangler kv:key put whitelistHostnames '["www.google.com", "api.github.com"]' --binding KV
```

### 4. 部署
将 Worker 部署到 Cloudflare。Wrangler 会自动处理 Durable Object 的迁移。

```bash
wrangler deploy
```

## 配置

### 限流阈值
您可以通过 `wrangler.toml` 或 Cloudflare Dashboard 中的环境变量调整限流阈值。

| 变量名 | 默认值 | 说明 |
|----------|---------|-------------|
| `LIMIT_10M_PER_IP_ORIGIN` | 300 | 每 IP+Origin 在 10 分钟内的最大请求数 |
| `LIMIT_1D_PER_IP_ORIGIN` | 5000 | 每 IP+Origin 在 24 小时内的最大请求数 |

**`wrangler.toml` 配置示例：**
```toml
[vars]
LIMIT_10M_PER_IP_ORIGIN = "1000"
LIMIT_1D_PER_IP_ORIGIN = "10000"
```

### 静态设置 (`index.js`)
如果需要，您可以直接在代码中修改这些常量：
- `PREFLIGHT_MAX_AGE`: CORS 预检请求的浏览器缓存时间（默认 `600` 秒）。
- `ALLOW_CREDENTIALS`: 是否允许 cookies/auth 头（默认 `false` 以提高安全性）。
- `REQUIRE_ORIGIN_HEADER`: 是否拒绝没有 Origin 头的请求（默认 `true`）。

## 使用方法

### API 格式
```
GET https://<your-worker-domain>/?url=<encoded-target-url>
```

### JavaScript 示例
```javascript
const proxy = "https://your-worker.workers.dev/";
const target = "https://api.github.com/users/lifei6671";
const url = proxy + "?url=" + encodeURIComponent(target);

fetch(url)
  .then(res => res.json())
  .then(data => console.log(data));
```

### 发送自定义 Header
要发送 Header（如 `Authorization`）到目标 API，请将其包装在 `x-cors-headers` 头中。代理会自动提取并转发。

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

## 许可证

MIT License. 基于 Zibri 的原始概念，但针对现代 Cloudflare Workers 特性（Durable Objects, KV）进行了重写。
