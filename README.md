# 🛡️ PasteGuard

**Strip passwords, API keys, tokens and private keys out of text before you paste it into ChatGPT, Claude, Copilot or any other AI tool.**

Paste a config file, a log, a `curl` command or a stack trace. PasteGuard finds the secrets and replaces them with masks, and gives you back text that is safe to share. Everything runs **in your browser**: no backend, no telemetry, and no network requests after the page loads.

```diff
- DATABASE_URL=postgres://admin:S3cr3tP@ss@db.internal:5432/app
- OPENAI_API_KEY=sk-proj-AbC123...xyz
- Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
- {"password": "hunter2!", "confirm_password": "hunter2!"}
+ DATABASE_URL=postgres://********:********@db.internal:5432/app
+ OPENAI_API_KEY=********
+ Authorization: Bearer ********
+ {"password": "********", "confirm_password": "********"}
```

The structure stays intact: hosts, ports, key names, JSON and YAML layout are kept, so the AI can still understand and help with your problem.

---

## Why

Developers paste real config and logs into AI assistants every day, and secrets go with them. Once a secret is sent, you can't take it back: it may be logged, retained or used for training. PasteGuard is a quick checkpoint before you hit Enter.

- 🔒 **100% client-side.** Your text never leaves the browser tab. A strict Content-Security-Policy blocks connections to any other host.
- 🧠 **Understands real-world formats:** JSON, YAML, `.env`, shell, Docker, Kubernetes, HTTP headers, source code, logs, connection strings.
- 🔁 **Verifies itself.** After masking, the output is scanned again, and you get a warning if anything still looks like a secret.
- 🏠 **Self-hostable in one command.** A static site served by a hardened nginx container.

---

## Quick start

### Option 1: Docker (recommended)

```bash
git clone https://github.com/ThaiAnhDuc02/PasteGuard.git
cd PasteGuard
docker compose up -d --build
```

Open **http://localhost:8080**.

### Option 2: Node.js

Requires Node.js 22+ (24 LTS recommended).

```bash
git clone https://github.com/ThaiAnhDuc02/PasteGuard.git
cd PasteGuard
npm install
npm run dev
```

Open **http://localhost:5173**.

---

## How to use

1. **Paste** your text into the left editor. The format is detected automatically, or you can pick one from the **Format** menu.
2. Click **🛡️ MASK SECRETS**.
3. Review the masked output on the right, and the findings list below it (category, line, rule, confidence).
4. Click **Copy** or **Download**, then paste the result into your AI tool.

| Option | What it does |
|---|---|
| **Strategy** | How secrets are replaced; see [Masking strategies](#masking-strategies) |
| **Detect** toggles | Turn detector families on or off: Keys, Tokens, Conn. Strings, PEM Keys, Entropy |
| **Custom Rules** | Add your own field names (e.g. `internal_token`) or regex patterns for company-specific secrets |

> ⚠️ **Always review the output before sharing.** PasteGuard uses deterministic rules and catches a lot, but no tool catches everything. See [Limitations](#limitations).

---

## What it detects

| Category | Examples |
|---|---|
| Passwords | `password`, `passwd`, `passphrase`, plus prefixed or renamed forms: `DB_PASSWORD`, `confirm_password`, `dbPassword` |
| API keys | `api_key`, `X-API-Key`, `STRIPE_SECRET_KEY`, `APIKEY`, Google `AIza…`, Stripe `sk_live_…` / `whsec_…`, SendGrid, Twilio |
| AI provider keys | OpenAI `sk-…` / `sk-proj-…`, Anthropic `sk-ant-…`, Hugging Face `hf_…` |
| Tokens | `token`, `access_token`, `X-Auth-Token`, Slack `xoxb-…`, npm `npm_…`, GitLab `glpat-…`, PyPI, Docker Hub, Shopify |
| JWTs | `eyJ…` three-part tokens |
| Cloud credentials | AWS `AKIA…` / `ASIA…` key IDs, AWS secret keys, S3/GCS presigned-URL signatures, Azure `AccountKey` |
| GitHub tokens | `ghp_…`, `gho_…`, `ghs_…`, `ghu_…`, `github_pat_…` |
| Auth headers | `Authorization: Bearer …`, standalone `Bearer …`, `Authorization: Basic …`, `curl -u user:pass` |
| OAuth secrets | `client_secret`, `consumer_secret`, Google `GOCSPX-…` |
| Webhooks | Slack and Discord webhook URLs, Telegram bot tokens |
| Connection strings | PostgreSQL, MySQL, MongoDB, Redis, SQL Server, Oracle, AMQP, Kafka, LDAP, SMTP, FTP/SFTP, HTTPS/Git URLs with credentials, JDBC, ADO.NET |
| Private keys | Any PEM `… PRIVATE KEY` (RSA, EC, OpenSSH, PKCS#8, encrypted), PGP, PuTTY `.ppk`, including truncated pastes |
| Unknown formats | Random-looking, high-entropy values under any key (flagged as low confidence; toggle **Entropy**) |

**Input syntaxes:** JSON, YAML (including `|` block scalars), `.env`, shell and CLI flags, INI/TOML, XML attributes, source code, PHP arrays, HTTP headers, `.properties`, Kubernetes/ECS `name`/`value` env lists, Dockerfile `ENV`.

The full rule list is in [DETECTION_RULES.md](./DETECTION_RULES.md).

---

## Masking strategies

| Strategy | Output | When to use |
|---|---|---|
| **Full Mask** (default) | `password=********` | Safest; hides the length too |
| **Fixed Mask** | `password=*****` | Same, shorter |
| **Placeholder** | `password=[PASSWORD_1]` | When the AI needs to tell secrets apart. The same value always gets the same label, so you can map the AI's answer back |
| **Partial Mask** | `api_key=sk****1234` | When you need to recognise *which* key it was. Only applies to token-like values of 16+ characters, never shows more than ⅓ of a value, and never applies to passwords, private keys or usernames |

---

## Deploying for your team

The production build is a folder of static files. Any static host works, but the included Docker image adds security headers (CSP, `X-Frame-Options`, and others) and runs as a non-root user with a read-only filesystem.

```bash
docker compose up -d --build                 # serve on port 8080
curl -I http://localhost:8080/index.html     # should include Content-Security-Policy
docker compose down                          # stop
```

### Private network / VPN (e.g. AWS EC2 with a private IP)

A common setup is one small instance in a private subnet that teammates reach over VPN at `http://<private-ip>:8080`.

1. **Firewall first.** Allow inbound TCP `8080` only from your VPN/VPC CIDR (in AWS, the Security Group). Never from `0.0.0.0/0`.
2. **Optional: an IP allowlist in nginx** as defence in depth. Add this to `nginx.conf` under `server_tokens off;`:
   ```nginx
   allow 10.8.0.0/16;   # your VPN CIDR
   allow 127.0.0.1;     # container health check
   deny  all;
   ```
   Check `docker compose logs` afterwards. If client IPs show up as a Docker gateway address (e.g. `172.17.0.1`), the allowlist can't tell clients apart, so rely on the firewall instead.
3. **HTTPS is recommended** even behind a VPN. Inside the network, plain HTTP lets anyone who can tamper with traffic inject script into the page. Either terminate TLS in nginx with a certificate from your internal CA, or put an internal load balancer with a managed certificate (e.g. AWS ALB + ACM) in front of the container.

The app works over plain HTTP: copy-to-clipboard and custom rules have fallbacks for non-HTTPS pages. Don't add an HSTS header unless you serve over HTTPS.

### Static hosting

```bash
npm run build      # outputs dist/
```

Upload `dist/` to any static host (S3 + CloudFront, GitHub Pages, Netlify, an internal web server, …). If you don't use the included nginx config, copy the headers from [`security-headers.conf`](./security-headers.conf) into your host's configuration. The `Content-Security-Policy` header is what guarantees the page can't send data anywhere.

---

## Security & privacy

- **No backend.** All detection and redaction runs in a Web Worker inside your tab.
- **No storage.** Nothing is written to `localStorage`, `sessionStorage`, IndexedDB or cookies (an ESLint rule enforces this). Closing the tab discards everything.
- **No third-party requests.** The editor (Monaco) is bundled, not loaded from a CDN. The CSP sets `connect-src 'self'` and `script-src 'self'`, with no `unsafe-eval`.
- **No logging of input.** Errors log only an error message, never your text or the detected values.
- **Fail-closed.** Truncated private keys are still masked, and a hard timeout stops a runaway custom regex instead of freezing the page.

You can verify all of this yourself: run `npm run build`, inspect `dist/`, or open DevTools → Network while you use the app.

See [SECURITY.md](./SECURITY.md) for the threat model and how to report a vulnerability.

---

## Limitations

PasteGuard matches **structure**: key names, known token formats, connection strings, PEM blocks. It will not catch:

- Secrets in free prose: *"the password is hunter2"*
- Purely numeric secrets under an unknown key: `pin=4821`
- Secrets deliberately disguised under misleading key names (the entropy check catches some of these)
- Brand-new token formats that aren't in the rule set yet (again, partly covered by the entropy check)

When in doubt, add a [custom rule](#how-to-use), and always read the output before sharing.

---

## Development

```bash
npm install
npm run dev          # dev server with hot reload (http://localhost:5173)
npm run check        # typecheck + lint + format check + tests; run before every PR
npm test             # tests only
npm run build        # production build → dist/
npm run preview      # serve dist/ with the production CSP (http://localhost:4173)
```

**Stack:** React 19 · TypeScript 7 · Vite 8 · Monaco Editor · Tailwind CSS · Vitest

> TypeScript is installed side by side. `@typescript/native` is TypeScript 7 and provides `tsc`. The `typescript` package name points at the 6.0 compatibility package, because typescript-eslint doesn't support TypeScript 7 yet.

### Project docs

- [ARCHITECTURE.md](./ARCHITECTURE.md): code structure and design decisions
- [DETECTION_RULES.md](./DETECTION_RULES.md): every detection rule
- [SECURITY.md](./SECURITY.md): threat model and guarantees
- [CONTRIBUTING.md](./CONTRIBUTING.md): adding detectors, writing tests

---

## Contributing

Contributions are very welcome, especially **new token formats** and **missed-secret reports**.

- **Found a secret that wasn't masked?** Open an issue with a minimal example using **fake** values (e.g. `FAKE_SECRET_VALUE`). Never post real credentials.
- **Adding a detector?** Follow [CONTRIBUTING.md](./CONTRIBUTING.md). Each new rule needs positive, negative and "secret fully removed" tests, and `npm run check` must pass.

---

## License

Released under the [MIT License](./LICENSE).
