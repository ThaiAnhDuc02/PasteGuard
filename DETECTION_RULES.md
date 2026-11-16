# PasteGuard — Detection Rules

All rules are deterministic. None use AI, ML, or external lookups.

---

## 1. Key-Based Detector (`keyBasedDetector.ts`)

One linear scan finds every `key <sep> value` pair, then classifies the key.

### Supported syntaxes

| Syntax | Example |
|---|---|
| JSON / JS objects | `"password": "value"`, `apiKey: 'value'` |
| ENV / shell / INI / TOML | `DB_PASSWORD=value`, `export APP_SECRET="value"`, `token = "value"` |
| YAML (incl. block scalars) | `password: value`, `secret: \|` followed by an indented block |
| XML attributes | `password="value"` |
| Source code | `const accessToken = "value"`, `String password = "value";` |
| PHP arrays | `'client_secret' => 'value'` |
| HTTP headers | `X-API-Key: value`, `Authorization: Bearer value` (scheme word kept) |
| Properties | `spring.datasource.password=value` |
| CLI flags | `--api-key=value` |
| Name/value lists | Kubernetes `- name: DB_PASSWORD` ⏎ `value: x`, ECS `{"name":"API_TOKEN","value":"x"}` |
| Dockerfile | `ENV DB_PASSWORD value` |

Quoted values are escape-aware (`"pa\"ss"` is captured whole). Unquoted values
stop at whitespace, quotes, `&name=` (query strings), `;name=` (connection
strings) and `, ` (lists), so `?user=bob&password=x&ssl=true` masks only the
values.

### Key matching (suffix words)

The key is split into words on `_ - .` whitespace and camelCase:
`STRIPE_SECRET_KEY` → `[stripe, secret, key]`, `X-Api-Key` → `[x, api, key]`,
`dbPassword` → `[db, password]`. A keyword matches when it equals a **suffix**
of the word list (word by word or concatenated, so `APIKEY` matches `api_key`).
The longest keyword wins.

- ✅ `confirm_password`, `STRIPE_SECRET_KEY`, `GITHUB_TOKEN`, `X-Auth-Token`, `dbPassword`
- ❌ `password_hash`, `token_type`, `password_min_length` (keyword is not the suffix)
- ❌ `monkey`, `bypass`, `superuser` (keyword is inside a word, not a whole word)

### Keyword table

| Keywords | Category | Confidence |
|---|---|---|
| `password`, `passwd`, `pwd`, `passphrase`, `db_pass`, `db_password`, `root_password`, `admin_password`, … | PASSWORD | HIGH |
| `pass` | PASSWORD | MEDIUM |
| `api_key`, `api_secret`, `access_key`, `secret_key`, `signing_key`, `encryption_key`, `app_key`, `app_secret`, `master_key`, `license_key`, `subscription_key`, `account_key`, `webhook_secret`, … | API_KEY | HIGH |
| `token`, `access_token`, `refresh_token`, `auth_token`, `id_token`, `bearer_token`, `session_token`, `api_token`, `security_token`, `pat`, … | TOKEN | HIGH |
| `auth`, `session_id`, `sessionid`, `session_key`, `cookie`, `set_cookie` | TOKEN | MEDIUM |
| `client_secret`, `oauth_secret`, `consumer_secret`, `oauth_token_secret` | OAUTH_SECRET | HIGH |
| `secret`, `private_key`, `secret_value`, `secret_token`, `salt`, `pepper` | GENERIC_SECRET | HIGH |
| `authorization`, `proxy_authorization`, `bearer` | BEARER_TOKEN | HIGH |
| `credential`, `credentials`, `dsn` | GENERIC_SECRET | MEDIUM |
| `username`, `user_name`, `login` | USERNAME | MEDIUM |
| `user` | USERNAME | LOW |
| `client_id` | OAUTH_SECRET | LOW |

### Values that are skipped

`true/false/null/yes/no/on/off`, type names (`string`, `int`, …), placeholders
(`changeme`, `xxx`, `<token>`), references (`${VAR}`, `$VAR`, `{{ .Values.x }}`,
`%VAR%`, `process.env.X`, `os.environ[...]`), unquoted function calls
(`getPassword()`), already-masked values (`****`, `[PASSWORD_1]`) and values
shorter than 3 characters.

### Entropy fallback (LOW)

If the key is not a keyword but the value looks machine-generated — 20–512
chars, no whitespace, ≥ 3 character classes and Shannon entropy ≥ 4.0 (or ≥ 32
hex chars with entropy ≥ 3.5) — it is reported as `GENERIC_SECRET` / LOW.
URLs, paths, UUIDs, lockfile integrity hashes, version numbers and emails are
excluded, as are keys ending in `id`, `hash`, `sha`, `checksum`, `digest`,
`commit`, `version`, `url`, `path`, `name`, … Toggle with **Entropy**.

---

## 2. Token / Pattern Detector (`tokenDetector.ts`)

| Rule ID | Pattern | Category | Confidence |
|---|---|---|---|
| `jwt` | Three base64url segments starting with `eyJ` | JWT | HIGH |
| `aws-access-key-id` | `AKIA`/`ABIA`/`ACCA`/`ASIA` + 16 uppercase alphanum | AWS_CREDENTIAL | HIGH |
| `aws-secret-access-key` | 40-char base64 after `aws_secret_access_key` | AWS_CREDENTIAL | HIGH |
| `github-pat-classic` / `-fine` / `-oauth-token` / `-app-token` / `-user-token` | `ghp_`, `github_pat_`, `gho_`, `ghs_`/`ghr_`, `ghu_` | GITHUB_TOKEN | HIGH |
| `bearer-header` | `Authorization: Bearer <token>` | BEARER_TOKEN | HIGH |
| `bearer-standalone` | `Bearer <token ≥16>` anywhere | BEARER_TOKEN | MEDIUM |
| `basic-auth-header` | `Authorization: Basic <base64>` | BASIC_AUTH | HIGH |
| `curl-basic-auth` | `curl -u user:<password>` / `--user` | BASIC_AUTH | HIGH |
| `anthropic-key` | `sk-ant-…` | API_KEY | HIGH |
| `openai-key` | `sk-…`, `sk-proj-…`, `sk-svcacct-…` (20+ chars, contains a digit) | API_KEY | HIGH |
| `huggingface-token` | `hf_` + 30+ alphanum | TOKEN | HIGH |
| `google-api-key` | `AIza` + 35 chars | API_KEY | HIGH |
| `google-oauth-secret` | `GOCSPX-…` | OAUTH_SECRET | HIGH |
| `gitlab-token` | `glpat-`, `gldt-`, `glrt-`, … | TOKEN | HIGH |
| `pypi-token` | `pypi-AgEIcHlwaS5vcmc…` | TOKEN | HIGH |
| `docker-hub-pat` | `dckr_pat_…` | TOKEN | HIGH |
| `slack-webhook` / `discord-webhook` | webhook URL secret path | TOKEN | HIGH |
| `telegram-bot-token` | `123456789:AA…` | TOKEN | HIGH |
| `stripe-key` / `stripe-webhook-secret` | `sk_live_…`, `pk_test_…`, `rk_…`, `whsec_…` | API_KEY | HIGH |
| `shopify-token` | `shpat_`, `shpca_`, `shppa_`, `shpss_` + 32 hex | TOKEN | HIGH |
| `sendgrid-key` | `SG.` + 22 `.` + 43 | API_KEY | HIGH |
| `slack-token` | `xoxb-…`, `xoxa-…`, … | TOKEN | HIGH |
| `twilio-sid` | `AC` + 32 hex | API_KEY | HIGH |
| `npm-token` | `npm_` + 36 alphanum | TOKEN | HIGH |
| `generic-hex-secret` | 32–64 hex chars after `=` or `:` | GENERIC_SECRET | LOW |

---

## 3. Connection String Detector (`connectionStringDetector.ts`)

### URL credentials

`scheme://[user[:password]@]host` for postgres(ql), mysql(x), mariadb,
mongodb(+srv), redis(s), sqlserver, mssql, oracle, cockroachdb, clickhouse,
cassandra, neo4j(+s), couchdb, amqp(s), mqtt(s), nats, kafka, ldap(s),
smtp(s), imap(s), ftp(s), sftp, ssh, http(s), git+http(s).

Username and password are separate spans; host, port, path and query are kept.
Per RFC 3986 the userinfo may not contain unescaped `/ ? #`, so
`https://host:8080/p?email=a@b.c` is not misread as credentials.

### JDBC and query parameters

`jdbc:<driver>://…?user=…&password=…` and `;password=…`, plus `?`/`&`/`;`
parameters named `password`, `passwd`, `pwd`, `secret`, `client_secret`,
`token`, `auth`, `api_key`, `apikey`, `api-key`, `key`, `access_token`,
`refresh_token`, `id_token`, `session_token`, `private_token`, `sig`,
`signature`, `x-amz-signature`, `x-amz-security-token`, `x-goog-signature`.

ADO.NET (`Password=…;`) and Azure (`AccountKey=…;`) strings are handled by the
key-based detector.

---

## 4. Private Key Detector (`privateKeyDetector.ts`)

- Any `-----BEGIN … PRIVATE KEY-----` label (RSA, EC, DSA, OPENSSH, ENCRYPTED,
  PKCS#8, …), `PGP PRIVATE KEY BLOCK`, `CERTIFICATE`, PuTTY `.ppk` files.
- The **entire block** is one span, so no fragment survives.
- **Fail-closed:** a BEGIN without END (truncated paste) is redacted from the
  header through every following line of key material (base64, PEM headers,
  blank lines); it stops at the first ordinary text line.
- JSON-escaped PEM (`"-----BEGIN PRIVATE KEY-----\nMIIE…"`, e.g. GCP service
  account files) is supported.

---

## 5. Custom Rules (`customDetector.ts`)

User-defined rules live in component state (not persisted).

| Field | Description |
|---|---|
| `name` | Human-readable label |
| `fieldNames` | Key names, matched with the same suffix-word logic as built-in keywords (`my_token` also matches `MY_TOKEN`, `myToken`, `"my-token"`, `APP_MY_TOKEN`) in every supported syntax |
| `regexPattern` | Optional regex; first capture group is the secret span |
| `category` | Assigned SecretCategory |
| `confidence` | HIGH / MEDIUM / LOW |
| `maskingStrategy` | Overrides the global strategy for this rule's detections, or null to inherit |
| `enabled` | Toggle on/off without deleting |

### Regex safety

1. Syntax check.
2. Nested quantifiers (`(a+)+`, `(\w*)*`, `(a|aa)+`) are rejected.
3. Timing probe against several adversarial strings.
4. At runtime the pipeline runs in a Web Worker with a 15 s hard timeout.

---

## Confidence levels

| Level | Meaning |
|---|---|
| HIGH | Strong structural evidence (known prefix, format, or context) |
| MEDIUM | Keyword match without strong structural evidence |
| LOW | Broad heuristic (entropy, generic hex, `user`); may produce false positives — shown with a warning |

LOW-confidence results are still redacted, and the UI shows a warning banner.

## Verification pass

After redaction the masked output is scanned again. Any HIGH/MEDIUM detection
that is not itself a mask (`****`, `[LABEL_N]`) is counted as residual, and the
UI warns the user to review before copying.

---

## Known limitations

- Secrets in free prose ("my password is hunter2") have no structure and are not detected.
- Numeric-only secrets (e.g. `pin=1234`) under a non-keyword key are not detected.
- Binary formats are not supported.
- Detection coverage is best-effort. **Always review the sanitized output before sharing.**
