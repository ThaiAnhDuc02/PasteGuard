# PasteGuard — Security

## Threat Model

PasteGuard is designed for a single threat scenario: **accidentally exposing secrets when pasting developer content into AI tools**.

It is not designed to prevent:
- A malicious actor who already has access to the developer's machine.
- Secrets embedded in binary formats or encrypted containers.
- Secrets that are semantically sensitive but have no syntactic pattern (e.g. a dictionary word used as a password).

---

## Security Properties

### All Processing Is Local

- No network requests are made during detection or redaction.
- No third-party analytics, telemetry, or tracking libraries are included.
- The build process can be audited: run `npm run build` and inspect `dist/`.

### No Persistence of Sensitive Data

- Input text is held only in React component state (JavaScript heap).
- Nothing is written to `localStorage`, `sessionStorage`, `IndexedDB`, or cookies.
- Clicking **Clear All** sets the state to empty strings.

### No Secret Values in Logs or Error Messages

- `console.error` calls report only the error type/message, never the input text or detected values.
- The `placeholderMap` returned by the redaction engine maps replacement labels to occurrence counts — it does not store original secret values.
- Detection summary statistics count by category — no original values are included.

### Safe Rendering

- All output is displayed inside Monaco Editor as plain text, not injected as raw HTML.
- No use of `dangerouslySetInnerHTML` anywhere in the codebase.

### Safe Regex Execution

- The whole detect → redact pipeline runs in a **Web Worker** with a **15 s hard
  timeout**. If a run exceeds it, the worker is terminated and the user sees an
  error — the page never freezes. This is the real guarantee: JavaScript cannot
  interrupt a regex that is already running on the main thread.
- User-supplied regex patterns are also validated before saving (first line of
  defence): syntax check, rejection of nested quantifiers (`(a+)+`, `(a|b)*`),
  and a timing probe against several adversarial strings.
- Built-in patterns are covered by stress tests (`regression.test.ts`) that run
  ~200 KB adversarial inputs and fail if any detector goes super-linear.

### Fail-Closed Behaviour

- A private key pasted without its `-----END` line is still redacted (header
  plus every following key-material line).
- Escape-aware quoting: `"pa\"ss"` is captured whole, not cut at the escaped quote.
- After masking, the output is re-scanned; any remaining non-LOW detection
  triggers a warning banner before the user copies the text.
- `PARTIAL_MASK` never reveals characters of passwords, private keys, Basic
  auth, usernames or connection-string credentials, never applies to values
  shorter than 16 characters, and never shows more than ⅓ of a value.

### Input Bounds

- Format detection sniffs only the first 4 096 characters.
- Key-based value matching is capped at 2 048 characters per value.
- Custom regex patterns are capped at 10 000 characters.

---

## Security Limitations

> **PasteGuard uses deterministic detection rules. Some sensitive values may not be detected. Review sanitized output before sharing.**

This disclaimer appears in the UI on every detection run.

Specific gaps:

| Gap | Why |
|---|---|
| Encoded secrets | A password that is base64-encoded before being stored has no recognizable pattern |
| Numeric-only secrets | PIN codes and purely numeric keys have no structural distinguisher from ordinary numbers |
| Obfuscated field names | A key named `x1z9q` is not caught by keyword matching; the entropy fallback flags it (LOW) only if the value looks random |
| Secrets in prose | "my password is hunter2" has no key/value structure and is not detected |
| Secrets in comments | Multi-line block comments in source code may be missed if the comment wraps across a keyword boundary |
| Novel vendor tokens | New token formats not yet in the pattern table will not be detected |

---

## Responsible Disclosure

There are two kinds of report:

- **A secret that wasn't masked** (a detection gap). Open a normal GitHub issue with a minimal reproducing input. These are expected, best-effort limitations, and public reports help everyone.
- **A vulnerability in the app itself**, e.g. a way to make the page send input to another host, bypass the CSP, or execute injected script. Report it privately via GitHub's **Security → Report a vulnerability** (private vulnerability reporting) rather than a public issue. You should get a response within a few days.

Do **not** include real secrets in any report. Use obviously fake values like `FAKE_SECRET_VALUE`.

---

## Content Security Policy

The production headers live in `security-headers.conf` and are included in the
nginx server block **and** in every location that sets its own `add_header`
(nginx otherwise silently drops inherited headers for that location).

```
default-src     'self';
script-src      'self';                 ← no 'unsafe-eval': Monaco is bundled locally
style-src       'self' 'unsafe-inline'; ← required by Monaco Editor's dynamic styles
worker-src      'self' blob:;           ← Monaco + detection workers (same-origin files)
font-src        'self' data:;
img-src         'self' data:;
connect-src     'self';                 ← the app never talks to another host
object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'
```

Monaco is loaded from the app bundle (`src/monaco/setup.ts` →
`loader.config({ monaco })`), **not** from cdn.jsdelivr.net, which is the
default of `@monaco-editor/react`. `npm run preview` serves the build with the
same CSP, so a regression shows up locally as a console CSP error.

Also set: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`,
`Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
`Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy` (camera,
microphone, geolocation, clipboard-read disabled), `X-XSS-Protection: 0`.

The container runs nginx as a non-root user (`nginx-unprivileged`), read-only
root filesystem, all Linux capabilities dropped, `no-new-privileges`.

---

## Dependency Security

Run `npm audit` to check for known vulnerabilities in dependencies. ESLint
enforces `no-console` (except `console.error`), `no-eval`, `no-new-func`, and
bans `dangerouslySetInnerHTML` and `localStorage` / `sessionStorage`.

To update: `npm audit fix` for non-breaking fixes, or pin affected packages as needed.
