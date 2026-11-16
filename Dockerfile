# ── Stage 1: build ────────────────────────────────────────────────────────────
FROM node:24-alpine AS builder

WORKDIR /app

# Install dependencies first (layer-cached)
COPY package.json package-lock.json ./
RUN npm ci --no-audit --no-fund

# Copy source and build (tests run here too — a failing suite fails the image)
COPY . .
RUN npm test && npm run build

# ── Stage 2: serve ────────────────────────────────────────────────────────────
# Unprivileged image: nginx runs as uid 101 and listens on 8080.
FROM nginxinc/nginx-unprivileged:1.28-alpine AS runtime

COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY security-headers.conf /etc/nginx/snippets/security-headers.conf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1

CMD ["nginx", "-g", "daemon off;"]
