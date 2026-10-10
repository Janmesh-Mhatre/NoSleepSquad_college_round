# Incognito — Production Deployment Guide

## 1. Production Architecture Overview

The production architecture consists of five decoupled layers:

```
[ Institutional Identity Provider ] (Microsoft Entra ID / Google Workspace)
                  │
                  ▼ (OIDC Verification)
       [ Incognito Frontend SPA ] (Vercel / Cloudflare Pages / Static CDN)
                  │
                  ▼ (HTTPS / TLS 1.3 / Strict CSP)
       [ Incognito Backend API ] (FastAPI / Express / Container on Render/Fly/Cloud Run)
         ├── [ PostgreSQL 16 ] (AWS RDS / GCP Cloud SQL / Neon with SSL required)
         ├── [ Cloud KMS ] (AWS KMS / GCP Cloud KMS / Azure Key Vault)
         ├── [ AI Moderation ] (Gemini 2.5 Flash / OpenAI fallback)
         └── [ Blockchain RPC ] (Alchemy / Infura multi-RPC failover)
                  │
                  ▼ (JSON-RPC)
       [ AuditRegistry Smart Contract ] (Arbitrum One / Sepolia Testnet)
```

---

## 2. Environment Configuration

Three environments are strictly segregated. Never reuse databases, KMS keys, or relayer private keys across environments.

| Variable | Staging | Production | Description |
| :--- | :--- | :--- | :--- |
| `NODE_ENV` | `staging` | `production` | Enforces production fail-closed security mode |
| `DATABASE_URL` | Staging PostgreSQL connection | Production PostgreSQL connection (`sslmode=verify-full`) | Production connection string |
| `ENCRYPTION_KEY` | Staging KMS secret | Injected via Secret Manager (>= 32 bytes) | AES-256-GCM master key |
| `AUTH_SECRET` | Staging secret | Injected via Vault (>= 64 chars) | JWT signing secret |
| `CORS_ORIGINS` | Staging domain | `https://incognito.institutional.edu` | Strict browser origin allowlist |
| `LLM_PROVIDER` | `gemini` | `gemini` | Primary AI moderation provider |
| `LLM_MODEL` | `gemini-2.5-flash` | `gemini-2.5-flash` | Contextual safety evaluation model |
| `LLM_API_KEY` | Staging key | Production backend-only key from Vault | Never exposed to client |
| `BLOCKCHAIN_RPC_URL`| Alchemy Sepolia | Alchemy Mainnet / Arbitrum One | Primary JSON-RPC endpoint |
| `BLOCKCHAIN_BACKUP_RPC_URL`| Infura Sepolia | Infura Mainnet / Arbitrum One | Automatic failover endpoint |
| `CONTRACT_ADDRESS` | Sepolia contract address | Deployed production contract address | `AuditRegistry.sol` contract address |
| `BLOCKCHAIN_PRIVATE_KEY` | Dedicated testnet wallet | Dedicated relayer wallet (no personal funds) | Publishes batch commitments |

---

## 3. Deployment Steps

### 3.1 Backend Deployment (Docker / Cloud Run / Render)

```bash
# 1. Build production image
docker build -t incognito-api:latest .

# 2. Run database migrations
docker run --rm --env-file .env.production incognito-api:latest node -e "import('./backend/migrations/runner.js').then(m => m.migrationRunner.runMigrations())"

# 3. Deploy container with non-root security context
docker run -d \
  -p 4000:4000 \
  --env-file .env.production \
  --name incognito-api \
  incognito-api:latest
```

### 3.2 Frontend Deployment (Vercel)

```bash
# Deploy to Vercel with security headers from vercel.json
vercel --prod
```

---

## 4. Security Headers & CSP Configuration

The frontend web server and API enforce:
- **Content-Security-Policy (CSP)**: `default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none';`
- **X-Content-Type-Options**: `nosniff`
- **X-Frame-Options**: `DENY`
- **Referrer-Policy**: `no-referrer`
- **Strict-Transport-Security (HSTS)**: `max-age=63072000; includeSubDomains; preload`
- **Cache-Control**: `no-store, no-cache, must-revalidate` on all sensitive API responses.
