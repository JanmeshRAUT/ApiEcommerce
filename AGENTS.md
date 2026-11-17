# Antigravity Agent Configuration (AGENTS.md)

This repository is an **API Security Monitoring Platform** — a central ingestion hub and multi-tenant security dashboard.

---

## 🛠 Tech Stack & Architecture

- **Backend**: Node.js (v23+), Express 4, TypeScript, tsx
- **Frontend**: React 19, Vite 8, Tailwind CSS v4, Lucide React, Recharts
- **Storage**: In-memory ring buffers with append-only JSONL files (`traffic.jsonl`, `features.jsonl`) and local state JSON files (`apps.json`, `threats.json`, `rules.json`, `settings.json`, `alerts_history.json`)
- **Ingestion**: Asynchronous, non-blocking telemetry ingestion at `POST /api/v1/ingest` (requires `X-API-Key` header)
- **Threat Engine**: 13 OWASP API security threat rules evaluated in memory (Shadow Mode & Alert Mode)
- **ML Features**: Periodic 1m, 5m, and 1h feature extraction for ML training and RFC-4180 CSV export

---

## 🚀 Key Commands

- `npm run dev` — Start the backend server & Vite dashboard at `http://localhost:3000`
- `npm run build` — Compile frontend production assets with Vite
- `npm run lint` — Run TypeScript type checking (`tsc --noEmit`)
- `npm test` — Run unit test suites (`tsx --test test/**/*.test.ts`)
- `npm run clean` — Clean build artifacts (`dist`)

---

## 📋 Guidelines for Agents

1. **Safety & Privacy**: Never persist request bodies, query parameter values, passwords, or secrets. Normalize paths (`/orders/123` -> `/orders/{id}`) and store query keys only.
2. **Ingest Performance**: Ingest requests must return an immediate `202 Accepted` response. Background processing must never block incoming telemetry.
3. **Multi-Tenant Scoping**: All telemetry, threat evaluations, and metrics support scoping by `app_id`.
4. **Testing**: Always run `npm run lint` and `npm test` after modifying server logic or threat detection rules.
