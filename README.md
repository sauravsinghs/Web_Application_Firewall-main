# Web Application Firewall (WAF) Simulation

A complete WAF simulation built with Node.js and TypeScript. The system implements a reverse-proxy firewall with a weighted scoring engine, rate limiting, a real-time SSE-powered dashboard, and an automated evaluation runner.

## Architecture

```
Client --> [WAF Proxy :8080] --> [Demo App :5001]
                |
                +--> block (403 / 429)
                +--> logs/waf_events.jsonl
                +--> SSE stream --> [Dashboard :8501]

[Evaluate CLI] --> [WAF Proxy :8080]
```

## Features

- **Scoring Engine** -- 40+ regex rules across 6 categories (SQLi, XSS, path traversal, command injection, header injection, encoding abuse). Each rule has a weight; total score vs configurable threshold determines block/allow. Matched rules are logged for explainability.
- **Rate Limiter** -- per-IP sliding window counter. Requests exceeding the threshold receive 429 before classification runs.
- **Reverse Proxy** -- allowed requests forwarded to the backend with hop-by-hop header stripping.
- **JSONL Event Logging** -- every request logged with timestamp, method, path, IP, decision, score, matched rules, status code, and latency.
- **Real-Time Dashboard** -- Chart.js SPA with SSE for live event streaming, latency trend chart, decision doughnut, stat cards, and filtered event table.
- **Evaluation Runner** -- replays good/bad payload files through the WAF and computes TP/TN/FP/FN, accuracy, precision, recall, F1 score, and average latency.

## Project Structure

```
src/
  waf/
    index.ts          WAF Express app (wires rate limiter -> classifier -> proxy)
    classifier.ts     Scoring engine and rule definitions
    rate-limiter.ts   Sliding window per-IP rate limiter
    logger.ts         JSONL writer + in-memory event buffer + SSE EventEmitter
    types.ts          Shared TypeScript interfaces
  demo-app/
    index.ts          Demo backend with /search, /login, /product/:id, /products
  dashboard/
    index.ts          Dashboard Express server
    public/
      index.html      SPA dashboard (Chart.js, SSE client)
  evaluate/
    index.ts          CLI evaluation runner
testing-data/
  payloads-good.txt   22 benign payloads
  payloads-bad.txt    29 malicious payloads (SQLi, XSS, traversal, cmdi, encoding)
```

## Run Locally

### Install

```bash
npm install
```

### Start services (3 terminals)

```bash
npm run dev:app        # Demo backend on :5001
npm run dev:waf        # WAF proxy on :8080
npm run dev:dashboard  # Dashboard on :8501
```

### Access

- WAF: http://localhost:8080
- Demo app (direct): http://localhost:5001
- Dashboard: http://localhost:8501

### Run evaluation

```bash
npm run evaluate
```

Or with a custom WAF URL:

```bash
npx tsx src/evaluate/index.ts --base-url http://localhost:8080
```

Outputs are written to `testing-data/evaluation_results.csv`, `evaluation_summary.json`, and `evaluation_report.md`.

## WAF Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check + score threshold |
| `/metrics` | GET | Aggregate counters (total, blocked, allowed, rate limited, avg latency) |
| `/events` | GET | Recent events (query `?limit=N`, max 250) |
| `/events/stream` | GET | SSE stream of live events |
| `/*` | ALL | Catch-all: inspect then proxy or block |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `BACKEND_URL` | `http://localhost:5001` | Backend to proxy to |
| `WAF_PORT` | `8080` | WAF listen port |
| `WAF_HOST` | `0.0.0.0` | WAF bind address |
| `WAF_LOG_FILE` | `logs/waf_events.jsonl` | Event log path |
| `SCORE_THRESHOLD` | `1.0` | Minimum score to block |
| `RATE_LIMIT_MAX` | `100` | Max requests per window per IP |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Rate limit window in ms |
| `DEMO_PORT` | `5001` | Demo app port |
| `DASHBOARD_PORT` | `8501` | Dashboard port |

## Demo Flow

1. Open the dashboard at http://localhost:8501
2. Send a normal request: `curl http://localhost:8080/search?q=hello`
3. Send a malicious request: `curl "http://localhost:8080/search?q=' OR 1=1 --"`
4. Watch the dashboard update in real time
5. Run `npm run evaluate` and review the generated report

## Detection Categories

| Category | Examples |
|----------|----------|
| SQL Injection | Tautology, UNION SELECT, DROP, stacked queries, time-based blind |
| XSS | Script tags, event handlers, javascript: URIs, SVG/IMG payloads |
| Path Traversal | `../`, `/etc/passwd`, null bytes, Windows paths |
| Command Injection | Pipe, semicolon, backtick, `$()`, reverse shell patterns |
| Header Injection | CRLF injection (`%0d%0a`) |
| Encoding Abuse | Double encoding, overlong UTF-8 |
