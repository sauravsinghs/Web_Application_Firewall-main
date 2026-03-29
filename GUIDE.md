# WAF Simulation -- Concepts, Features & Testing Guide

This document explains every concept, term, and feature used in this project. It is intended as a companion to the README and assumes no prior knowledge of web application firewalls.

---

## Table of Contents

1. [What Is a Web Application Firewall?](#1-what-is-a-web-application-firewall)
2. [Architecture Overview](#2-architecture-overview)
3. [Request Lifecycle](#3-request-lifecycle)
4. [The Scoring Engine](#4-the-scoring-engine)
5. [Detection Categories](#5-detection-categories)
6. [Rate Limiting](#6-rate-limiting)
7. [Reverse Proxy](#7-reverse-proxy)
8. [Event Logging (JSONL)](#8-event-logging-jsonl)
9. [Real-Time Dashboard & SSE](#9-real-time-dashboard--sse)
10. [Evaluation Runner](#10-evaluation-runner)
11. [How to Test Interactively](#11-how-to-test-interactively)
12. [Glossary](#12-glossary)

---

## 1. What Is a Web Application Firewall?

A **Web Application Firewall (WAF)** is a security layer that sits between external clients and a web application. Every HTTP request passes through the WAF before reaching the real server. The WAF inspects the request (URL, query parameters, headers, body) and decides whether to **allow** it through or **block** it.

In this project the WAF operates as a **reverse proxy**: the client talks to the WAF (port 8080), and the WAF either rejects the request or forwards it to the backend application (port 5001) on the client's behalf. The client never communicates with the backend directly.

```
                    ┌──────────────┐
  Client ──────────>│  WAF  :8080  │──── allowed ────> Backend :5001
                    │              │
                    │  blocked?    │──── 403 / 429 ──> Client
                    └──────┬───────┘
                           │
                    logs + SSE stream
                           │
                    ┌──────▼───────┐
                    │ Dashboard    │
                    │     :8501    │
                    └──────────────┘
```

---

## 2. Architecture Overview

The simulation consists of three independent Node.js processes:

| Service | Port | Role |
|---------|------|------|
| **Demo App** | 5001 | A simple Express backend with product search, login, and product listing routes. This is the "real application" the WAF protects. |
| **WAF Proxy** | 8080 | The firewall. Receives all client traffic, runs rate limiting and the scoring engine, then either blocks or forwards the request. Logs every decision and broadcasts events over SSE. |
| **Dashboard** | 8501 | A single-page web app that visualises WAF activity in real time using Chart.js and Server-Sent Events. |

There is also a **CLI evaluation runner** (`npm run evaluate`) that replays predefined good and bad payloads through the WAF and computes accuracy metrics.

### Source File Map

```
src/
  waf/
    index.ts          Main WAF Express app -- wires rate limiter, classifier, proxy
    classifier.ts     Scoring engine: 40+ regex rules with weights
    rate-limiter.ts   Per-IP fixed-window rate limiter
    logger.ts         JSONL file writer + in-memory event buffer + EventEmitter for SSE
    types.ts          Shared TypeScript interfaces (Rule, WafEvent, Metrics, etc.)
  demo-app/
    index.ts          Backend with /search, /login, /products, /product/:id
  dashboard/
    index.ts          Dashboard Express server (serves static files, proxies metrics)
    public/
      index.html      SPA with Chart.js charts, stat cards, event table, SSE client
  evaluate/
    index.ts          CLI tool -- replays payloads and computes TP/TN/FP/FN
testing-data/
  payloads-good.txt   22 benign search queries
  payloads-bad.txt    29 malicious payloads across all attack categories
```

---

## 3. Request Lifecycle

When a request arrives at the WAF on port 8080, it passes through three stages in order:

### Stage 1 -- Rate Limiting

The WAF extracts the client's IP address and checks a per-IP request counter. If the IP has exceeded the configured maximum (default: 100 requests per 60-second window), the request is immediately rejected with HTTP **429 Too Many Requests** and a `Retry-After` header. The scoring engine is never reached.

### Stage 2 -- Classification (Scoring Engine)

If rate limiting passes, the WAF concatenates the full URL path (including query string) and the request body into a single string. This string is tested against every rule in the scoring engine. Each matching rule adds its **weight** to a running **score**. If the total score meets or exceeds the **threshold** (default: 1.0), the request is classified as malicious and blocked with HTTP **403 Forbidden**. The response includes the score and the list of rules that matched.

### Stage 3 -- Proxy Forwarding

If the request is not blocked, the WAF forwards it to the backend at `http://localhost:5001`. It strips hop-by-hop headers (like `Connection`, `Transfer-Encoding`) and sends the request using the native `fetch` API. The backend's response is relayed back to the client.

### After Every Stage

Regardless of the outcome (429, 403, or proxied response), the WAF:

1. Creates a **WafEvent** object with timestamp, method, path, IP, decision, score, matched rules, status code, and latency.
2. Appends it as a JSON line to `logs/waf_events.jsonl`.
3. Updates in-memory aggregate metrics (total, blocked, allowed, rate limited, average latency).
4. Emits the event over **SSE** to all connected dashboard clients.

---

## 4. The Scoring Engine

The scoring engine is the core detection mechanism. It is defined in `src/waf/classifier.ts`.

### How It Works

1. **Input preparation**: The URL path and request body are URL-decoded (e.g. `%27` becomes `'`). For encoding-abuse and header-injection rules, the **raw** (un-decoded) input is used instead, because those attacks rely on encoded characters.

2. **Rule matching**: The engine iterates over 40+ rules. Each rule has:
   - **name** -- a human-readable identifier (e.g. `sqli-tautology`)
   - **pattern** -- a regular expression
   - **weight** -- a number (typically 0.3 to 1.0) representing severity
   - **category** -- the attack type (e.g. `sqli`, `xss`)

3. **Score accumulation**: Every rule whose regex matches adds its weight to the total score. Multiple rules can match a single request.

4. **Decision**: If `score >= threshold`, the request is malicious. The default threshold is **1.0**.

### Example

The request `/search?q=' OR 1=1 --` matches two rules:

| Rule | Category | Weight |
|------|----------|--------|
| `sqli-tautology` | sqli | 1.0 |
| `sqli-comment-trail` | sqli | 1.0 |

Total score = **2.0**, which exceeds the threshold of 1.0, so the request is blocked.

### Why Weights?

Not all patterns are equally suspicious. `alert(` alone (weight 0.5) could appear in legitimate text, but combined with `<script>` (weight 1.0) the total score of 1.5 correctly triggers a block. Weights allow the engine to make nuanced decisions rather than relying on a single pattern match.

---

## 5. Detection Categories

The 40+ rules are organised into six categories:

### SQL Injection (sqli)

SQL injection attacks attempt to manipulate database queries by injecting SQL syntax into user input.

| Rule | What It Detects | Example Payload |
|------|----------------|-----------------|
| `sqli-tautology` | Always-true conditions | `' OR 1=1 --` |
| `sqli-union-select` | UNION-based data extraction | `UNION SELECT username, password FROM users` |
| `sqli-drop` | Destructive DDL | `'; DROP TABLE users; --` |
| `sqli-comment-trail` | Comment-based truncation | `admin' --` |
| `sqli-stacked` | Stacked queries via semicolon | `1; SELECT * FROM information_schema.tables` |
| `sqli-waitfor` | Time-based blind (MSSQL) | `WAITFOR DELAY '00:00:05'` |
| `sqli-sleep` | Time-based blind (MySQL) | `SLEEP(5)` |
| `sqli-benchmark` | CPU-based blind (MySQL) | `BENCHMARK(10000000,SHA1('test'))` |
| `sqli-information` | Schema enumeration | `information_schema.tables` |
| `sqli-order-by-probe` | Column count probing | `ORDER BY 99` |
| `sqli-hex-literal` | Hex-encoded payloads | `0x41424344` |
| `sqli-inline-comment` | Inline comment obfuscation | `/* ... */` |
| `sqli-tautology-str` | String tautology | `' OR 'a'='a'` |

### Cross-Site Scripting (xss)

XSS attacks inject client-side scripts into web pages viewed by other users.

| Rule | What It Detects | Example Payload |
|------|----------------|-----------------|
| `xss-script-tag` | Script element injection | `<script>alert(1)</script>` |
| `xss-event-handler` | Event handler attributes | `onload=`, `onerror=`, `onfocus=` |
| `xss-javascript-uri` | JavaScript protocol URIs | `javascript:alert('xss')` |
| `xss-img-onerror` | Image error handler | `<img src=x onerror=alert(1)>` |
| `xss-svg-onload` | SVG load handler | `<svg onload=alert(1)>` |
| `xss-body-event` | Body element events | `<body onload=alert('xss')>` |
| `xss-iframe` | Iframe injection | `<iframe src="...">` |
| `xss-data-uri` | Data URI with HTML | `data:text/html,...` |
| `xss-eval` | eval() calls | `eval(...)` |
| `xss-document-cookie` | Cookie theft | `document.cookie` |
| `xss-alert` | Alert calls (low weight) | `alert(...)` |

### Path Traversal (traversal)

Path traversal attacks attempt to access files outside the web root by manipulating file paths.

| Rule | What It Detects | Example Payload |
|------|----------------|-----------------|
| `traversal-dotdot` | Directory traversal sequences | `../../etc/passwd` |
| `traversal-etc` | Linux sensitive files | `/etc/passwd`, `/etc/shadow` |
| `traversal-win` | Windows system paths | `\windows\system32\` |
| `traversal-null-byte` | Null byte injection | `%00` |
| `traversal-encoded` | URL-encoded traversal | `%2e%2e%2f` |

### Command Injection (cmdi)

Command injection attacks attempt to execute operating system commands on the server.

| Rule | What It Detects | Example Payload |
|------|----------------|-----------------|
| `cmdi-pipe` | Pipe to command | `\| whoami` |
| `cmdi-semicolon` | Semicolon chaining | `; cat /etc/passwd` |
| `cmdi-backtick` | Backtick execution | `` `id` `` |
| `cmdi-dollar-paren` | Subshell execution | `$(uname -a)` |
| `cmdi-uid-root` | Root user fingerprint | `uid=0(root)` |
| `cmdi-nc-reverse` | Reverse shell via netcat | `nc -e /bin/sh` |

### Header Injection (header-injection)

Header injection attacks insert CRLF sequences to manipulate HTTP response headers.

| Rule | What It Detects | Example Payload |
|------|----------------|-----------------|
| `header-crlf` | Encoded CRLF | `%0d%0a` |
| `header-newline` | Raw newline characters | `\r\n` |

### Encoding Abuse (encoding)

Encoding abuse attacks use double-encoding or overlong UTF-8 sequences to bypass security filters.

| Rule | What It Detects | Example Payload |
|------|----------------|-----------------|
| `encoding-double` | Double URL encoding | `%252e%252e%252f` (decodes to `%2e%2e%2f`, then `../`) |
| `encoding-overlong` | Overlong UTF-8 | `%c0%af` (overlong encoding of `/`) |

These rules match against the **raw** (un-decoded) input, because the attack specifically relies on the encoded form to evade detection.

---

## 6. Rate Limiting

The rate limiter (`src/waf/rate-limiter.ts`) implements a **fixed-window** per-IP counter.

### How It Works

- Each IP address gets a counter and a window start timestamp.
- When a request arrives, if the current time is past the window (default: 60 seconds), the counter resets to 1.
- If the counter exceeds the maximum (default: 100), the request is rejected with HTTP 429 and a `Retry-After` header telling the client how many seconds to wait.
- A background cleanup timer runs every 2 windows to remove stale entries from memory.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RATE_LIMIT_MAX` | 100 | Maximum requests per window per IP |
| `RATE_LIMIT_WINDOW_MS` | 60000 | Window duration in milliseconds |

### Why Rate Limiting Runs First

Rate limiting is checked **before** the scoring engine. This is intentional: if an attacker is flooding the server with requests, we want to reject them as cheaply as possible without spending CPU on regex matching.

---

## 7. Reverse Proxy

When a request passes both rate limiting and classification, the WAF acts as a **reverse proxy** -- it forwards the request to the backend and relays the response back to the client.

### What Happens During Proxying

1. The WAF builds a new URL by combining the original request path with the backend base URL (`http://localhost:5001`).
2. **Hop-by-hop headers** are stripped. These are headers that are meaningful only for a single transport connection and must not be forwarded: `Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, etc.
3. The `Host` header is also removed so the backend sees the correct host.
4. The request is sent using the native Node.js `fetch` API with an 8-second timeout.
5. The backend's response status, headers (minus hop-by-hop), and body are relayed back to the original client.
6. If the backend is unreachable, the WAF returns HTTP **502 Bad Gateway**.

---

## 8. Event Logging (JSONL)

Every request processed by the WAF -- whether blocked or allowed -- is logged in two places:

### JSONL File

Events are appended to `logs/waf_events.jsonl` (one JSON object per line). This file persists across WAF restarts and serves as the audit trail.

### In-Memory Ring Buffer

The most recent 250 events are kept in memory for fast access via the `/events` API endpoint.

### Event Schema

Each event contains:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | string | ISO 8601 timestamp |
| `method` | string | HTTP method (GET, POST, etc.) |
| `path` | string | Full URL path including query string |
| `ip` | string | Client IP address |
| `blocked` | boolean | Whether the request was blocked |
| `reason` | string | `"rule"`, `"rate-limit"`, or `"allowed"` |
| `score` | number | Total score from the scoring engine |
| `threshold` | number | The threshold that was in effect |
| `ruleMatches` | array | List of rules that matched (each with rule name, category, weight) |
| `statusCode` | number | HTTP status code returned to the client |
| `latencyMs` | number | Time from request arrival to response, in milliseconds |

---

## 9. Real-Time Dashboard & SSE

The dashboard at `http://localhost:8501` provides a live view of WAF activity.

### Server-Sent Events (SSE)

SSE is a browser API that allows the server to push data to the client over a persistent HTTP connection. Unlike WebSockets, SSE is one-directional (server to client) and uses plain HTTP.

The WAF exposes an SSE endpoint at `/events/stream`. When a new event is recorded, the WAF writes it to all connected SSE clients. The dashboard's JavaScript uses `EventSource` to subscribe and updates the UI on each incoming event.

### Dashboard Components

| Component | What It Shows |
|-----------|---------------|
| **SSE Pill** | Connection status: "Live" (green) when connected, "Reconnecting..." when the SSE connection drops |
| **Block % Pill** | Percentage of total requests that were blocked |
| **Total Requests** | Count of all requests processed |
| **Blocked** | Count of requests blocked (by rules or rate limiting) |
| **Allowed** | Count of requests forwarded to the backend |
| **Rate Limited** | Count of requests rejected by the rate limiter (subset of blocked) |
| **Avg Latency** | Average processing time per request |
| **Latency Trend** | Line chart of latency over the most recent 50 requests |
| **Decision Ratio** | Doughnut chart showing blocked vs allowed proportions |
| **Event Table** | Scrollable table of individual events with time, method, path, IP, status, decision badge, score, matched rules, and latency |
| **Filter Buttons** | Filter the event table by: All, Blocked, Allowed, or Rate Limited |

### How Metrics Load

On page load, the dashboard fetches `/api/data` from its own server (port 8501). The dashboard server then:

1. Fetches `/metrics` from the WAF for aggregate counters.
2. Reads the last 50 lines from the JSONL log file for event history.
3. If the WAF's metrics are stale (e.g. after a restart), the dashboard derives metrics from the log-file events.
4. Returns everything plus the SSE URL to the browser.

The browser renders the initial state and then opens an SSE connection for live updates.

---

## 10. Evaluation Runner

The evaluation runner (`npm run evaluate`) is an automated testing tool that measures the WAF's detection accuracy.

### How It Works

1. Reads two payload files:
   - `testing-data/payloads-good.txt` -- 22 benign search queries (e.g. "laptop price", "hello world")
   - `testing-data/payloads-bad.txt` -- 29 malicious payloads across all attack categories

2. For each payload, sends `GET /search?q=<payload>` to the WAF and records:
   - The HTTP status code
   - Whether it was blocked (status 403)
   - The response latency

3. Computes a **confusion matrix**:

| | WAF Blocked | WAF Allowed |
|---|---|---|
| **Actually Malicious** | True Positive (TP) | False Negative (FN) |
| **Actually Benign** | False Positive (FP) | True Negative (TN) |

4. Derives standard classification metrics:

| Metric | Formula | Meaning |
|--------|---------|---------|
| **Accuracy** | (TP + TN) / Total | Overall correctness |
| **Precision** | TP / (TP + FP) | Of all blocked requests, how many were truly malicious |
| **Recall** | TP / (TP + FN) | Of all malicious requests, how many were caught |
| **F1 Score** | 2 * Precision * Recall / (Precision + Recall) | Harmonic mean of precision and recall |

5. Writes results to:
   - `testing-data/evaluation_results.csv` -- per-payload results
   - `testing-data/evaluation_summary.json` -- aggregate metrics as JSON
   - `testing-data/evaluation_report.md` -- human-readable report

---

## 11. How to Test Interactively

### Prerequisites

Start all three services in separate terminals:

```bash
npm run dev:app        # Backend on :5001
npm run dev:waf        # WAF on :8080
npm run dev:dashboard  # Dashboard on :8501
```

Open the dashboard at **http://localhost:8501** and keep it visible.

### Sending Requests Through the WAF

All test requests should go to port **8080** (the WAF), not 5001 (the backend directly). The WAF inspects the request and either blocks or proxies it.

#### Benign Request (should be allowed)

```bash
curl http://localhost:8080/search?q=laptop
```

Expected: HTTP 200 with search results. Dashboard shows a green "ALLOWED" badge.

#### SQL Injection (should be blocked)

```bash
curl "http://localhost:8080/search?q=' OR 1=1 --"
```

Expected: HTTP 403 with `{"message":"Blocked by WAF","reason":"malicious pattern detected","score":2,"rules":["sqli-tautology","sqli-comment-trail"]}`. Dashboard shows a red "BLOCKED" badge.

#### XSS Attack (should be blocked)

```bash
curl "http://localhost:8080/search?q=<script>alert(1)</script>"
```

Expected: HTTP 403. Rules matched: `xss-script-tag`, `xss-alert`.

#### Path Traversal (should be blocked)

```bash
curl "http://localhost:8080/search?q=../../etc/passwd"
```

Expected: HTTP 403. Rules matched: `traversal-dotdot`, `traversal-etc`.

#### Command Injection (should be blocked)

```bash
curl "http://localhost:8080/search?q=; cat /etc/passwd"
```

Expected: HTTP 403. Rules matched: `traversal-etc`, `cmdi-semicolon`.

#### POST Request with Body (should be allowed)

```bash
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d "{\"username\":\"alice\"}"
```

Expected: HTTP 200 with `{"message":"Welcome alice","authenticated":true}`.

#### POST with Malicious Body (should be blocked)

```bash
curl -X POST http://localhost:8080/login -H "Content-Type: application/json" -d "{\"username\":\"' OR 1=1 --\"}"
```

Expected: HTTP 403.

#### Testing Your Own Payloads

You can test any string by passing it as the `q` parameter:

```bash
curl "http://localhost:8080/search?q=YOUR_PAYLOAD_HERE"
```

The WAF inspects both the URL and the request body, so you can also test via POST bodies.

### Using the Browser

You can also type directly in the browser address bar:

```
http://localhost:8080/search?q=hello world
http://localhost:8080/search?q=' OR 1=1 --
http://localhost:8080/products
http://localhost:8080/product/1
```

Each request will appear in the dashboard in real time.

### Checking WAF Internals

```bash
# View current aggregate metrics
curl http://localhost:8080/metrics

# View the last 10 events
curl "http://localhost:8080/events?limit=10"

# Health check (shows current score threshold)
curl http://localhost:8080/health
```

### Running the Full Evaluation Suite

```bash
npm run evaluate
```

This replays all 51 payloads (22 good + 29 bad) and prints a confusion matrix with accuracy, precision, recall, and F1 score.

---

## 12. Glossary

| Term | Definition |
|------|-----------|
| **WAF** | Web Application Firewall -- a security layer that inspects and filters HTTP traffic before it reaches the application |
| **Reverse Proxy** | A server that receives client requests and forwards them to a backend server, acting as an intermediary |
| **Scoring Engine** | The rule-based detection system that assigns a numeric score to each request based on pattern matches |
| **Rule** | A named regex pattern with a weight and category that detects a specific attack signature |
| **Weight** | A numeric value (0.3--1.0) assigned to each rule, representing its severity or confidence |
| **Threshold** | The minimum total score required to classify a request as malicious (default: 1.0) |
| **Rate Limiting** | Restricting the number of requests a single IP can make within a time window |
| **Fixed Window** | A rate limiting strategy where the counter resets at fixed intervals rather than sliding |
| **Hop-by-Hop Headers** | HTTP headers that apply only to a single connection and must not be forwarded by proxies |
| **JSONL** | JSON Lines -- a format where each line of a file is a separate JSON object |
| **SSE** | Server-Sent Events -- a browser API for receiving a stream of events from a server over HTTP |
| **EventSource** | The browser JavaScript API used to connect to an SSE endpoint |
| **SQL Injection (SQLi)** | An attack that inserts SQL code into application inputs to manipulate database queries |
| **Cross-Site Scripting (XSS)** | An attack that injects malicious scripts into web pages viewed by other users |
| **Path Traversal** | An attack that uses `../` sequences to access files outside the intended directory |
| **Command Injection** | An attack that executes operating system commands through application inputs |
| **Header Injection** | An attack that inserts CRLF characters to manipulate HTTP response headers |
| **Encoding Abuse** | Using double URL encoding or overlong UTF-8 to bypass security filters |
| **CRLF** | Carriage Return + Line Feed (`\r\n`) -- the HTTP line separator, exploited in header injection |
| **Confusion Matrix** | A table comparing predicted vs actual classifications (TP, TN, FP, FN) |
| **True Positive (TP)** | A malicious request correctly blocked |
| **True Negative (TN)** | A benign request correctly allowed |
| **False Positive (FP)** | A benign request incorrectly blocked |
| **False Negative (FN)** | A malicious request incorrectly allowed |
| **Accuracy** | (TP + TN) / Total -- overall correctness of the classifier |
| **Precision** | TP / (TP + FP) -- of all blocked requests, how many were truly malicious |
| **Recall** | TP / (TP + FN) -- of all malicious requests, how many were caught |
| **F1 Score** | Harmonic mean of precision and recall -- balances both metrics |
| **Express** | The Node.js web framework used for all three services |
| **Chart.js** | A JavaScript charting library used in the dashboard for latency and decision charts |
| **tsx** | A TypeScript execution tool that runs `.ts` files directly without a separate compile step |
