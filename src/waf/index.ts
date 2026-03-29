import express, { type Request, type Response } from "express";
import { classifyRequest } from "./classifier.js";
import { WafLogger } from "./logger.js";
import { RateLimiter } from "./rate-limiter.js";
import type { WafEvent } from "./types.js";

const BACKEND_URL = process.env.BACKEND_URL ?? "http://localhost:5001";
const LOG_FILE = process.env.WAF_LOG_FILE ?? "logs/waf_events.jsonl";
const PORT = Number(process.env.WAF_PORT ?? 8080);
const HOST = process.env.WAF_HOST ?? "0.0.0.0";
const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX ?? 100);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000);
const SCORE_THRESHOLD = Number(process.env.SCORE_THRESHOLD ?? 1.0);

const app = express();
const wafLogger = new WafLogger(LOG_FILE);
const rateLimiter = new RateLimiter(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);

// ── SSE connections ─────────────────────────────────────────────────
const sseClients = new Set<Response>();

wafLogger.on("event", (event: WafEvent) => {
  const data = `data: ${JSON.stringify(event)}\n\n`;
  for (const client of sseClients) {
    client.write(data);
  }
});

// ── CORS for dashboard (different port) ──────────────────────────────
app.use("/health", cors);
app.use("/metrics", cors);
app.use("/events", cors);

function cors(_req: Request, res: Response, next: () => void) {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  });
  if (_req.method === "OPTIONS") { res.sendStatus(204); return; }
  next();
}

// ── Observability endpoints ─────────────────────────────────────────
app.get("/health", (_req, res) => {
  res.json({ status: "ok", scoreThreshold: SCORE_THRESHOLD });
});

app.get("/metrics", (_req, res) => {
  res.json(wafLogger.getMetrics());
});

app.get("/events", (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit ?? 100), 250));
  res.json({ events: wafLogger.getRecentEvents(limit) });
});

app.get("/events/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    Connection: "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });
  res.write(":\n\n");
  sseClients.add(res);
  req.on("close", () => sseClients.delete(res));
});

// ── Buffer raw body for classification, then proxy manually ─────────
app.use(express.raw({ type: "*/*" }));

const HOP_BY_HOP = new Set([
  "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
  "te", "trailers", "transfer-encoding", "upgrade",
]);

app.use((req: Request, res: Response) => {
  const start = performance.now();
  const ip = (req.ip ?? req.socket.remoteAddress ?? "unknown").replace(/^::ffff:/, "");
  const fullPath = req.originalUrl;

  const makeEvent = (
    partial: Pick<WafEvent, "blocked" | "reason" | "score" | "ruleMatches" | "statusCode">,
  ): WafEvent => ({
    timestamp: new Date().toISOString(),
    method: req.method,
    path: fullPath,
    ip,
    threshold: SCORE_THRESHOLD,
    latencyMs: Math.round((performance.now() - start) * 100) / 100,
    ...partial,
  });

  // 1. Rate limiter
  const rl = rateLimiter.check(ip);
  if (!rl.allowed) {
    const event = makeEvent({ blocked: true, reason: "rate-limit", score: 0, ruleMatches: [], statusCode: 429 });
    wafLogger.record(event);
    res.set("Retry-After", String(rl.retryAfterSec));
    res.status(429).json({ message: "Rate limit exceeded", retryAfterSec: rl.retryAfterSec });
    return;
  }

  // 2. Classify
  const bodyStr = Buffer.isBuffer(req.body) ? (req.body as Buffer).toString("utf-8") : String(req.body ?? "");
  const result = classifyRequest(fullPath, bodyStr, SCORE_THRESHOLD);

  if (result.malicious) {
    const event = makeEvent({ blocked: true, reason: "rule", score: result.score, ruleMatches: result.ruleMatches, statusCode: 403 });
    wafLogger.record(event);
    res.status(403).json({
      message: "Blocked by WAF",
      reason: "malicious pattern detected",
      score: result.score,
      rules: result.ruleMatches.map((m) => m.rule),
    });
    return;
  }

  // 3. Forward to backend
  const forwardHeaders: Record<string, string> = {};
  for (const [key, val] of Object.entries(req.headers)) {
    if (!HOP_BY_HOP.has(key.toLowerCase()) && key.toLowerCase() !== "host" && typeof val === "string") {
      forwardHeaders[key] = val;
    }
  }

  const backendUrl = new URL(fullPath, BACKEND_URL);

  fetch(backendUrl.toString(), {
    method: req.method,
    headers: forwardHeaders,
    body: ["GET", "HEAD"].includes(req.method) ? undefined : new Uint8Array(req.body as Buffer),
    signal: AbortSignal.timeout(8000),
    redirect: "manual",
  })
    .then(async (upstream) => {
      const latencyMs = Math.round((performance.now() - start) * 100) / 100;
      const event: WafEvent = {
        timestamp: new Date().toISOString(),
        method: req.method,
        path: fullPath,
        ip,
        blocked: false,
        reason: "allowed",
        score: result.score,
        threshold: SCORE_THRESHOLD,
        ruleMatches: result.ruleMatches,
        statusCode: upstream.status,
        latencyMs,
      };
      wafLogger.record(event);

      res.status(upstream.status);
      upstream.headers.forEach((value, key) => {
        if (!HOP_BY_HOP.has(key.toLowerCase())) {
          res.setHeader(key, value);
        }
      });

      const body = Buffer.from(await upstream.arrayBuffer());
      res.end(body);
    })
    .catch(() => {
      const event = makeEvent({ blocked: false, reason: "allowed", score: result.score, ruleMatches: result.ruleMatches, statusCode: 502 });
      wafLogger.record(event);
      res.status(502).json({ message: "Backend unavailable" });
    });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[WAF] listening on http://${HOST}:${PORT}`);
  console.log(`[WAF] proxying to ${BACKEND_URL}`);
  console.log(`[WAF] score threshold: ${SCORE_THRESHOLD}`);
});

function shutdown() {
  for (const client of sseClients) client.end();
  sseClients.clear();
  rateLimiter.destroy();
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

export { app };
