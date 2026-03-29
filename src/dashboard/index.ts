import express from "express";
import { readFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = Number(process.env.DASHBOARD_PORT ?? 8501);
const WAF_METRICS_URL = process.env.WAF_METRICS_URL ?? "http://localhost:8080/metrics";
const WAF_EVENTS_URL = process.env.WAF_EVENTS_URL ?? "http://localhost:8080/events?limit=50";
const WAF_SSE_URL = process.env.WAF_SSE_URL ?? "http://localhost:8080/events/stream";
const LOG_FILE = process.env.WAF_LOG_FILE ?? "logs/waf_events.jsonl";

app.use(express.static(join(__dirname, "public")));

function readRecentEvents(limit = 50): unknown[] {
  if (!existsSync(LOG_FILE)) return [];
  try {
    const lines = readFileSync(LOG_FILE, "utf-8").trim().split("\n");
    return lines
      .slice(-limit)
      .reverse()
      .map((line) => {
        try { return JSON.parse(line); } catch { return null; }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

function deriveMetrics(events: Record<string, unknown>[]): Record<string, unknown> {
  let total = 0, blocked = 0, allowed = 0, rateLimited = 0, latencySum = 0;
  for (const e of events) {
    total++;
    if (e.blocked) blocked++;
    else allowed++;
    if (e.reason === "rate-limit") rateLimited++;
    latencySum += Number(e.latencyMs ?? 0);
  }
  return {
    total,
    blocked,
    allowed,
    rateLimited,
    avgLatencyMs: total ? Math.round((latencySum / total) * 100) / 100 : 0,
  };
}

app.get("/api/data", async (_req, res) => {
  let metrics: Record<string, unknown> = {};
  let events: unknown[] = [];

  try {
    const r = await fetch(WAF_METRICS_URL, { signal: AbortSignal.timeout(3000) });
    metrics = (await r.json()) as Record<string, unknown>;
  } catch { /* WAF unreachable */ }

  events = readRecentEvents(50);
  if (events.length === 0) {
    try {
      const r = await fetch(WAF_EVENTS_URL, { signal: AbortSignal.timeout(3000) });
      const body = (await r.json()) as { events?: unknown[] };
      events = body.events ?? [];
    } catch { /* fallback failed */ }
  }

  if (Number(metrics.total ?? 0) === 0 && events.length > 0) {
    metrics = deriveMetrics(events as Record<string, unknown>[]);
  }

  res.json({ metrics, events, sseUrl: WAF_SSE_URL });
});

app.get("/api/sse-url", (_req, res) => {
  res.json({ url: WAF_SSE_URL });
});

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`[Dashboard] listening on http://localhost:${PORT}`);
});

function shutdown() {
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 3000).unref();
}
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

export { app };
