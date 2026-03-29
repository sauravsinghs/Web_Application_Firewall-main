import { EventEmitter } from "node:events";
import { appendFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import type { Metrics, WafEvent } from "./types.js";

const MAX_RECENT = 250;

class WafLogger extends EventEmitter {
  private recentEvents: WafEvent[] = [];
  private logPath: string;
  private metrics: Metrics = {
    total: 0,
    blocked: 0,
    allowed: 0,
    rateLimited: 0,
    avgLatencyMs: 0,
  };

  constructor(logPath: string) {
    super();
    this.logPath = logPath;
    mkdirSync(dirname(logPath), { recursive: true });
  }

  record(event: WafEvent): void {
    this.recentEvents.unshift(event);
    if (this.recentEvents.length > MAX_RECENT) {
      this.recentEvents.length = MAX_RECENT;
    }

    try {
      appendFileSync(this.logPath, JSON.stringify(event) + "\n", "utf-8");
    } catch {
      // disk write failure is non-fatal
    }

    const prev = this.metrics.total;
    this.metrics.total++;
    this.metrics.blocked += event.blocked ? 1 : 0;
    this.metrics.allowed += event.blocked ? 0 : 1;
    if (event.reason === "rate-limit") this.metrics.rateLimited++;

    this.metrics.avgLatencyMs =
      prev === 0
        ? event.latencyMs
        : (this.metrics.avgLatencyMs * prev + event.latencyMs) /
          this.metrics.total;

    this.emit("event", event);
  }

  getMetrics(): Readonly<Metrics> {
    return { ...this.metrics };
  }

  getRecentEvents(limit: number): WafEvent[] {
    return this.recentEvents.slice(0, Math.min(limit, MAX_RECENT));
  }
}

export { WafLogger };
