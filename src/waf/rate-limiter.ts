interface RateLimitEntry {
  count: number;
  windowStart: number;
}

export class RateLimiter {
  private windows = new Map<string, RateLimitEntry>();
  private maxRequests: number;
  private windowMs: number;
  private cleanupTimer: ReturnType<typeof setInterval>;

  constructor(maxRequests = 100, windowMs = 60_000) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.cleanupTimer = setInterval(() => this.cleanup(), windowMs * 2);
    this.cleanupTimer.unref();
  }

  /** Returns remaining seconds to wait, or 0 if allowed. */
  check(ip: string): { allowed: boolean; retryAfterSec: number } {
    const now = Date.now();
    let entry = this.windows.get(ip);

    if (!entry || now - entry.windowStart >= this.windowMs) {
      entry = { count: 1, windowStart: now };
      this.windows.set(ip, entry);
      return { allowed: true, retryAfterSec: 0 };
    }

    entry.count++;

    if (entry.count > this.maxRequests) {
      const retryAfterSec = Math.ceil(
        (entry.windowStart + this.windowMs - now) / 1000,
      );
      return { allowed: false, retryAfterSec: Math.max(retryAfterSec, 1) };
    }

    return { allowed: true, retryAfterSec: 0 };
  }

  reset(ip: string): void {
    this.windows.delete(ip);
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [ip, entry] of this.windows) {
      if (now - entry.windowStart >= this.windowMs) {
        this.windows.delete(ip);
      }
    }
  }

  destroy(): void {
    clearInterval(this.cleanupTimer);
  }
}
