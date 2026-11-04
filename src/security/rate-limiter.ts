/**
 * AUGUR RECON 2.0 - Request Rate Limiter
 * In-memory sliding window rate limiter for scan job submissions and API endpoints.
 */

interface RateLimitBucket {
  tokens: number;
  lastRefill: number;
}

export class TokenBucketRateLimiter {
  private buckets = new Map<string, RateLimitBucket>();
  private capacity: number;
  private refillRatePerSec: number;

  constructor(capacity = 30, refillRatePerSec = 5) {
    this.capacity = capacity;
    this.refillRatePerSec = refillRatePerSec;
  }

  public check(key: string, cost = 1): { allowed: boolean; remaining: number; retryAfterMs: number } {
    const now = Date.now();
    let bucket = this.buckets.get(key);

    if (!bucket) {
      bucket = { tokens: this.capacity, lastRefill: now };
      this.buckets.set(key, bucket);
    } else {
      // Calculate refilled tokens
      const elapsedSeconds = (now - bucket.lastRefill) / 1000;
      bucket.tokens = Math.min(this.capacity, bucket.tokens + elapsedSeconds * this.refillRatePerSec);
      bucket.lastRefill = now;
    }

    if (bucket.tokens >= cost) {
      bucket.tokens -= cost;
      return {
        allowed: true,
        remaining: Math.floor(bucket.tokens),
        retryAfterMs: 0,
      };
    }

    const missing = cost - bucket.tokens;
    const retryAfterMs = Math.ceil((missing / this.refillRatePerSec) * 1000);
    return {
      allowed: false,
      remaining: 0,
      retryAfterMs,
    };
  }

  // Periodic cleanup of stale buckets
  public prune(maxIdleMs = 300000) {
    const now = Date.now();
    for (const [key, bucket] of this.buckets.entries()) {
      if (now - bucket.lastRefill > maxIdleMs) {
        this.buckets.delete(key);
      }
    }
  }
}

// Global scan job rate limiter (e.g. max 5 new scans per minute per client)
export const scanJobRateLimiter = new TokenBucketRateLimiter(5, 0.1);

// General API request rate limiter
export const apiRateLimiter = new TokenBucketRateLimiter(60, 2);
