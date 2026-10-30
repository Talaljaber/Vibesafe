/** Token bucket. Capacity equals the rate (one second of burst); refills continuously. */

export const DEFAULT_RATE = 5;

export interface RateLimiterOptions {
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export class RateLimiter {
  private tokens: number;
  private last: number;
  private readonly capacity: number;
  private readonly now: () => number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(
    readonly rps: number = DEFAULT_RATE,
    options: RateLimiterOptions = {},
  ) {
    if (!Number.isFinite(rps) || rps <= 0) throw new Error(`invalid rate: ${String(rps)}`);
    this.capacity = Math.max(1, rps);
    this.now = options.now ?? (() => Date.now());
    this.sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
    this.tokens = this.capacity;
    this.last = this.now();
  }

  private refill(): void {
    const t = this.now();
    this.tokens = Math.min(this.capacity, this.tokens + ((t - this.last) / 1000) * this.rps);
    this.last = t;
  }

  /** Non-blocking: takes a token if one is available. */
  tryAcquire(): boolean {
    this.refill();
    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }

  /** Resolves once a token has been taken. */
  async acquire(): Promise<void> {
    for (;;) {
      if (this.tryAcquire()) return;
      const wait = Math.ceil(((1 - this.tokens) / this.rps) * 1000);
      await this.sleep(Math.max(1, wait));
    }
  }
}
