/**
 * Pure debounce batching: collects keys and flushes them together once no new
 * key has arrived for `delayMs`. Timers are injectable so it can be tested
 * deterministically.
 */
export interface Scheduler {
  setTimeout: (fn: () => void, ms: number) => unknown;
  clearTimeout: (handle: unknown) => void;
}

const defaultScheduler: Scheduler = {
  setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimeout: (handle) => globalThis.clearTimeout(handle as ReturnType<typeof setTimeout>),
};

export interface Batcher {
  /** Adds a key to the pending batch and (re)starts the debounce timer. */
  add(key: string): void;
  /** Drops the pending batch without flushing. */
  cancel(): void;
}

export function createBatcher(
  delayMs: number,
  onFlush: (keys: string[]) => void,
  scheduler: Scheduler = defaultScheduler,
): Batcher {
  const pending = new Set<string>();
  let handle: unknown;
  let armed = false;

  const disarm = () => {
    if (armed) {
      scheduler.clearTimeout(handle);
      armed = false;
    }
  };

  const flush = () => {
    disarm();
    if (pending.size === 0) return;
    const keys = [...pending];
    pending.clear();
    onFlush(keys);
  };

  return {
    add(key) {
      pending.add(key);
      disarm();
      handle = scheduler.setTimeout(flush, delayMs);
      armed = true;
    },
    cancel() {
      disarm();
      pending.clear();
    },
  };
}
