import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { createBatcher } from "../src/watch/batcher.js";

describe("createBatcher", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("flushes once after the debounce window, deduplicating keys", () => {
    const onFlush = vi.fn();
    const b = createBatcher(300, onFlush);
    b.add("a.ts");
    b.add("b.ts");
    b.add("a.ts");
    vi.advanceTimersByTime(299);
    expect(onFlush).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(onFlush).toHaveBeenCalledTimes(1);
    expect(onFlush).toHaveBeenCalledWith(["a.ts", "b.ts"]);
  });

  it("restarts the timer on every new key", () => {
    const onFlush = vi.fn();
    const b = createBatcher(300, onFlush);
    b.add("a");
    vi.advanceTimersByTime(200);
    b.add("b");
    vi.advanceTimersByTime(200);
    expect(onFlush).not.toHaveBeenCalled();
    vi.advanceTimersByTime(100);
    expect(onFlush).toHaveBeenCalledWith(["a", "b"]);
  });

  it("starts a fresh batch after a flush", () => {
    const onFlush = vi.fn();
    const b = createBatcher(100, onFlush);
    b.add("a");
    vi.advanceTimersByTime(100);
    b.add("b");
    vi.advanceTimersByTime(100);
    expect(onFlush.mock.calls).toEqual([[["a"]], [["b"]]]);
  });

  it("cancel() drops pending keys", () => {
    const onFlush = vi.fn();
    const b = createBatcher(300, onFlush);
    b.add("a");
    b.cancel();
    vi.advanceTimersByTime(1000);
    expect(onFlush).not.toHaveBeenCalled();
  });
});
