import { describe, it, expect, afterEach } from "vitest";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

// ─────────────────────────────────────────────────────────────────────────────
// Smoke test for the THE STDOUT RULE: stdio MCP transport uses stdout
// exclusively for JSON-RPC framing. This test spawns the *built* server as a
// real subprocess (matching how an MCP client launches it) and asserts that
// every line written to stdout parses as JSON-RPC — no stray console.log,
// banner, or progress output allowed to leak in.
//
// Requires `pnpm build` to have run first so dist/index.js exists.
// ─────────────────────────────────────────────────────────────────────────────

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SERVER_ENTRY = path.resolve(__dirname, "../dist/index.js");

interface JsonRpcMessage {
  jsonrpc: "2.0";
  id?: number | string;
  method?: string;
  result?: unknown;
  error?: unknown;
}

function sendRequest(child: ChildProcessWithoutNullStreams, message: Record<string, unknown>): void {
  child.stdin.write(JSON.stringify(message) + "\n");
}

/**
 * Accumulates every line the server writes to stdout for the lifetime of the
 * child process, and lets callers await a specific line index. A single
 * shared listener avoids losing lines that arrive between separate
 * one-off listener registrations.
 */
class StdoutLineCollector {
  private lines: string[] = [];
  private buffer = "";
  private waiters: { index: number; resolve: (line: string) => void }[] = [];

  constructor(child: ChildProcessWithoutNullStreams) {
    child.stdout.on("data", (chunk: Buffer) => {
      this.buffer += chunk.toString("utf-8");
      let newlineIndex: number;
      while ((newlineIndex = this.buffer.indexOf("\n")) !== -1) {
        const line = this.buffer.slice(0, newlineIndex);
        this.buffer = this.buffer.slice(newlineIndex + 1);
        if (line.trim().length === 0) continue;
        this.lines.push(line);
        this.flushWaiters();
      }
    });
  }

  private flushWaiters(): void {
    this.waiters = this.waiters.filter((w) => {
      if (this.lines.length > w.index) {
        w.resolve(this.lines[w.index]!);
        return false;
      }
      return true;
    });
  }

  /** Resolves with the Nth line (0-indexed) once it has arrived. */
  async line(index: number, timeoutMs = 10000): Promise<string> {
    if (this.lines.length > index) return this.lines[index]!;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Timed out waiting for stdout line ${index}. Got so far: ${JSON.stringify(this.lines)}`));
      }, timeoutMs);
      this.waiters.push({
        index,
        resolve: (line) => {
          clearTimeout(timer);
          resolve(line);
        },
      });
    });
  }

  all(): string[] {
    return this.lines;
  }
}

describe("MCP server smoke test (stdio)", () => {
  let child: ChildProcessWithoutNullStreams | null = null;

  afterEach(() => {
    if (child && !child.killed) {
      child.kill();
    }
    child = null;
  });

  it("emits only valid JSON-RPC on stdout and registers exactly 4 tools", async () => {
    child = spawn(process.execPath, [SERVER_ENTRY], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const stderrChunks: string[] = [];
    child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk.toString("utf-8")));

    const collector = new StdoutLineCollector(child);

    sendRequest(child, {
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "vibesafe-smoke-test", version: "0.0.0" },
      },
    });

    const initLine = await collector.line(0);

    // The #1 failure mode: any stray console.log would either break JSON
    // parsing outright, or silently smuggle non-protocol text into the
    // stream. Every line on stdout must parse as a JSON-RPC message.
    const initMessage = JSON.parse(initLine) as JsonRpcMessage;
    expect(initMessage.jsonrpc).toBe("2.0");
    expect(initMessage.id).toBe(1);
    expect(initMessage.error).toBeUndefined();

    // Required handshake notification before further requests.
    sendRequest(child, { jsonrpc: "2.0", method: "notifications/initialized" });

    sendRequest(child, { jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });

    const toolsLine = await collector.line(1);
    const toolsMessage = JSON.parse(toolsLine) as JsonRpcMessage & {
      result?: { tools: { name: string }[] };
    };

    expect(toolsMessage.jsonrpc).toBe("2.0");
    expect(toolsMessage.id).toBe(2);
    expect(toolsMessage.error).toBeUndefined();

    const toolNames = (toolsMessage.result?.tools ?? []).map((t) => t.name).sort();
    expect(toolNames).toEqual(["vibesafe_explain", "vibesafe_fix", "vibesafe_repair_plan", "vibesafe_scan"]);

    // Every line collected on stdout must parse as JSON-RPC — this is the
    // actual stdout-purity assertion: no banner, no progress bar, no stray log.
    for (const line of collector.all()) {
      expect(() => JSON.parse(line)).not.toThrow();
    }

    // Diagnostics belong on stderr, not stdout — confirm the startup banner
    // landed there instead of polluting the protocol stream.
    expect(stderrChunks.join("")).toContain("vibesafe-mcp");
  });
});
