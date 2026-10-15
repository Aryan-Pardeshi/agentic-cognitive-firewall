/**
 * IPC client transport: a Unix domain socket, or a named pipe on Windows. Node's
 * `net` module handles both. One connection per request, as the sidecar expects.
 * Retries a refused or missing socket with exponential backoff, like the Python SDK.
 */
import { createConnection } from "node:net";

import { decodeResponse, encodeRequest, RESPONSE_HEADER_SIZE } from "./frame";
import { FirewallConnectionError, FrameError } from "./models";

export const DEFAULT_SOCKET_PATH = process.platform === "win32" ? "\\\\.\\pipe\\acf" : "/tmp/acf.sock";
const MAX_ATTEMPTS = 3;
const BACKOFF_MS = 100;
const RETRYABLE = new Set(["ECONNREFUSED", "ENOENT"]);

export class Transport {
  constructor(readonly socketPath: string, private readonly key: Buffer, private readonly timeoutMs = 10_000) {}

  /** Sign and send a payload; resolve to the decoded response. */
  async send(payload: Buffer): Promise<{ decision: number; sanitisedPayload: Buffer }> {
    const frame = encodeRequest(payload, this.key);
    let lastError: unknown;
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
      try {
        return decodeResponse(await this.roundTrip(frame));
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (!code || !RETRYABLE.has(code)) throw error;
        lastError = error;
        if (attempt < MAX_ATTEMPTS) await new Promise((r) => setTimeout(r, BACKOFF_MS * 2 ** (attempt - 1)));
      }
    }
    throw new FirewallConnectionError(
      `could not connect to sidecar at ${this.socketPath} after ${MAX_ATTEMPTS} attempts: ${String(lastError)}`,
    );
  }

  /** Write one frame and read exactly one response frame. */
  private roundTrip(frame: Buffer): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const socket = createConnection(this.socketPath);
      const chunks: Buffer[] = [];
      let received = 0;
      let settled = false;
      const finish = (error: unknown, data?: Buffer) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        if (error) reject(error);
        else resolve(data as Buffer);
      };
      socket.setTimeout(this.timeoutMs, () => finish(new FrameError("timed out waiting for the sidecar")));
      socket.on("error", (error) => finish(error));
      socket.on("connect", () => socket.write(frame));
      socket.on("data", (chunk: Buffer) => {
        chunks.push(chunk);
        received += chunk.length;
        if (received < RESPONSE_HEADER_SIZE) return;
        const data = Buffer.concat(chunks);
        if (data.length >= RESPONSE_HEADER_SIZE + data.readUInt32BE(1)) finish(null, data);
      });
      socket.on("end", () => {
        const data = Buffer.concat(chunks);
        if (data.length >= RESPONSE_HEADER_SIZE) finish(null, data);
        else finish(new FrameError("the sidecar closed the connection without a decision"));
      });
    });
  }
}
