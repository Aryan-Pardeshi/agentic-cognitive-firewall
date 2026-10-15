/**
 * Binary frame encoder/decoder. Mirrors sidecar/internal/transport/frame.go and
 * sdk/python/acf/frame.py exactly.
 *
 * Request (54-byte header + payload):
 *   [0] magic 0xAC · [1] version 1 · [2:6] payload length, uint32 BE ·
 *   [6:22] nonce, 16 random bytes · [22:54] HMAC-SHA256 · [54:] JSON payload
 * The HMAC covers version (1B) || length (4B BE) || nonce (16B) || payload.
 *
 * Response: [0] decision · [1:5] sanitised length, uint32 BE · [5:] sanitised bytes
 */
import { createHmac, randomBytes } from "node:crypto";

import { FrameError } from "./models";

export const MAGIC = 0xac;
export const VERSION = 1;
export const HEADER_SIZE = 54;
export const RESPONSE_HEADER_SIZE = 5;

/** The bytes the HMAC is computed over. */
export function signedMessage(version: number, nonce: Buffer, payload: Buffer): Buffer {
  const head = Buffer.alloc(5);
  head.writeUInt8(version, 0);
  head.writeUInt32BE(payload.length, 1);
  return Buffer.concat([head, nonce, payload]);
}

/** Encode a signed request frame with a fresh nonce. */
export function encodeRequest(payload: Buffer, key: Buffer, nonce: Buffer = randomBytes(16)): Buffer {
  if (nonce.length !== 16) throw new FrameError("nonce must be 16 bytes");
  const mac = createHmac("sha256", key).update(signedMessage(VERSION, nonce, payload)).digest();
  const header = Buffer.alloc(6);
  header.writeUInt8(MAGIC, 0);
  header.writeUInt8(VERSION, 1);
  header.writeUInt32BE(payload.length, 2);
  return Buffer.concat([header, nonce, mac, payload]);
}

/** Decode a response frame. */
export function decodeResponse(data: Buffer): { decision: number; sanitisedPayload: Buffer } {
  if (data.length < RESPONSE_HEADER_SIZE) {
    throw new FrameError(`truncated response: got ${data.length} bytes, need at least 5`);
  }
  const decision = data.readUInt8(0);
  const length = data.readUInt32BE(1);
  if (data.length < RESPONSE_HEADER_SIZE + length) {
    throw new FrameError(`truncated sanitised payload: want ${length} bytes`);
  }
  return { decision, sanitisedPayload: data.subarray(RESPONSE_HEADER_SIZE, RESPONSE_HEADER_SIZE + length) };
}
