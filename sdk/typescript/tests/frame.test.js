// Frame encoding must match the Python SDK and the sidecar byte for byte.
const test = require("node:test");
const assert = require("node:assert/strict");

const { encodeRequest, decodeResponse, Decision, decisionFromByte, FrameError } = require("../dist/index.js");

// Generated with sdk/python/acf/frame.py for the same key, nonce and payload.
const PYTHON_FRAME =
  "ac01000000286465666768696a6b6c6d6e6f70717273c82313d25ebea712345fbda46a1c91607a48a83772bbef670deb803fd1a9b5057b22686f6f6b5f74797065223a226f6e5f70726f6d7074222c227061796c6f6164223a226869227d";

test("request frame matches the Python SDK", () => {
  const key = Buffer.from([...Array(32).keys()]);
  const nonce = Buffer.from([...Array(16).keys()].map((i) => i + 100));
  const payload = Buffer.from('{"hook_type":"on_prompt","payload":"hi"}');
  assert.equal(encodeRequest(payload, key, nonce).toString("hex"), PYTHON_FRAME);
});

test("each request gets a fresh nonce", () => {
  const key = Buffer.alloc(32, 1);
  const a = encodeRequest(Buffer.from("x"), key);
  const b = encodeRequest(Buffer.from("x"), key);
  assert.notEqual(a.subarray(6, 22).toString("hex"), b.subarray(6, 22).toString("hex"));
});

test("response frames decode, including a sanitised payload", () => {
  assert.deepEqual(decodeResponse(Buffer.from([0x02, 0, 0, 0, 0])).decision, 0x02);
  const sanitised = Buffer.concat([Buffer.from([0x01, 0, 0, 0, 4]), Buffer.from("[R]x")]);
  assert.equal(decodeResponse(sanitised).sanitisedPayload.toString(), "[R]x");
  assert.throws(() => decodeResponse(Buffer.from([0x01, 0, 0])), FrameError);
  assert.throws(() => decodeResponse(Buffer.from([0x01, 0, 0, 0, 9, 1])), FrameError);
});

test("decision bytes map to decisions", () => {
  assert.equal(decisionFromByte(0), Decision.ALLOW);
  assert.equal(decisionFromByte(1), Decision.SANITISE);
  assert.equal(decisionFromByte(2), Decision.BLOCK);
  assert.throws(() => decisionFromByte(7), FrameError);
});
