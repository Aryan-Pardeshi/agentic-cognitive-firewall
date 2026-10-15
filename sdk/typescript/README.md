# ACF TypeScript SDK

The policy enforcement point for Node agents. It speaks the same wire protocol
and sends the same payloads as the Python SDK, so it works with the same sidecar
and the same policies. No runtime dependencies.

```bash
cd sdk/typescript
npm install
npm run build        # compiles to dist/
npm test             # builds, then runs the tests against a fake sidecar
```

## Use

The sidecar must be running and share the HMAC key (see the repository README).

```ts
import { Firewall, Decision, isSanitised, guardTool } from "@acf-sdk/acf";

const fw = new Firewall();            // reads ACF_HMAC_KEY (hex) and ACF_SOCKET_PATH

// One session per task. The scope can only narrow the sidecar's allowlist.
const session = await fw.session({
  allowedTools: ["read_file", "send_money"],
  toolConstraints: { send_money: { amount: { max: 500 } } },
  trustedValues: [confirmedPayee],     // values the user vouched for
});

if ((await session.onPrompt(request)) === Decision.BLOCK) throw new Error("refused");

// Wrap tools: each call is checked before it runs, each result before the model reads it.
const readFile = guardTool(session, "read_file", rawReadFile);
const sendMoney = guardTool(session, "send_money", rawSendMoney);
```

Or call the hooks directly:

| Method | When |
|---|---|
| `onPrompt(text)` | the user's request |
| `onContext(chunks)` | retrieved documents; one result per chunk |
| `onToolCall(name, params)` | before a tool runs |
| `onToolResult(tool, result)` | before the model reads a tool's output |
| `onMemory(key, value, op)` | memory reads and writes |
| `session(scope?)` | start a session; with a scope, the sidecar enforces it |

Each hook resolves to `Decision.ALLOW`, `Decision.BLOCK`, or a `SanitiseResult`
whose `sanitisedText` replaces the input (`isSanitised(result)` tells them apart).

## Adapters

- `guardTool(guard, name, fn)` wraps any async tool function: LangChain.js tools,
  the Vercel AI SDK, or a hand-written loop. A blocked call never runs and
  resolves to a refusal the agent can read; pass `{ throwOnBlock: true }` to throw
  `FirewallBlocked` instead.
- `firewallNode(guard, hook, key)` is a LangGraph.js node that runs `onPrompt`,
  `onContext` or `onToolResult` on a value in state.

Both accept a `Firewall` or a `Session`; a session also enforces its task scope
and the provenance rule.

## Example

[`examples/typescript/provenance.js`](../../examples/typescript/provenance.js)
runs the banking provenance scenario from Node against the banking policy.

## Not in this SDK

The optional semantic scanner is Python only. Its signals can only add risk, and
the sidecar's lexical scan and policies apply either way.
