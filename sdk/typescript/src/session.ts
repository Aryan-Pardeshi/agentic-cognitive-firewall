/**
 * Session: hook calls the sidecar treats as one agent run. Mirrors
 * sdk/python/acf/session.py.
 *
 * Within a session the sidecar remembers earlier calls: the declared task scope,
 * the values the agent read in untrusted content, and the values the user or
 * developer vouched for. That is what lets it block a tool call outside the
 * task, or one that sends money or data to a value read from a tool result.
 *
 *   const session = await fw.session({ allowedTools: ["read_file", "send_money"] });
 *   await session.onPrompt(request);
 *   const verdict = await session.onToolCall("send_money", { recipient, amount });
 */
import { randomBytes } from "node:crypto";

import type { Firewall } from "./firewall";
import { ChunkResult, Decision, decisionOf, FirewallError, HookResult, TaskScope } from "./models";

const SESSION_ID = /^[A-Za-z0-9._:-]{1,128}$/;

export class Session {
  private constructor(
    private readonly firewall: Firewall,
    readonly id: string,
    readonly scope: TaskScope | null,
  ) {}

  /** @internal Use `Firewall.session`. */
  static async open(firewall: Firewall, scope?: TaskScope, sessionId?: string): Promise<Session> {
    const id = sessionId ?? randomBytes(16).toString("hex");
    if (!SESSION_ID.test(id)) {
      throw new FirewallError("session id must be 1-128 characters from A-Z a-z 0-9 . _ : -");
    }
    if (!scope) return new Session(firewall, id, null);
    if (!Array.isArray(scope.allowedTools)) {
      throw new FirewallError("a task scope needs allowedTools");
    }
    const wire: Record<string, unknown> = { allowed_tools: [...scope.allowedTools] };
    if (scope.trustedValues) wire.trusted_values = [...scope.trustedValues];
    if (scope.toolConstraints) wire.tool_constraints = scope.toolConstraints;
    const result = await firewall.call("on_task", wire, "developer", id);
    if (decisionOf(result) !== Decision.ALLOW) {
      // Fail loudly: an agent must never run believing it is scoped when it is not.
      throw new FirewallError(
        `the sidecar rejected the task scope (${Decision[decisionOf(result)]}); check that every ` +
          "allowed tool is in its global allowlist and the constraints are well formed",
      );
    }
    return new Session(firewall, id, scope);
  }

  onPrompt(text: string): Promise<HookResult> {
    return this.firewall.call("on_prompt", text, "user", this.id);
  }

  onContext(chunks: string[]): Promise<ChunkResult[]> {
    return this.firewall.context(chunks, this.id);
  }

  onToolCall(name: string, params: Record<string, unknown>): Promise<HookResult> {
    return this.firewall.call("on_tool_call", { name, params }, "agent", this.id);
  }

  onToolResult(tool: string, result: unknown): Promise<HookResult> {
    return this.firewall.toolResult(tool, result, this.id);
  }

  onMemory(key: string, value: string, op: "read" | "write" = "write"): Promise<HookResult> {
    return this.firewall.call("on_memory", { key, value, op }, "agent", this.id);
  }
}
