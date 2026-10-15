/**
 * Data models for the ACF TypeScript SDK. They mirror sdk/python/acf/models.py.
 */

/** The three enforcement outcomes, with their wire values. */
export enum Decision {
  ALLOW = 0x00,
  SANITISE = 0x01,
  BLOCK = 0x02,
}

/** Map a response byte to a Decision; throws on an unknown byte. */
export function decisionFromByte(byte: number): Decision {
  if (byte === Decision.ALLOW || byte === Decision.SANITISE || byte === Decision.BLOCK) {
    return byte;
  }
  throw new FrameError(`unknown decision byte: 0x${byte.toString(16).padStart(2, "0")}`);
}

/** Returned when the sidecar decides SANITISE: use `sanitisedText` in place of the input. */
export interface SanitiseResult {
  decision: Decision.SANITISE;
  sanitisedPayload: Buffer;
  sanitisedText: string | null;
}

/** What a hook returns: a decision, or the sanitised replacement. */
export type HookResult = Decision.ALLOW | Decision.BLOCK | SanitiseResult;

/** Per-chunk result of `onContext`. */
export interface ChunkResult {
  original: string;
  decision: Decision;
  sanitisedText: string | null;
}

/** True when a hook result is a SanitiseResult. */
export function isSanitised(result: HookResult | Decision): result is SanitiseResult {
  return typeof result === "object" && result !== null && result.decision === Decision.SANITISE;
}

/** The Decision of any hook result. */
export function decisionOf(result: HookResult | Decision): Decision {
  return isSanitised(result) ? Decision.SANITISE : (result as Decision);
}

/** A declared task scope; see `Firewall.session`. */
export interface TaskScope {
  /** Tools the task may call. Must be within the sidecar's global allowlist. */
  allowedTools: string[];
  /** Values the user or developer vouches for; they are never treated as untrusted. */
  trustedValues?: string[];
  /** Per tool, per argument: `allowed` values, a `pattern`, and/or a numeric `max`. */
  toolConstraints?: Record<string, Record<string, { allowed?: unknown[]; pattern?: string; max?: number }>>;
}

/** Base class for SDK errors. */
export class FirewallError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** The sidecar could not be reached after every retry. */
export class FirewallConnectionError extends FirewallError {}

/** A malformed frame was received. */
export class FrameError extends FirewallError {}

/** Thrown by adapters when a hook returns BLOCK. */
export class FirewallBlocked extends FirewallError {
  constructor(message: string, readonly hook?: string) {
    super(message);
  }
}
