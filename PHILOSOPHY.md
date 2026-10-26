# ACF – Project Philosophy

ACF (Agentic Cognitive Firewall) is an application-level policy layer for LLM
agents. It decides whether what an agent reads and what it does are permitted
for the task at hand, and it makes that decision outside the agent, with no
model involved.

This document describes the principles behind the architecture, the
implementation, and how the project evolves.

---

# 1. Policy Decides; Detection Only Informs

Whether an agent may act must be decided by **explicit, enforceable policy**,
not by guessing whether a piece of text looks malicious.

Attacks can be written to look harmless, and a detector, rule-based or a model,
only recognises what it has seen before. ACF therefore treats detection as
evidence: scanners flag known attack phrasing and score risk, and the policy
uses that evidence alongside what it knows about the task. The decision holds
whether or not an attack was recognised, and whether the agent was fooled,
confused, or simply wrong.

---

# 2. Provenance Informs, but Never Grants Authority

Information can be a valid source of facts without being allowed to give
orders. A retrieved document may tell the agent what a bill says; it may not
redirect the payment.

ACF records where each important value came from (the user, a document, a web
page, a tool) and uses it when deciding on an action. A payment, message or
invitation to a value read from untrusted content is blocked unless the user or
the application vouched for it. Persistence must not raise trust either: a value
that was untrusted when stored stays untrusted when read back.

---

# 3. Check Every Boundary, Decide Outside the Agent

An agent has many entry points: the user's prompt, retrieved documents, tool
results, and memory. It also has exit points: tool calls and memory writes.
Each is an enforcement point.

Decisions are made in a **separate process** that the agent cannot reach into.
It assigns trust-relevant attributes, such as where a request came from, itself,
and discards what the agent claims about them. All content arriving from outside
the application is untrusted until policy says otherwise.

---

# 4. Independent of the Model

Security should not depend on which model runs the agent. Teams that choose a
small, local or open-weight model, for cost, latency or data locality, should get
the same protection as teams using the largest models.

No model is involved in an ACF decision, so the protection holds for any model
and adds no inference cost.

---

# 5. Minimal Overhead

Security controls should not noticeably slow an agent down. ACF uses
lightweight mechanisms (pattern matching, risk scoring, and policy evaluation
over a small session state) and adds about half a millisecond per check,
against seconds for a model reply. Heavier detectors, such as embedding-based
scanning, are optional.

---

# 6. General Engine, Application-Specific Policy

The rules are shared by every deployment. Each application supplies the data
they read: which tools it may use, which of them can do harm, which argument of
each decides where money or data goes, and which sources it controls. Each task
can narrow this further with a declared scope.

Writing that policy is a real cost, and the project treats it as one: defaults
cover common cases, and the examples show a complete application policy.

---

# 7. Policy-as-Code

Policies are written in Rego (Open Policy Agent), kept separate from their data
(YAML and JSON), and reloaded without restarting. They are:

- version controlled
- auditable and testable
- portable across environments
- deterministic: the same request, session state and policy always give the
  same decision

---

# 8. Framework-Agnostic Integration

ACF works with existing agent frameworks rather than replacing them. Thin
clients in Python and TypeScript call the decision process at each boundary,
and adapters integrate with LangChain, LangGraph and Agent Kernel. A custom
agent loop needs only a few calls.

Integration instruments the transitions to be governed; it does not change the
model or the tools. The guarantee covers the operations that are routed through
ACF.

---

# 9. Observability and Accountability

Every decision should be explainable. Each decision can be traced to a rule,
and the decision process records what was decided, why, and how long each step
took. Richer telemetry, such as OpenTelemetry traces, is planned and must never
slow down a decision.

---

# 10. Honest Claims

The project reports what ACF does and does not stop, measured on public
benchmarks with the runs recorded in the repository. Limits, such as attacks
with no destination to track, are stated alongside results.

---

# Summary

ACF makes agent security a property of the application around the model:
explicit policy decides what an agent may do, provenance informs those decisions
without granting authority, and decisions are made in an isolated process with
no model involved. The result is protection that is deterministic, inexpensive,
and independent of the model running the agent.
