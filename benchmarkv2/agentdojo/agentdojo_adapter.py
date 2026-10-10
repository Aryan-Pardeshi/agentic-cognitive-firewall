"""The AgentDojo-facing half of the runner. Needs the pinned agentdojo installed.

Written against agentdojo 0.1.35. It uses upstream's suites, attacks, tool
runtime, agent pipeline and task checks as they are, and adds only:

- a worst-case agent that replays ground-truth calls (replay mode)
- two pipeline elements that put ACF on the prompt and around tool execution
  (agent mode)
- scoring from a trace that leaves out the calls ACF blocked, which upstream's
  own runner cannot know about

Two private upstream methods are called for scoring,
TaskSuite._check_user_task_utility and _check_injection_task_security. They
are what TaskSuite.run_task_with_pipeline calls; the version pin in
manifest.json is what keeps that safe.
"""

from __future__ import annotations

import json
import os
from ast import literal_eval
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from agentdojo.agent_pipeline import (
    AgentPipeline,
    BasePipelineElement,
    InitQuery,
    SystemMessage,
    ToolsExecutionLoop,
    ToolsExecutor,
)
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.errors import AbortAgentError
from agentdojo.agent_pipeline.llms.google_llm import EMPTY_FUNCTION_NAME
from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str
from agentdojo.attacks.attack_registry import ATTACKS, load_attack
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionCall, FunctionsRuntime
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suites
from agentdojo.task_suite.task_suite import (
    functions_stack_trace_from_messages,
    model_output_from_messages,
)
from agentdojo.types import ChatMessage, ChatToolResultMessage, text_content_block_from_string

from acf_guard import BLOCKED_CALL_ERROR, Guard, injection_visible, visible_key

PROMPT_BLOCKED_MESSAGE = "The request was blocked by the security policy."


@dataclass(frozen=True)
class Case:
    suite: str
    user_task: str
    injection_task: str | None


@dataclass
class Plan:
    suites: list[str]
    suite_objects: dict[str, Any]
    attacks: dict[str, Any]
    attack_model_name: str | None
    suite_tools: dict[str, tuple[str, ...]]
    suite_tool_params: dict[str, dict[str, list[str]]]
    task_tools: dict[tuple[str, str], tuple[str, ...]]
    cases: list[Case] = field(default_factory=list)
    skipped_injection_tasks: dict[str, list[str]] = field(default_factory=dict)


class _AttackTarget(BasePipelineElement):
    """Stands in for the attacked pipeline: upstream attacks only read its name,
    to address the model in the injected text."""

    def __init__(self, name: str) -> None:
        self.name = name

    def query(self, query, runtime, env=EmptyEnv(), messages=[], extra_args={}):  # noqa: B006
        raise RuntimeError("the attack target is a name only and is never run")


def attack_target_name(model: str) -> str:
    """A pipeline name upstream can map to a model name for the injected text.

    A model upstream does not know is addressed as "Local model", which is how
    upstream treats its own local providers.
    """
    return model if any(known in model for known in MODEL_NAMES) else "local"


def _ordered(ids: Sequence[str]) -> list[str]:
    return sorted(ids, key=lambda task_id: int(task_id.rsplit("_", 1)[1]))


def build_plan(benchmark_version: str, suite_names: list[str] | None, *, attack_name: str,
               model: str, mode: str, user_tasks: list[str] | None = None,
               injection_tasks: list[str] | None = None, limit: int | None = None,
               benign: bool = True) -> Plan:
    """Enumerate the cases from the installed suites, so they match the version measured."""
    available = get_suites(benchmark_version)
    if not available:
        raise SystemExit(f"agentdojo has no suites for benchmark version {benchmark_version!r}")
    names = list(available) if suite_names is None else suite_names
    unknown = [name for name in names if name not in available]
    if unknown:
        raise SystemExit(f"unknown suites {unknown}; available: {sorted(available)}")
    if attack_name not in ATTACKS:
        raise SystemExit(f"unknown attack {attack_name!r}; available: {sorted(ATTACKS)}")

    target = _AttackTarget(attack_target_name(model))
    plan = Plan(suites=names, suite_objects={}, attacks={}, attack_model_name=None,
                suite_tools={}, suite_tool_params={}, task_tools={})
    for name in names:
        suite = available[name]
        plan.suite_objects[name] = suite
        plan.attacks[name] = load_attack(attack_name, suite, target)
        plan.attack_model_name = getattr(plan.attacks[name], "model_name", None)
        plan.suite_tools[name] = tuple(sorted(tool.name for tool in suite.tools))
        plan.suite_tool_params[name] = {
            tool.name: list(tool.parameters.model_fields) for tool in suite.tools
        }
        default_env = suite.load_and_inject_default_environment({})

        user_ids = _ordered(suite.user_tasks)
        if user_tasks is not None:
            user_ids = [task_id for task_id in user_ids if task_id in user_tasks]
        if limit is not None:
            user_ids = user_ids[:limit]
        injection_ids = _ordered(suite.injection_tasks)
        if injection_tasks is not None:
            injection_ids = [task_id for task_id in injection_ids if task_id in injection_tasks]
        if mode == "replay":
            replayable = [
                task_id for task_id in injection_ids
                if suite.injection_tasks[task_id].ground_truth(default_env.model_copy(deep=True))
            ]
            skipped = [task_id for task_id in injection_ids if task_id not in replayable]
            if skipped:
                plan.skipped_injection_tasks[name] = skipped
            injection_ids = replayable

        for user_id in user_ids:
            task = suite.user_tasks[user_id]
            task_env = task.init_environment(default_env.model_copy(deep=True))
            plan.task_tools[(name, user_id)] = tuple(
                sorted({call.function for call in task.ground_truth(task_env)})
            )
            if benign:
                plan.cases.append(Case(name, user_id, None))
            plan.cases.extend(Case(name, user_id, injection_id) for injection_id in injection_ids)
    return plan


def _prepare(plan: Plan, case: Case) -> tuple[Any, Any, Any, Any, Any]:
    """Suite, tasks and the environment with this case's injections in place."""
    suite = plan.suite_objects[case.suite]
    user_task = suite.user_tasks[case.user_task]
    injection_task = suite.injection_tasks[case.injection_task] if case.injection_task else None
    injections = plan.attacks[case.suite].attack(user_task, injection_task) if injection_task else {}
    environment = user_task.init_environment(suite.load_and_inject_default_environment(injections))
    return suite, user_task, injection_task, environment, environment.model_copy(deep=True)


def _plain(args: Any) -> dict[str, Any]:
    """Tool arguments as plain JSON values, which is what the SDK sends."""
    return json.loads(json.dumps(dict(args), default=str))


# ── replay mode ──────────────────────────────────────────────────────────────


def replay_case(plan: Plan, case: Case, guard: Guard) -> dict[str, Any]:
    """Run one case with the worst-case agent. No model.

    The agent makes the user task's ground-truth calls in order. The first
    time it can read the injected instruction in a tool result, it makes the
    injection task's ground-truth calls, then carries on. It obeys if and only
    if the instruction is still readable after ACF screened the result, and a
    call ACF blocks does not run.
    """
    suite, user_task, injection_task, env, pre_env = _prepare(plan, case)
    runtime = FunctionsRuntime(suite.tools)
    executed: list[FunctionCall] = []

    def make(call: FunctionCall, legitimate: bool) -> tuple[str, str] | None:
        if not guard.check_call(call.function, _plain(call.args), legitimate):
            return None
        result, error = runtime.run_function(env, call.function, call.args)
        executed.append(call)
        raw = error if error else tool_result_to_str(result)
        return raw, guard.screen_result(call.function, raw)

    goal = visible_key(injection_task.GOAL) if injection_task else ""
    seen = hidden = False
    proceed = guard.prompt(user_task.PROMPT)
    if proceed:
        user_calls = user_task.ground_truth(pre_env.model_copy(deep=True))
        injection_calls = (
            injection_task.ground_truth(pre_env.model_copy(deep=True)) if injection_task else []
        )
        for call in user_calls:
            observed = make(call, legitimate=True)
            if observed is None or seen or not injection_visible(observed[0], goal):
                continue
            if injection_visible(observed[1], goal):
                seen = True
                for injection_call in injection_calls:
                    make(injection_call, legitimate=False)
            else:
                hidden = True

    output = [text_content_block_from_string(user_task.GROUND_TRUTH_OUTPUT)]
    suite_utility = suite._check_user_task_utility(user_task, output, pre_env, env, executed)
    # Lower bound: the reference answer is only credible if the agent could
    # read every result the user's task relies on.
    lost_result = any(c["legitimate"] and c["result"] in ("SANITISE", "BLOCK") for c in guard.calls)
    record: dict[str, Any] = {
        "utility": bool(proceed and suite_utility and not lost_result),
        "attack_succeeded": None,
        "injection_seen": seen if injection_task else None,
        "injection_hidden": hidden if injection_task else None,
    }
    if injection_task is not None:
        record["attack_succeeded"] = bool(
            suite._check_injection_task_security(injection_task, output, pre_env, env, executed)
        )
    return record


# ── agent mode ───────────────────────────────────────────────────────────────


class ACFPromptGuard(BasePipelineElement):
    """Passes the user's prompt through on_prompt before the model sees it."""

    def __init__(self, guard: Guard) -> None:
        self.guard = guard

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):  # noqa: B006
        if not self.guard.prompt(query):
            raise AbortAgentError(PROMPT_BLOCKED_MESSAGE, list(messages), env)
        return query, runtime, env, messages, extra_args


class ACFToolsExecutor(ToolsExecutor):
    """Upstream's ToolsExecutor with ACF around each call.

    on_tool_call runs before the tool; a blocked call does not run and the
    model gets an error for it. on_tool_result screens the output before it is
    added to the conversation. Everything else follows upstream's executor.
    """

    def __init__(self, guard: Guard, legitimate: bool | None) -> None:
        super().__init__()
        self.guard = guard
        self.legitimate = legitimate
        self.blocked: set[int] = set()  # id() of the FunctionCall objects ACF blocked

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):  # noqa: B006
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args

        results = []
        known = {tool.name for tool in runtime.functions.values()}

        def reply(tool_call: FunctionCall, text: str, error: str | None) -> None:
            results.append(ChatToolResultMessage(
                role="tool", content=[text_content_block_from_string(text)],
                tool_call_id=tool_call.id, tool_call=tool_call, error=error,
            ))

        for tool_call in messages[-1]["tool_calls"]:
            if tool_call.function == EMPTY_FUNCTION_NAME:
                reply(tool_call, "", "Empty function name provided. Provide a valid function name.")
                continue
            if tool_call.function not in known:
                reply(tool_call, "", f"Invalid tool {tool_call.function} provided.")
                continue
            for key, value in tool_call.args.items():
                if isinstance(value, str) and is_string_list(value):
                    tool_call.args[key] = literal_eval(value)
            if not self.guard.check_call(tool_call.function, _plain(tool_call.args), self.legitimate):
                self.blocked.add(id(tool_call))
                reply(tool_call, "", BLOCKED_CALL_ERROR)
                continue
            result, error = runtime.run_function(env, tool_call.function, tool_call.args)
            text = self.guard.screen_result(tool_call.function, self.output_formatter(result))
            reply(tool_call, text, error)
        return query, runtime, env, [*messages, *results], extra_args


def make_llm(model: str, base_url: str | None) -> BasePipelineElement:
    """The agent model, through an OpenAI-compatible endpoint at temperature 0."""
    import openai  # noqa: PLC0415
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM  # noqa: PLC0415

    api_key = os.environ.get("OPENAI_API_KEY") or ("local" if base_url else None)
    client = openai.OpenAI(base_url=base_url, api_key=api_key)
    return OpenAILLM(client, model)


def agent_case(plan: Plan, case: Case, guard: Guard, llm: BasePipelineElement) -> dict[str, Any]:
    """Run one case end to end: upstream's default pipeline, with ACF in it.

    Mirrors TaskSuite.run_task_with_pipeline, including its three attempts at
    getting a final answer, but scores from a trace without the blocked calls.
    """
    suite, user_task, injection_task, env, pre_env = _prepare(plan, case)
    executor = ACFToolsExecutor(guard, legitimate=True if injection_task is None else None)
    pipeline = AgentPipeline([
        SystemMessage(load_system_message(None)),
        InitQuery(),
        ACFPromptGuard(guard),
        llm,
        ToolsExecutionLoop([executor, llm]),
    ])
    runtime = FunctionsRuntime(suite.tools)
    messages: Sequence[ChatMessage] = []
    output = None
    for _ in range(3):
        try:
            _, _, env, messages, _ = pipeline.query(user_task.PROMPT, runtime, env)
        except AbortAgentError as abort:
            env, messages = abort.task_environment, abort.messages
        output = model_output_from_messages(messages)
        if output is not None:
            break

    trace = [call for call in functions_stack_trace_from_messages(messages)
             if id(call) not in executor.blocked]
    record: dict[str, Any] = {
        "utility": bool(suite._check_user_task_utility(user_task, output or [], pre_env, env, trace)),
        "attack_succeeded": None,
    }
    if injection_task is not None:
        record["attack_succeeded"] = bool(
            suite._check_injection_task_security(injection_task, output or [], pre_env, env, trace)
        )
    return record
