"""Tests for task scopes derived from the user's request."""
from __future__ import annotations

import http.server
import json
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import derive_scopes  # noqa: E402
import run_agentdojo  # noqa: E402

KNOWN = {"read_file", "send_money", "get_balance"}


def test_parse_tool_list_reads_an_array_and_drops_unknown_names():
    assert derive_scopes.parse_tool_list('["send_money", "read_file", "launch"]', KNOWN) == [
        "read_file", "send_money"]
    assert derive_scopes.parse_tool_list("[]", KNOWN) == []


def test_parse_tool_list_takes_the_last_array_in_a_wrapped_answer():
    answer = 'I considered ["get_balance"] first.\n```json\n["read_file"]\n```'
    assert derive_scopes.parse_tool_list(answer, KNOWN) == ["read_file"]


@pytest.mark.parametrize("answer", [None, "", "send_money and read_file", "[1, 2]", '["unterminated'])
def test_parse_tool_list_is_none_when_there_is_no_array_of_names(answer):
    assert derive_scopes.parse_tool_list(answer, KNOWN) is None


def test_compare_and_summarise_against_the_reference_solution():
    suite_tools = {"banking": sorted(KNOWN)}
    references = {"banking": {"t0": ["read_file", "send_money"], "t1": ["get_balance"], "t2": ["get_balance"]}}
    scopes = {"banking": {"t0": ["read_file"], "t1": ["get_balance", "send_money"], "t2": None}}
    assert derive_scopes.compare(["read_file"], ["read_file", "send_money"], sorted(KNOWN)) == {
        "size": 1, "missing": ["send_money"], "extra": []}
    summary = derive_scopes.summarise(scopes, references, suite_tools)
    assert summary["tasks"] == 3 and summary["unreadable_answers"] == 1
    assert summary["tasks_missing_a_reference_tool"] == 1
    # t1 adds send_money; t2 has no scope, so it gets every tool.
    assert summary["tasks_with_extra_tools"] == 2
    assert summary["mean_scope_size"] == 2.0


def test_first_line_skips_parameter_documentation():
    assert derive_scopes.first_line("\n  Sends money.\n\n  :param recipient: IBAN") == "Sends money."
    assert derive_scopes.first_line(None) == ""


def test_load_scope_file_narrows_and_falls_back_to_the_suite(tmp_path):
    path = tmp_path / "scopes.json"
    path.write_text(json.dumps({"scopes": {"banking": {
        "t0": ["send_money", "not_a_tool"], "t1": None, "t2": []}}}), encoding="utf-8")
    suite_tools = {"banking": tuple(sorted(KNOWN))}
    scopes = run_agentdojo.load_scope_file(
        path, suite_tools, [("banking", "t0"), ("banking", "t1"), ("banking", "t2")])
    assert scopes[("banking", "t0")] == ("send_money",)
    assert scopes[("banking", "t1")] == tuple(sorted(KNOWN))   # no scope: every tool
    assert scopes[("banking", "t2")] == ()                      # an empty scope allows nothing
    with pytest.raises(SystemExit):
        run_agentdojo.load_scope_file(path, suite_tools, [("banking", "t9")])


def test_derive_scopes_end_to_end_against_a_local_endpoint(tmp_path):
    pytest.importorskip("agentdojo")
    seen: list[dict] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            body = json.dumps({
                "id": "x", "object": "chat.completion", "created": 0, "model": "m",
                "choices": [{"index": 0, "finish_reason": "stop", "message": {
                    "role": "assistant", "content": '["send_money", "get_most_recent_transactions"]'}}],
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    out = tmp_path / "scopes.json"
    try:
        assert derive_scopes.main([
            "--model", "m", "--base-url", f"http://127.0.0.1:{server.server_port}/v1",
            "--suites", "banking", "--no-thinking", "--out", str(out)]) == 0
    finally:
        server.shutdown()

    document = json.loads(out.read_text(encoding="utf-8"))
    assert len(document["scopes"]["banking"]) == 16 == len(seen)
    assert document["scopes"]["banking"]["user_task_0"] == ["get_most_recent_transactions", "send_money"]
    assert document["against_reference_solutions"]["tasks"] == 16
    # The model sees the request and the tools, and nothing the tools return.
    request = seen[0]
    assert [message["role"] for message in request["messages"]] == ["system", "user"]
    assert "send_money" in request["messages"][1]["content"]
    assert request["chat_template_kwargs"] == {"enable_thinking": False}
    assert request["temperature"] == 0.0
