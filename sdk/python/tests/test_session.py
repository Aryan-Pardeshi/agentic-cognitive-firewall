"""
Tests for Firewall.session() and the Session hook methods.

The transport is replaced with a recorder, so these check what the SDK puts
on the wire: the session ID on every call in a session, none on the
Firewall's own sessionless calls.
"""
from __future__ import annotations

import json

import pytest

from acf import Firewall, Session
from acf.models import ChunkResult, Decision, FirewallError

HMAC_KEY = b"test-key-32-bytes-long-padded!!!"


@pytest.fixture
def firewall(monkeypatch):
    monkeypatch.delenv("ACF_SEMANTIC_SCAN", raising=False)
    fw = Firewall(socket_path="/tmp/acf_test_session.sock", hmac_key=HMAC_KEY)
    sent: list[dict] = []

    def record(payload: bytes) -> dict:
        sent.append(json.loads(payload))
        return {"decision": Decision.ALLOW.value, "sanitised_payload": b""}

    monkeypatch.setattr(fw._transport, "send", record)
    fw.sent = sent  # type: ignore[attr-defined]
    return fw


def test_every_call_in_a_session_carries_its_id(firewall):
    with firewall.session() as s:
        s.on_prompt("hello")
        assert isinstance(s.on_context(["a chunk"])[0], ChunkResult)
        s.on_tool_call("search", {"q": "x"})
        s.on_memory("notes", "v", "write")
    assert [p["hook_type"] for p in firewall.sent] == ["on_prompt", "on_context", "on_tool_call", "on_memory"]
    assert {p["session_id"] for p in firewall.sent} == {s.id}


def test_firewall_calls_stay_sessionless(firewall):
    firewall.on_prompt("hello")
    firewall.on_tool_call("search", {})
    assert [p["session_id"] for p in firewall.sent] == ["", ""]


def test_sessions_get_distinct_random_ids(firewall):
    a, b = firewall.session(), firewall.session()
    assert a.id != b.id
    assert len(a.id) == 32 and all(c in "0123456789abcdef" for c in a.id)


def test_explicit_id_is_kept(firewall):
    s = firewall.session("run-42:tenant.a")
    s.on_prompt("x")
    assert s.id == "run-42:tenant.a"
    assert firewall.sent[0]["session_id"] == "run-42:tenant.a"


@pytest.mark.parametrize("bad", ["", "has space", "semi;colon", "x" * 129])
def test_malformed_ids_fail_early(firewall, bad):
    with pytest.raises(FirewallError):
        firewall.session(bad)


def test_session_payloads_match_firewall_payloads_apart_from_the_id(firewall):
    firewall.on_tool_call("search", {"q": "x"})
    firewall.session("s1").on_tool_call("search", {"q": "x"})
    plain, in_session = firewall.sent
    assert in_session["session_id"] == "s1"
    in_session["session_id"] = ""
    assert plain == in_session


def test_session_is_exported():
    assert Session.__module__ == "acf.session"
