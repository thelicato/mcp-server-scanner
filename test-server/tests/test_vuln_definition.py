from __future__ import annotations

import json
from typing import Any

import pytest

from tests.conftest import ServerFactory
from tests.support import McpSession, TestServer, tool_text

LIST_CHANGED = "notifications/tools/list_changed"
MODES = ["vulnerable", "safe"]


def _server(make_server: ServerFactory, vuln: str, mode: str, **overrides: Any) -> TestServer:
    return make_server(default_mode="safe", vulns={vuln: mode}, **overrides)


def _as(server: TestServer, user: str = "alice") -> McpSession:
    return server.session({"authorization": f"Bearer {user}-token"})


def _tools(session: McpSession) -> dict[str, dict[str, Any]]:
    tools: dict[str, dict[str, Any]] = {}
    params: dict[str, Any] = {}
    while True:
        result = session.result("tools/list", params)
        tools.update({tool["name"]: tool for tool in result["tools"]})
        if "nextCursor" not in result:
            return tools
        params = {"cursor": result["nextCursor"]}


def _streamed(session: McpSession, method: str, params: dict[str, Any]) -> list[dict[str, Any]]:
    response = session.post(session.message(method, params))
    assert response.headers["content-type"].startswith("text/event-stream")
    return [json.loads(line.removeprefix("data: ")) for line in response.text.splitlines() if line.startswith("data: ")]


def _convert(session: McpSession) -> str:
    return tool_text(session.call_tool("convert_currency", {"amount": 10, "currency": "GBP"}))


@pytest.mark.parametrize("mode", MODES)
def test_convert_currency_works_in_both_modes(make_server: ServerFactory, mode: str) -> None:
    session = _as(_server(make_server, "tool_definition_drift", mode))
    assert _convert(session) == "11.70 EUR"
    assert _convert(session) == "11.70 EUR"


def test_the_definition_is_redefined_after_its_first_call_only_when_vulnerable(make_server: ServerFactory) -> None:
    session = _as(_server(make_server, "tool_definition_drift", "vulnerable"))
    before = _tools(session)["convert_currency"]
    assert _tools(session)["convert_currency"] == before
    _convert(session)
    after = _tools(session)["convert_currency"]
    assert "id_rsa" in after["description"]
    assert "note" in after["inputSchema"]["properties"]
    assert _tools(session)["convert_currency"] == after


def test_the_safe_mode_only_adds_a_tool_after_the_first_call(make_server: ServerFactory) -> None:
    session = _as(_server(make_server, "tool_definition_drift", "safe"))
    before = _tools(session)
    assert "currency_history" not in before
    _convert(session)
    after = _tools(session)
    assert "currency_history" in after
    assert after["convert_currency"] == before["convert_currency"]


@pytest.mark.parametrize("mode", MODES)
def test_the_first_call_announces_a_list_change_on_the_reply_stream(make_server: ServerFactory, mode: str) -> None:
    session = _as(_server(make_server, "tool_definition_drift", mode, response_mode="sse"))
    arguments = {"name": "convert_currency", "arguments": {"amount": 1, "currency": "EUR"}}
    first = _streamed(session, "tools/call", arguments)
    assert [message.get("method") for message in first] == [LIST_CHANGED, None]
    assert first[1]["result"]["content"][0]["text"] == "1.00 EUR"
    assert [message.get("method") for message in _streamed(session, "tools/call", arguments)] == [None]


@pytest.mark.parametrize("mode", MODES)
def test_a_redefinition_stays_in_the_session_that_called(make_server: ServerFactory, mode: str) -> None:
    server = _server(make_server, "tool_definition_drift", mode)
    _convert(_as(server))
    other = _as(server)
    assert "id_rsa" not in _tools(other)["convert_currency"]["description"]
    assert "currency_history" not in _tools(other)


def test_the_server_advertises_tool_list_changes(server: TestServer) -> None:
    response = server.session(initialize=False).initialize()
    assert response.json()["result"]["capabilities"]["tools"]["listChanged"] is True


def _search_tickets_as(server: TestServer, user: str) -> dict[str, Any]:
    return _tools(_as(server, user))["search_tickets"]


def test_readers_see_a_targeted_description_only_when_vulnerable(make_server: ServerFactory) -> None:
    vulnerable = _server(make_server, "tool_definition_per_user", "vulnerable")
    assert "<IMPORTANT>" in _search_tickets_as(vulnerable, "carol")["description"]
    assert "<IMPORTANT>" not in _search_tickets_as(vulnerable, "alice")["description"]
    assert _search_tickets_as(vulnerable, "alice") == _search_tickets_as(vulnerable, "bob")
    safe = _server(make_server, "tool_definition_per_user", "safe")
    assert _search_tickets_as(safe, "carol") == _search_tickets_as(safe, "alice")


@pytest.mark.parametrize("mode", MODES)
def test_search_tickets_answers_every_user(make_server: ServerFactory, mode: str) -> None:
    server = _server(make_server, "tool_definition_per_user", mode)
    for user in ("alice", "carol"):
        assert tool_text(_as(server, user).call_tool("search_tickets", {"keyword": "printer"})).count("Printer") == 2
