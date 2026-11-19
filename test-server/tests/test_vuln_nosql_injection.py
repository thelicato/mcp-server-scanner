from __future__ import annotations

from typing import Any

import pytest

from tests.conftest import ServerFactory
from tests.support import McpSession, tool_text


def _session(make_server: ServerFactory, vuln: str, mode: str) -> McpSession:
    return make_server(default_mode="safe", vulns={vuln: mode}).session({"authorization": "Bearer alice-token"})


def _find(session: McpSession, title: Any) -> dict[str, Any]:
    return session.call_tool("find_note_by_title", {"title": title})


def _owned(session: McpSession, owner: str) -> str:
    return tool_text(session.call_tool("list_notes_by_owner", {"owner": owner}))


@pytest.mark.parametrize("mode", ["vulnerable", "safe"])
def test_a_title_lookup_works_in_both_modes(make_server: ServerFactory, mode: str) -> None:
    session = _session(make_server, "nosql_operator_injection", mode)
    assert tool_text(_find(session, "standup")) == "standup: demo the release candidate"
    assert tool_text(_find(session, "q1a2b3")) == "no matching note"


def test_query_operators_are_honoured_only_when_vulnerable(make_server: ServerFactory) -> None:
    vulnerable = _session(make_server, "nosql_operator_injection", "vulnerable")
    assert tool_text(_find(vulnerable, {"$ne": "q1a2b3"})).count("\n") == 2
    assert tool_text(_find(vulnerable, {"$eq": "q1a2b3"})) == "no matching note"
    assert tool_text(_find(vulnerable, {"$regex": "^road"})) == "roadmap: ship offline mode in Q3"
    assert tool_text(_find(vulnerable, {"$in": ["groceries", "standup"]})).count("\n") == 1
    unknown = _find(vulnerable, {"$where": "sleep(1)"})
    assert unknown["isError"] is True and tool_text(unknown) == "Error: unknown operator: $where"
    safe = _find(_session(make_server, "nosql_operator_injection", "safe"), {"$ne": "q1a2b3"})
    assert safe["isError"] is True and tool_text(safe) == "Error: title must be a string"


@pytest.mark.parametrize("mode", ["vulnerable", "safe"])
def test_an_owner_lookup_works_in_both_modes(make_server: ServerFactory, mode: str) -> None:
    session = _session(make_server, "nosql_where_injection", mode)
    assert _owned(session, "alice") == "groceries\nroadmap"
    assert _owned(session, "q1a2b3") == "no notes"


def test_a_where_tautology_lists_every_note_only_when_vulnerable(make_server: ServerFactory) -> None:
    vulnerable = _session(make_server, "nosql_where_injection", "vulnerable")
    assert _owned(vulnerable, "q1a2b3' || 'a'=='a") == "groceries\nstandup\nroadmap"
    assert _owned(vulnerable, "q1a2b3' || 'a'=='b") == "no notes"
    assert _owned(vulnerable, "q1a2b3\" || \"a\"==\"a") == "no notes"
    broken = vulnerable.call_tool("list_notes_by_owner", {"owner": "q1a2b3' ||"})
    assert broken["isError"] is True and "SyntaxError" in tool_text(broken)
    safe = _session(make_server, "nosql_where_injection", "safe")
    assert _owned(safe, "q1a2b3' || 'a'=='a") == "no notes"
