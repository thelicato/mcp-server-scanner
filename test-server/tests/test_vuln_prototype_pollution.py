from __future__ import annotations

from typing import Any

import pytest

from tests.conftest import ServerFactory
from tests.support import McpSession, TestServer, tool_text

POLLUTERS = [
    {"__proto__": {"mcpkey": "mcpvalue"}},
    {"constructor": {"prototype": {"mcpkey": "mcpvalue"}}},
]


def _server(make_server: ServerFactory, mode: str) -> TestServer:
    return make_server(default_mode="safe", vulns={"prototype_pollution": mode})


def _session(server: TestServer) -> McpSession:
    return server.session({"authorization": "Bearer alice-token"})


def _invoice(session: McpSession, arguments: dict[str, Any]) -> str:
    return tool_text(session.call_tool("format_invoice", arguments))


@pytest.mark.parametrize("mode", ["vulnerable", "safe"])
def test_an_invoice_merges_options_over_the_defaults(make_server: ServerFactory, mode: str) -> None:
    text = _invoice(_session(_server(make_server, mode)), {"customer": "Ann", "options": {"currency": "GBP"}})
    assert text == ("Invoice for Ann\noptions.currency = GBP\noptions.locale = en-GB\n"
                    "footer = Thank you for your custom")


@pytest.mark.parametrize("polluter", POLLUTERS)
def test_pollution_reaches_every_later_call_only_when_vulnerable(
        make_server: ServerFactory, polluter: dict[str, Any]) -> None:
    vulnerable = _server(make_server, "vulnerable")
    _invoice(_session(vulnerable), {"customer": "Ann", **polluter})
    later = _invoice(_session(vulnerable), {"customer": "Bob"})
    assert "mcpkey = mcpvalue" in later
    assert "options.mcpkey = mcpvalue" in later
    safe = _server(make_server, "safe")
    _invoice(_session(safe), {"customer": "Ann", **polluter})
    assert "mcpvalue" not in _invoice(_session(safe), {"customer": "Bob"})


def test_pollution_through_a_nested_object(make_server: ServerFactory) -> None:
    server = _server(make_server, "vulnerable")
    _invoice(_session(server), {"customer": "Ann", "options": {"currency": "GBP", "__proto__": {"mcpkey": "v2"}}})
    assert "footer = Thank you for your custom\nmcpkey = v2" in _invoice(_session(server), {"customer": "Bob"})


@pytest.mark.parametrize("mode", ["vulnerable", "safe"])
def test_an_ordinary_nested_key_does_not_outlive_its_call(make_server: ServerFactory, mode: str) -> None:
    server = _server(make_server, mode)
    first = _invoice(_session(server), {"customer": "Ann", "extra": {"mcpkey": "mcpvalue"}})
    assert "extra.mcpkey = mcpvalue" in first
    assert "mcpvalue" not in _invoice(_session(server), {"customer": "Bob"})
