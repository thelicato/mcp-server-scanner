from __future__ import annotations

from typing import Any

import pytest

from tests.conftest import ServerFactory
from tests.support import McpSession, tool_text

BAD_ARGUMENTS = [
    {"celsius": "mcp-scanner-type-confusion", "scale": "kelvin"},
    {"celsius": 20, "scale": -1.5e308},
    {"celsius": 20, "scale": "A" * 65536},
    {"celsius": [[[]]], "scale": "kelvin"},
    {},
]


def _session(make_server: ServerFactory, mode: str) -> McpSession:
    server = make_server(default_mode="safe", vulns={"verbose_errors": mode})
    return server.session({"authorization": "Bearer alice-token"})


def _convert(session: McpSession, arguments: dict[str, Any]) -> dict[str, Any]:
    return session.call_tool("convert_temperature", arguments)


@pytest.mark.parametrize("mode", ["vulnerable", "safe"])
def test_a_valid_conversion_works_in_both_modes(make_server: ServerFactory, mode: str) -> None:
    session = _session(make_server, mode)
    assert tool_text(_convert(session, {"celsius": 20, "scale": "fahrenheit"})) == "68.00"
    assert tool_text(_convert(session, {"celsius": 20, "scale": "kelvin"})) == "293.15"


@pytest.mark.parametrize("arguments", BAD_ARGUMENTS)
def test_bad_arguments_disclose_internals_only_when_vulnerable(
        make_server: ServerFactory, arguments: dict[str, Any]) -> None:
    vulnerable = _convert(_session(make_server, "vulnerable"), arguments)
    assert vulnerable["isError"] is True
    text = tool_text(vulnerable)
    assert "Traceback (most recent call last):" in text
    assert "verbose_errors.py" in text
    assert "Python 3." in text and "Starlette " in text
    safe = _convert(_session(make_server, "safe"), arguments)
    assert safe["isError"] is True
    assert tool_text(safe) == "Error: celsius must be a number and scale one of fahrenheit, kelvin"
