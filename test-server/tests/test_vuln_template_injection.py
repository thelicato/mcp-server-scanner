from __future__ import annotations

from typing import Any

from tests.conftest import ServerFactory
from tests.support import McpSession, TestServer, tool_text


def _session(make_server: ServerFactory, mode: str) -> McpSession:
    server: TestServer = make_server(default_mode="safe", vulns={"template_injection": mode})
    return server.session({"authorization": "Bearer alice-token"})


def _preview(session: McpSession, signature: str) -> dict[str, Any]:
    return session.call_tool("preview_signature", {"signature": signature})


def test_a_plain_signature_renders_in_both_modes(make_server: ServerFactory) -> None:
    for mode in ("vulnerable", "safe"):
        assert tool_text(_preview(_session(make_server, mode), "Ann Lee")) == "Kind regards,\nAnn Lee\nExample Ltd"


def test_template_syntax_is_evaluated_only_when_vulnerable(make_server: ServerFactory) -> None:
    assert "8202547" in tool_text(_preview(_session(make_server, "vulnerable"), "Ann{{1237*6631}}"))
    assert tool_text(_preview(_session(make_server, "safe"), "Ann{{1237*6631}}")) == (
        "Kind regards,\nAnn{{1237*6631}}\nExample Ltd")


def test_the_vulnerable_template_reaches_python_objects(make_server: ServerFactory) -> None:
    text = tool_text(_preview(_session(make_server, "vulnerable"), "{{ ''.__class__.__mro__[1].__name__ }}"))
    assert "object" in text


def test_broken_template_syntax_is_a_clean_tool_error(make_server: ServerFactory) -> None:
    result = _preview(_session(make_server, "vulnerable"), "Ann{{1237*")
    assert result["isError"] is True
    assert tool_text(result).startswith("Error: template error:")


def test_other_engines_syntax_is_left_alone(make_server: ServerFactory) -> None:
    session = _session(make_server, "vulnerable")
    for signature in ("${1237*6631}", "<%= 1237*6631 %>", "#{1237*6631}", "1237*6631"):
        assert "8202547" not in tool_text(_preview(session, signature))
