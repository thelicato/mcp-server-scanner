from __future__ import annotations

from typing import Any

from mcp_test_server.protocol.catalog import Arguments, Tool, text_content
from mcp_test_server.protocol.context import CallContext
from mcp_test_server.protocol.jsonrpc import JsonObject
from mcp_test_server.surface import ServerSurface
from mcp_test_server.vulns.base import Vulnerability
from mcp_test_server.vulns.injection.js_objects import JsObject, JsRealm

SCHEMA: JsonObject = {
    "type": "object",
    "properties": {
        "customer": {"type": "string"},
        "options": {"type": "object", "properties": {"currency": {"type": "string"}, "locale": {"type": "string"}}},
    },
    "required": ["customer"],
}
DEFAULTS: JsonObject = {"options": {"currency": "EUR", "locale": "en-GB"}, "footer": "Thank you for your custom"}


class PrototypePollution(Vulnerability):
    name = "prototype_pollution"
    summary = ("format_invoice deep-merges its arguments into the invoice settings with a merge that follows "
               "__proto__ and constructor.prototype (the lodash.merge CVE-2018-16487 shape), polluting "
               "Object.prototype for every later call")

    def contribute(self, surface: ServerSurface) -> None:
        self._realm = JsRealm()
        surface.catalog.add_tool(Tool("format_invoice", "Format the invoice header for a customer", SCHEMA,
                                      self._format))

    async def _format(self, arguments: Arguments, context: CallContext) -> JsonObject:
        settings = self._realm.new_object()
        for source in (DEFAULTS, arguments):
            converted = self._realm.from_json(source)
            if isinstance(converted, JsObject):
                self._realm.merge(settings, converted, guarded=not self.vulnerable)
        return text_content("\n".join(_lines(settings)))


def _lines(settings: JsObject) -> list[str]:
    lines = [f"Invoice for {settings.get('customer')}"]
    for key, value in settings.for_in():
        if key == "customer":
            continue
        if isinstance(value, JsObject):
            lines += [f"{key}.{inner} = {_shown(member)}" for inner, member in value.for_in()]
        else:
            lines.append(f"{key} = {_shown(value)}")
    return lines


def _shown(value: Any) -> str:
    return "[object Object]" if isinstance(value, JsObject) else str(value)
