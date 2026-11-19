from __future__ import annotations

from mcp_test_server.protocol.catalog import Arguments, Tool, text_content
from mcp_test_server.protocol.context import CallContext
from mcp_test_server.protocol.jsonrpc import JsonObject
from mcp_test_server.surface import ServerSurface
from mcp_test_server.vulns.base import Vulnerability
from mcp_test_server.vulns.injection.document_store import DocumentStore, QueryError

SCHEMA: JsonObject = {"type": "object", "properties": {"title": {"type": "string"}}, "required": ["title"]}


class NosqlOperatorInjection(Vulnerability):
    name = "nosql_operator_injection"
    summary = ("find_note_by_title passes the title argument into a MongoDB-style filter as received, so a JSON "
               "object such as {\"$ne\": \"x\"} is read as a query operator")

    def contribute(self, surface: ServerSurface) -> None:
        self._store = DocumentStore()
        surface.catalog.add_tool(Tool("find_note_by_title", "Return the notes with this title", SCHEMA,
                                      self._find))

    async def _find(self, arguments: Arguments, context: CallContext) -> JsonObject:
        title = arguments.get("title", "")
        if not self.vulnerable and not isinstance(title, str):
            return text_content("Error: title must be a string", is_error=True)
        try:
            notes = self._store.find({"title": title})
        except QueryError as failure:
            return text_content(f"Error: {failure}", is_error=True)
        return text_content("\n".join(f"{note['title']}: {note['body']}" for note in notes) or "no matching note")
