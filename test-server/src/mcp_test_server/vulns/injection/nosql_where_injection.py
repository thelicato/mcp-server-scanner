from __future__ import annotations

from collections.abc import Callable

from mcp_test_server.vulns.injection.document_store import Document, DocumentStore, QueryError
from mcp_test_server.vulns.injection.single_argument_tool import InputRejected, SingleArgumentTool

_STORE = DocumentStore()


class NosqlWhereInjection(SingleArgumentTool):
    name = "nosql_where_injection"
    summary = "list_notes_by_owner concatenates the owner argument into a MongoDB $where JavaScript expression"
    tool_name = "list_notes_by_owner"
    tool_description = "List the titles of the notes this owner wrote"
    argument = "owner"

    async def run_vulnerable(self, value: str) -> str:
        return self._titles(lambda: _STORE.where("this.owner == '" + value + "'"))

    async def run_safe(self, value: str) -> str:
        return self._titles(lambda: _STORE.find({"owner": value}))

    @staticmethod
    def _titles(query: Callable[[], list[Document]]) -> str:
        try:
            notes = query()
        except QueryError as failure:
            raise InputRejected(str(failure)) from failure
        return "\n".join(str(note["title"]) for note in notes) or "no notes"
