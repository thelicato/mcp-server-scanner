from __future__ import annotations

from jinja2 import Environment, TemplateError

from mcp_test_server.vulns.injection.single_argument_tool import InputRejected, SingleArgumentTool

COMPANY = "Example Ltd"
_ENVIRONMENT = Environment(autoescape=False)


class TemplateInjection(SingleArgumentTool):
    name = "template_injection"
    summary = "preview_signature concatenates the signature argument into Jinja2 template source before rendering it"
    tool_name = "preview_signature"
    tool_description = "Preview an email signature under the company footer"
    argument = "signature"

    async def run_vulnerable(self, value: str) -> str:
        return _render("Kind regards,\n" + value + "\n{{ company }}", {})

    async def run_safe(self, value: str) -> str:
        return _render("Kind regards,\n{{ signature }}\n{{ company }}", {"signature": value})


def _render(source: str, variables: dict[str, str]) -> str:
    try:
        return _ENVIRONMENT.from_string(source).render(company=COMPANY, **variables)
    except TemplateError as failure:
        raise InputRejected(f"template error: {failure}") from failure
