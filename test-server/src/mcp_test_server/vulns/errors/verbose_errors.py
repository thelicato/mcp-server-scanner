from __future__ import annotations

import logging
import platform
import traceback
from collections.abc import Callable

import starlette

from mcp_test_server.protocol.catalog import Arguments, Tool, text_content
from mcp_test_server.protocol.context import CallContext
from mcp_test_server.protocol.jsonrpc import JsonObject
from mcp_test_server.surface import ServerSurface
from mcp_test_server.vulns.base import Vulnerability

_LOGGER = logging.getLogger(__name__)
SCALES: dict[str, Callable[[float], float]] = {
    "fahrenheit": lambda celsius: celsius * 9 / 5 + 32,
    "kelvin": lambda celsius: celsius + 273.15,
}
SCHEMA: JsonObject = {
    "type": "object",
    "properties": {"celsius": {"type": "number"}, "scale": {"type": "string", "enum": sorted(SCALES)}},
    "required": ["celsius", "scale"],
}
SAFE_ERROR = "Error: celsius must be a number and scale one of fahrenheit, kelvin"


class VerboseErrors(Vulnerability):
    name = "verbose_errors"
    summary = ("convert_temperature answers a bad argument with the Python traceback, its source file paths and the "
               "Python and Starlette versions, as a server left in debug mode does")

    def contribute(self, surface: ServerSurface) -> None:
        surface.catalog.add_tool(Tool("convert_temperature", "Convert a Celsius temperature to another scale",
                                      SCHEMA, self._convert))

    async def _convert(self, arguments: Arguments, context: CallContext) -> JsonObject:
        try:
            converted = SCALES[arguments["scale"]](float(arguments["celsius"]))
        except Exception:
            _LOGGER.debug("convert_temperature refused its arguments", exc_info=True)
            if not self.vulnerable:
                return text_content(SAFE_ERROR, is_error=True)
            return text_content(f"Internal error while converting\n{traceback.format_exc()}\nmcp-test-server on "
                                f"Python {platform.python_version()}, Starlette {starlette.__version__}",
                                is_error=True)
        return text_content(f"{converted:.2f}")
