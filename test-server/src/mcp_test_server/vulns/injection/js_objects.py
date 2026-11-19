from __future__ import annotations

from typing import Any

DANGEROUS_KEYS = frozenset({"__proto__", "constructor", "prototype"})


class JsObject:

    def __init__(self, prototype: JsObject | None, properties: dict[str, Any] | None = None,
                 hidden: frozenset[str] = frozenset()) -> None:
        self.prototype = prototype
        self.properties: dict[str, Any] = dict(properties or {})
        self.hidden = set(hidden)

    def get(self, key: str) -> Any:
        if key == "__proto__":
            return self.prototype
        holder: JsObject | None = self
        while holder is not None:
            if key in holder.properties:
                return holder.properties[key]
            holder = holder.prototype
        return None

    def set(self, key: str, value: Any) -> None:
        if key == "__proto__":
            if value is None or isinstance(value, JsObject):
                self.prototype = value
            return
        self.properties[key] = value

    def for_in(self) -> list[tuple[str, Any]]:
        seen: set[str] = set()
        visited: list[tuple[str, Any]] = []
        holder: JsObject | None = self
        while holder is not None:
            for key, value in holder.properties.items():
                if key not in seen and key not in holder.hidden:
                    visited.append((key, value))
                seen.add(key)
            holder = holder.prototype
        return visited


class JsRealm:

    def __init__(self) -> None:
        self.object_prototype = JsObject(None)
        constructor = JsObject(None, {"prototype": self.object_prototype}, hidden=frozenset({"prototype"}))
        self.object_prototype.properties["constructor"] = constructor
        self.object_prototype.hidden.add("constructor")

    def new_object(self) -> JsObject:
        return JsObject(self.object_prototype)

    def from_json(self, value: Any) -> Any:
        if isinstance(value, dict):
            converted = self.new_object()
            for key, member in value.items():
                converted.properties[str(key)] = self.from_json(member)
            return converted
        if isinstance(value, list):
            return [self.from_json(member) for member in value]
        return value

    def merge(self, target: JsObject, source: JsObject, *, guarded: bool) -> None:
        for key, value in source.properties.items():
            if guarded and key in DANGEROUS_KEYS:
                continue
            if isinstance(value, JsObject):
                existing = target.get(key)
                if not isinstance(existing, JsObject):
                    existing = self.new_object()
                    target.set(key, existing)
                self.merge(existing, value, guarded=guarded)
            else:
                target.set(key, value)
