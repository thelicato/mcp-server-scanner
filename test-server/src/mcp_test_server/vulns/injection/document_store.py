from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from typing import Any

Document = dict[str, Any]

NOTES: tuple[Document, ...] = (
    {"title": "groceries", "owner": "alice", "body": "milk, eggs, coffee"},
    {"title": "standup", "owner": "bob", "body": "demo the release candidate"},
    {"title": "roadmap", "owner": "alice", "body": "ship offline mode in Q3"},
)


class QueryError(Exception):
    pass


class DocumentStore:

    def __init__(self, documents: Sequence[Document] = NOTES) -> None:
        self._documents = tuple(documents)

    def find(self, query: dict[str, Any]) -> list[Document]:
        return [document for document in self._documents
                if all(_satisfies(document.get(field), condition) for field, condition in query.items())]

    def where(self, expression: str) -> list[Document]:
        predicate = _compile_where(expression)
        return [document for document in self._documents if predicate(document)]


def _satisfies(value: Any, condition: Any) -> bool:
    if isinstance(condition, dict) and any(key.startswith("$") for key in condition):
        return all(_operator(value, operator, operand) for operator, operand in condition.items())
    return bool(value == condition)


def _operator(value: Any, operator: str, operand: Any) -> bool:
    if operator == "$eq":
        return bool(value == operand)
    if operator == "$ne":
        return bool(value != operand)
    if operator in ("$gt", "$gte", "$lt", "$lte"):
        return _compared(value, operator, operand)
    if operator in ("$in", "$nin"):
        if not isinstance(operand, list):
            raise QueryError(f"{operator} needs an array")
        return (value in operand) == (operator == "$in")
    if operator == "$regex":
        if not isinstance(operand, str):
            raise QueryError("$regex has to be a string")
        try:
            return isinstance(value, str) and re.search(operand, value) is not None
        except re.error as failure:
            raise QueryError(f"invalid regular expression: {failure}") from failure
    if operator == "$exists":
        return (value is not None) == bool(operand)
    raise QueryError(f"unknown operator: {operator}")


def _compared(value: Any, operator: str, operand: Any) -> bool:
    if type(value) is not type(operand):
        return False
    comparisons: dict[str, Callable[[Any, Any], Any]] = {
        "$gt": lambda left, right: left > right, "$gte": lambda left, right: left >= right,
        "$lt": lambda left, right: left < right, "$lte": lambda left, right: left <= right,
    }
    try:
        return bool(comparisons[operator](value, operand))
    except TypeError:
        return False


_TOKEN = re.compile(r"\s*(?:(\|\||&&|===|!==|==|!=|\(|\))|(this\.[A-Za-z_]\w*)|'((?:[^'\\]|\\.)*)'"
                    r"|\"((?:[^\"\\]|\\.)*)\"|(true|false))")


def _compile_where(expression: str) -> Callable[[Document], bool]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(expression):
        match = _TOKEN.match(expression, position)
        if match is None or match.end() == position:
            if expression[position:].strip() == "":
                break
            raise QueryError(f"SyntaxError: unexpected token at {position} in $where")
        operator, field, single, double, boolean = match.groups()
        if operator is not None:
            tokens.append(("op", operator))
        elif field is not None:
            tokens.append(("field", field[len("this."):]))
        elif boolean is not None:
            tokens.append(("bool", boolean))
        else:
            tokens.append(("str", single if single is not None else double or ""))
        position = match.end()
    parser = _WhereParser(tokens)
    evaluate = parser.disjunction()
    if not parser.done():
        raise QueryError("SyntaxError: unexpected token in $where")
    return lambda document: bool(evaluate(document))


class _WhereParser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self._tokens = tokens
        self._next = 0

    def done(self) -> bool:
        return self._next == len(self._tokens)

    def disjunction(self) -> Callable[[Document], Any]:
        terms = [self._conjunction()]
        while self._accept("||"):
            terms.append(self._conjunction())
        return lambda document: any(term(document) for term in terms)

    def _conjunction(self) -> Callable[[Document], Any]:
        terms = [self._comparison()]
        while self._accept("&&"):
            terms.append(self._comparison())
        return lambda document: all(term(document) for term in terms)

    def _comparison(self) -> Callable[[Document], Any]:
        left = self._atom()
        for operator in ("===", "==", "!==", "!="):
            if self._accept(operator):
                right = self._atom()
                equal = operator in ("===", "==")
                return lambda document: (left(document) == right(document)) == equal
        return left

    def _atom(self) -> Callable[[Document], Any]:
        if self._accept("("):
            inner = self.disjunction()
            if not self._accept(")"):
                raise QueryError("SyntaxError: missing ) in $where")
            return inner
        if self.done():
            raise QueryError("SyntaxError: unexpected end of $where")
        kind, text = self._tokens[self._next]
        self._next += 1
        if kind == "field":
            return lambda document: document.get(text)
        if kind == "str":
            return lambda document: text
        if kind == "bool":
            return lambda document: text == "true"
        raise QueryError(f"SyntaxError: unexpected {text} in $where")

    def _accept(self, operator: str) -> bool:
        if not self.done() and self._tokens[self._next] == ("op", operator):
            self._next += 1
            return True
        return False
