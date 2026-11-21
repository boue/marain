"""Database wrapper. The token binds one transaction around the statement list."""

import sqlite3
from typing import Any

from agent_idempotency.canonical import db_document, typed_param
from agent_idempotency.errors import (
    CanonicalError,
    ConfirmedRollback,
    NonserializableResult,
    NotApplied,
    TransactionBoundary,
    UncertainOutcome,
)


def statement(sql: str, params: list | None = None) -> dict:
    return {"params": list(params or []), "sql": sql}


def db_execute(client, target: dict, statements: list[dict], session, isolation: str = "deferred") -> dict:
    """Execute `statements` in one transaction, or replay the stored commit or rollback."""
    if session.in_transaction():
        raise TransactionBoundary("session is already inside a transaction")
    document = db_document(target, statements, isolation)

    def run() -> dict:
        try:
            session.begin()
        except Exception as exc:
            raise NotApplied(f"begin failed: {exc}") from exc
        results = []
        try:
            for item in statements:
                results.append(session.execute(item["sql"], item.get("params", [])))
            try:
                session.commit()
            except Exception as exc:
                raise UncertainOutcome("uncertain_database") from exc
        except UncertainOutcome:
            raise
        except Exception as exc:
            try:
                session.rollback()
            except Exception as rollback_exc:
                raise UncertainOutcome("uncertain_database") from rollback_exc
            raise ConfirmedRollback(str(exc)) from exc
        try:
            return _contract(results)
        except CanonicalError as exc:
            raise NonserializableResult(str(exc)) from exc

    return client.once(document, run)


class SqliteSession:
    """sqlite3 adapter. The connection is placed in autocommit mode when it is idle."""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection
        if not connection.in_transaction:
            connection.isolation_level = None

    def in_transaction(self) -> bool:
        return self.connection.in_transaction

    def begin(self) -> None:
        self.connection.execute("BEGIN")

    def execute(self, sql: str, params: list) -> dict:
        cursor = self.connection.execute(sql, tuple(_python_value(param) for param in params))
        fetched = cursor.fetchall() if cursor.description else []
        rows = [[_typed_cell(value) for value in row] for row in fetched]
        affected = cursor.rowcount if cursor.rowcount is not None and cursor.rowcount >= 0 else 0
        return {"rows": rows, "rows_affected": affected}

    def commit(self) -> None:
        self.connection.commit()

    def rollback(self) -> None:
        self.connection.rollback()


def _contract(results: list[dict]) -> dict:
    return {
        "committed": True,
        "kind": "db_result",
        "rows": [result["rows"] for result in results],
        "rows_affected": [int(result["rows_affected"]) for result in results],
    }


def _python_value(param: Any) -> Any:
    if isinstance(param, dict) and "type" in param:
        kind = param["type"]
        if kind == "null":
            return None
        if kind == "bytes":
            import base64

            return base64.b64decode(param["value"])
        return param.get("value")
    return param


def _typed_cell(value: Any) -> dict:
    try:
        return typed_param(value)
    except CanonicalError as exc:
        raise NonserializableResult(str(exc)) from exc
