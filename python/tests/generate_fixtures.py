"""Write the shared token and AES fixtures from the Python canonicalizer."""

import json
from pathlib import Path

from agent_idempotency.canonical import canonical_dumps, db_document, http_document, operation_id, resource_key, token_for, token_for_repo
from agent_idempotency.crypto import seal
from agent_idempotency.db import statement

ROOT = Path(__file__).resolve().parents[2]
SCOPE = "11" * 32


def http_case(name, method, url, headers, body):
    document = http_document(method, url, headers, body.encode("utf-8"))
    text = canonical_dumps(document)
    op_id = operation_id(document)
    return {
        "body_utf8": body,
        "canonical": text,
        "headers": headers,
        "kind": "http",
        "method": method,
        "name": name,
        "operation_id": op_id,
        "scope_id": SCOPE,
        "token": token_for(SCOPE, op_id),
        "url": url,
    }


def main() -> None:
    body = "{\"b\":1,\"a\":\"東京\\n\"}"
    db_statements = [statement("update t set n=? where id=?", [1, "a"]), statement("insert into t (id) values (?)", [2])]
    db_target = {"database": "app", "driver": "sqlite", "host": "", "port": 0, "user": "agent"}
    db = db_document(db_target, db_statements, "deferred")
    generic = {"kind": "op", "name": "save", "nested": {"a": True, "z": 1}, "password": "hunter2"}
    cases = [
        http_case(
            "http-json",
            "post",
            "HTTPS://User:Secret@Example.COM:443/a/./b?z=1&a=x",
            {"Accept": " application/json ", "Authorization": "Bearer one", "Content-Type": "application/json"},
            body,
        ),
        http_case(
            "http-json-different-authorization",
            "POST",
            "https://example.com/a/b?a=x&z=1",
            {"accept": "application/json", "Authorization": "Bearer two", "content-type": "application/json"},
            body,
        ),
        http_case(
            "http-query-order",
            "GET",
            "http://example.com:80/x?b=2&a=1",
            {},
            "",
        ),
    ]
    for name, document in (("db-statements", db), ("generic-secret", generic)):
        text = canonical_dumps(document)
        op_id = operation_id(document)
        case = {
            "canonical": text,
            "kind": "document" if name != "db-statements" else "db",
            "name": name,
            "operation_id": op_id,
            "scope_id": SCOPE,
            "token": token_for(SCOPE, op_id),
        }
        if name == "db-statements":
            case["isolation"] = "deferred"
            case["statements"] = db_statements
            case["target"] = db_target
            case["kind"] = "db"
        else:
            case["document"] = document
            case["kind"] = "document"
        cases.append(case)
    fixture_dir = ROOT / "protocol" / "fixtures"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    (fixture_dir / "tokens.json").write_text(json.dumps({"version": 1, "cases": cases}, indent=2) + "\n", encoding="utf-8")
    
    # Resource key fixtures
    resource_cases = [
        {
            "name": "http-numeric-path",
            "document": http_document("POST", "https://api.example.com/users/123", {}, b""),
            "resource_key": resource_key(http_document("POST", "https://api.example.com/users/123", {}, b"")),
        },
        {
            "name": "http-nested-numeric",
            "document": http_document("GET", "https://api.example.com/users/123/posts/456", {}, b""),
            "resource_key": resource_key(http_document("GET", "https://api.example.com/users/123/posts/456", {}, b"")),
        },
        {
            "name": "http-no-numeric",
            "document": http_document("GET", "https://api.example.com/health", {}, b""),
            "resource_key": resource_key(http_document("GET", "https://api.example.com/health", {}, b"")),
        },
        {
            "name": "http-root",
            "document": http_document("GET", "https://api.example.com/", {}, b""),
            "resource_key": resource_key(http_document("GET", "https://api.example.com/", {}, b"")),
        },
        {
            "name": "db-insert",
            "document": db_document(db_target, [statement("INSERT INTO users (name) VALUES (?)", ["alice"])], "deferred"),
            "resource_key": resource_key(db_document(db_target, [statement("INSERT INTO users (name) VALUES (?)", ["alice"])], "deferred")),
        },
        {
            "name": "db-update",
            "document": db_document(db_target, [statement("UPDATE posts SET title=? WHERE id=?", ["hello", 1])], "deferred"),
            "resource_key": resource_key(db_document(db_target, [statement("UPDATE posts SET title=? WHERE id=?", ["hello", 1])], "deferred")),
        },
        {
            "name": "db-delete",
            "document": db_document(db_target, [statement("DELETE FROM comments WHERE id=?", [1])], "deferred"),
            "resource_key": resource_key(db_document(db_target, [statement("DELETE FROM comments WHERE id=?", [1])], "deferred")),
        },
        {
            "name": "db-create",
            "document": db_document(db_target, [statement("CREATE TABLE t (id INTEGER)", [])], "deferred"),
            "resource_key": resource_key(db_document(db_target, [statement("CREATE TABLE t (id INTEGER)", [])], "deferred")),
        },
        {
            "name": "db-multiple-tables",
            "document": db_document(db_target, [
                statement("INSERT INTO users (name) VALUES (?)", ["alice"]),
                statement("UPDATE posts SET title=?", ["hello"]),
            ], "deferred"),
            "resource_key": resource_key(db_document(db_target, [
                statement("INSERT INTO users (name) VALUES (?)", ["alice"]),
                statement("UPDATE posts SET title=?", ["hello"]),
            ], "deferred")),
        },
        {
            "name": "db-unparseable",
            "document": db_document(db_target, [statement("SELECT 1", [])], "deferred"),
            "resource_key": resource_key(db_document(db_target, [statement("SELECT 1", [])], "deferred")),
        },
        {
            "name": "hook-pre-commit",
            "document": {"kind": "hook", "hook": "pre-commit"},
            "resource_key": "hook:pre-commit",
        },
        {
            "name": "http-repo-wide",
            "document": {**http_document("POST", "https://api.example.com/users/123", {}, b""), "repo_wide": True},
            "resource_key": resource_key(http_document("POST", "https://api.example.com/users/123", {}, b"")),
            "repo_wide": True,
        },
        {
            "name": "db-repo-wide",
            "document": {**db_document(db_target, [statement("INSERT INTO users (name) VALUES (?)", ["alice"])], "deferred"), "repo_wide": True},
            "resource_key": resource_key(db_document(db_target, [statement("INSERT INTO users (name) VALUES (?)", ["alice"])], "deferred")),
            "repo_wide": True,
        },
    ]
    for case in resource_cases:
        doc = case["document"]
        op_id = operation_id(doc)
        case["operation_id"] = op_id
        case["token_scope"] = token_for(SCOPE, op_id)
        if case.get("repo_wide"):
            case["token_repo"] = token_for_repo("r" * 64, op_id)
    (fixture_dir / "resource-keys.json").write_text(json.dumps({"version": 1, "cases": resource_cases}, indent=2) + "\n", encoding="utf-8")
    
    key = bytes.fromhex("11" * 32)
    nonce = bytes.fromhex("22" * 12)
    token = "abc"
    plaintext = {"body": {"kind": "value", "value": "東京"}, "outcome": "success"}
    sealed = seal(key, nonce, token, plaintext)
    (fixture_dir / "aes.json").write_text(
        json.dumps(
            {
                "ct": sealed["ct"],
                "key_hex": key.hex(),
                "nonce": sealed["nonce"],
                "nonce_hex": nonce.hex(),
                "plaintext": plaintext,
                "token": token,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
