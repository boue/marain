"""Canonical JSON, HTTP identity, and database identity."""

import json
from typing import Any
from urllib.parse import quote, unquote, urlsplit

from agent_idempotency.errors import CanonicalError

INT_MIN = -9223372036854775808
INT_MAX = 9223372036854775807
ALLOWED_HEADERS = ("accept", "content-type")


def canonical_dumps(value: Any) -> str:
    """Return the canonical JSON text for a contract value."""
    return "".join(_parts(value))


def sha256_hex(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def operation_id(document: dict) -> str:
    return sha256_hex(canonical_dumps(document).encode("utf-8"))


def token_for(scope_id: str, op_id: str) -> str:
    return sha256_hex(f"{scope_id}\n{op_id}".encode("utf-8"))


def token_for_repo(repo_id: str, op_id: str) -> str:
    """Token for repo-wide operations. Uses repo_id instead of scope_id."""
    return sha256_hex(f"{repo_id}\n{op_id}".encode("utf-8"))


def redis_key(token: str) -> str:
    return f"idempotency:v1:{token}"


def fence_key(token: str) -> str:
    return f"idempotency:v1:fence:{token}"


def resource_key(document: dict) -> str:
    """Compute a resource key for hotspot grouping.
    
    HTTP: method + host + normalized path (numeric segments → :id)
    DB: driver + database + sorted tables
    Hook: hook:<name>
    """
    kind = document.get("kind")
    if kind == "http":
        return _http_resource_key(document)
    if kind == "db":
        return _db_resource_key(document)
    if kind == "hook":
        return f"hook:{document.get('hook', '')}"
    return f"{kind}:unknown"


def _http_resource_key(document: dict) -> str:
    method = document.get("method", "GET")
    url = document.get("url", "")
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    path = _normalize_path_for_resource(parts.path)
    return f"http:{method}:{host}:{path}"


def _normalize_path_for_resource(path: str) -> str:
    """Replace numeric path segments with :id."""
    import re
    segments = path.split("/")
    normalized = []
    for segment in segments:
        if segment and re.fullmatch(r"\d+", segment):
            normalized.append(":id")
        else:
            normalized.append(segment)
    return "/".join(normalized) or "/"


def _db_resource_key(document: dict) -> str:
    target = document.get("target", {})
    driver = target.get("driver", "")
    database = target.get("database", "")
    statements = document.get("statements", [])
    tables = set()
    for stmt in statements:
        sql = stmt.get("sql", "")
        tables.update(_extract_tables(sql))
    if not tables:
        # Fallback: use operation_id for unparseable SQL
        op_id = operation_id(document)
        return f"db:{driver}:{database}:unparseable:{op_id}"
    return f"db:{driver}:{database}:{','.join(sorted(tables))}"


def _extract_tables(sql: str) -> set[str]:
    """Extract table names from SQL. Regex-based, no full parser."""
    import re
    tables = set()
    # INSERT INTO <table>
    for match in re.finditer(r"INSERT\s+INTO\s+(\w+)", sql, re.IGNORECASE):
        tables.add(match.group(1))
    # UPDATE <table>
    for match in re.finditer(r"UPDATE\s+(\w+)\s+SET", sql, re.IGNORECASE):
        tables.add(match.group(1))
    # DELETE FROM <table>
    for match in re.finditer(r"DELETE\s+FROM\s+(\w+)", sql, re.IGNORECASE):
        tables.add(match.group(1))
    # CREATE TABLE <table>
    for match in re.finditer(r"CREATE\s+TABLE\s+(\w+)", sql, re.IGNORECASE):
        tables.add(match.group(1))
    # ALTER TABLE <table>
    for match in re.finditer(r"ALTER\s+TABLE\s+(\w+)", sql, re.IGNORECASE):
        tables.add(match.group(1))
    # DROP TABLE <table>
    for match in re.finditer(r"DROP\s+TABLE\s+(\w+)", sql, re.IGNORECASE):
        tables.add(match.group(1))
    return tables


def parse_json_value(text: str) -> Any:
    """Parse JSON, rejecting numbers that are not integers in i64 range."""

    def reject_float(_value: str) -> Any:
        raise CanonicalError("json numbers must be integers")

    try:
        value = json.loads(text, parse_float=reject_float)
    except CanonicalError:
        raise
    except json.JSONDecodeError as exc:
        raise CanonicalError("invalid json") from exc
    _require_contract(value)
    return value


def http_document(method: str, url: str, headers: Any, body: bytes) -> dict:
    """Build the HTTP operation document. Volatile headers are omitted."""
    pairs = _header_pairs(headers)
    return {
        "kind": "http",
        "method": method.upper(),
        "url": canonical_url(url),
        "headers": _identity_headers(pairs),
        "body": _body_document(pairs, body),
    }


def db_document(target: dict, statements: list[dict], isolation: str) -> dict:
    """Build the database operation document. Operation names are not accepted."""
    if "password" in target:
        raise CanonicalError("password is not part of the database target")
    port = target.get("port", 0)
    if isinstance(port, bool) or not isinstance(port, int):
        raise CanonicalError("database port must be an integer")
    return {
        "kind": "db",
        "target": {
            "database": str(target.get("database", "")),
            "driver": str(target["driver"]),
            "host": str(target.get("host", "")),
            "port": port,
            "user": str(target.get("user", "")),
        },
        "transaction": {"boundary": "single_transaction", "isolation": isolation},
        "statements": [
            {"params": [typed_param(param) for param in statement.get("params", [])], "sql": statement["sql"]}
            for statement in statements
        ],
    }


def typed_param(value: Any) -> dict:
    if value is None:
        return {"type": "null", "value": None}
    if isinstance(value, bool):
        return {"type": "bool", "value": value}
    if isinstance(value, int):
        if value < INT_MIN or value > INT_MAX:
            raise CanonicalError("integer out of range")
        return {"type": "int", "value": value}
    if isinstance(value, str):
        return {"type": "string", "value": value}
    if isinstance(value, bytes):
        import base64

        return {"type": "bytes", "value": base64.b64encode(value).decode("ascii")}
    if isinstance(value, (dict, list)):
        _require_contract(value)
        return {"type": "json", "value": value}
    raise CanonicalError("unsupported parameter type")


def canonical_url(url: str) -> str:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise CanonicalError("url scheme must be http or https")
    host = (parts.hostname or "").lower()
    if not host:
        raise CanonicalError("url host is required")
    if ":" in host:
        host = f"[{host}]"
    port = parts.port
    default = 80 if scheme == "http" else 443
    authority = host if port in (None, default) else f"{host}:{port}"
    path = _canonical_path(parts.path)
    query = _canonical_query(parts.query)
    if query:
        return f"{scheme}://{authority}{path}?{query}"
    return f"{scheme}://{authority}{path}"


def success_envelope(body: dict) -> dict:
    return {"outcome": "success", "body": body}


def error_envelope(code: str, message: str) -> dict:
    return {"outcome": "error", "body": {"code": code, "message": message[:500]}}


def as_contract(value: Any) -> dict:
    if not isinstance(value, dict) or value.get("kind") not in {"value", "http_response", "db_result"}:
        raise CanonicalError("result is not a contract value")
    canonical_dumps(value)
    return value


def _require_contract(value: Any) -> None:
    canonical_dumps(value)


def _parts(value: Any) -> list[str]:
    if value is None:
        return ["null"]
    if isinstance(value, bool):
        return ["true" if value else "false"]
    if isinstance(value, int):
        if value < INT_MIN or value > INT_MAX:
            raise CanonicalError("integer out of range")
        return [str(value)]
    if isinstance(value, str):
        return ['"', _escape(value), '"']
    if isinstance(value, list):
        out = ["["]
        for index, item in enumerate(value):
            if index:
                out.append(",")
            out.extend(_parts(item))
        out.append("]")
        return out
    if isinstance(value, dict):
        if any(not isinstance(key, str) for key in value):
            raise CanonicalError("object keys must be strings")
        out = ["{"]
        for index, key in enumerate(sorted(value)):
            if index:
                out.append(",")
            out.extend(['"', _escape(key), '":'])
            out.extend(_parts(value[key]))
        out.append("}")
        return out
    raise CanonicalError("unsupported value")


def _escape(text: str) -> str:
    pieces: list[str] = []
    for char in text:
        code = ord(char)
        if char == '"':
            pieces.append('\\"')
        elif char == "\\":
            pieces.append("\\\\")
        elif char == "\b":
            pieces.append("\\b")
        elif char == "\f":
            pieces.append("\\f")
        elif char == "\n":
            pieces.append("\\n")
        elif char == "\r":
            pieces.append("\\r")
        elif char == "\t":
            pieces.append("\\t")
        elif code < 0x20:
            pieces.append(f"\\u{code:04x}")
        else:
            pieces.append(char)
    return "".join(pieces)


def _header_pairs(headers: Any) -> list[tuple[str, str]]:
    if headers is None:
        return []
    if isinstance(headers, dict):
        return [(str(key), str(value)) for key, value in headers.items()]
    return [(str(key), str(value)) for key, value in headers]


def _identity_headers(pairs: list[tuple[str, str]]) -> list[list[str]]:
    kept = []
    for name, value in pairs:
        lowered = name.lower().strip()
        if lowered in ALLOWED_HEADERS:
            kept.append([lowered, value.strip()])
    kept.sort()
    return kept


def _body_document(pairs: list[tuple[str, str]], body: bytes) -> dict:
    if not body:
        return {"kind": "empty"}
    content_type = ""
    for name, value in pairs:
        if name.lower().strip() == "content-type":
            content_type = value
    if _is_json_type(content_type):
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return {"kind": "bytes", "hex": body.hex()}
        try:
            parsed = json.loads(text, parse_float=_reject_float)
        except CanonicalError:
            raise
        except json.JSONDecodeError:
            return {"kind": "bytes", "hex": body.hex()}
        canonical_dumps(parsed)
        return {"kind": "json", "value": parsed}
    return {"kind": "bytes", "hex": body.hex()}


def _reject_float(_value: str) -> Any:
    raise CanonicalError("json numbers must be integers")


def _is_json_type(value: str) -> bool:
    media = value.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


def _canonical_path(path: str) -> str:
    from posixpath import normpath

    decoded = unquote(path or "")
    if not decoded.startswith("/"):
        decoded = f"/{decoded}"
    normalized = normpath(decoded)
    if not normalized.startswith("/"):
        normalized = "/" + normalized
    return quote(normalized, safe="/-._~")


def _canonical_query(query: str) -> str:
    if not query:
        return ""
    pairs: list[tuple[str, str]] = []
    for piece in query.split("&"):
        if not piece:
            continue
        key, separator, value = piece.partition("=")
        pairs.append((unquote(key), unquote(value) if separator else ""))
    pairs.sort()
    return "&".join(f"{quote(key, safe='-._~')}={quote(value, safe='-._~')}" for key, value in pairs)
