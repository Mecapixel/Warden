"""
proxy/inspect/schema.py  (v2 — Model Security)

Structural validation of tool CALLS and tool OUTPUTS.

Tool-call validation: if policy declares a JSON Schema for a tool's arguments,
a call whose arguments don't conform is a structural anomaly — a
malformed-on-purpose call probing for a parser bug, or an agent confused into
the wrong shape. Deny-by-default already stops unknown tools; this stops
known tools invoked with the wrong structure.

Output validation: if policy declares an expected output shape, a response
that violates it is suspicious (a tool that should return a small JSON object
instead returning a megabyte of prose, or vice versa).

Zero hard dependencies: a compact built-in validator covers the JSON-Schema
subset that matters here (type, required, properties, enum, min/maxLength,
additionalProperties, min/max, items). If the full `jsonschema` package is
installed, richer schemas are supported automatically — but it is never
required.
"""

from dataclasses import dataclass
from typing import Any

try:  # optional richer backend
    import jsonschema as _jsonschema
    _HAVE_JSONSCHEMA = True
except Exception:
    _HAVE_JSONSCHEMA = False


@dataclass
class SchemaViolation:
    where: str        # "arguments" or "output"
    detail: str       # human-readable reason


_JSON_TYPES = {
    "object": dict, "array": list, "string": str,
    "number": (int, float), "integer": int, "boolean": bool, "null": type(None),
}


def _validate_builtin(value: Any, schema: dict, path: str = "") -> list[str]:
    """A small, dependency-free JSON-Schema subset validator. Returns a list
    of human-readable errors (empty == valid)."""
    errs: list[str] = []
    if not isinstance(schema, dict):
        return errs

    t = schema.get("type")
    if t:
        types = t if isinstance(t, list) else [t]
        ok = any(
            isinstance(value, _JSON_TYPES[x]) and
            not (x in ("number", "integer") and isinstance(value, bool))
            for x in types if x in _JSON_TYPES
        )
        if not ok:
            errs.append(f"{path or 'value'}: expected type {t}, got {type(value).__name__}")
            return errs  # type wrong: further checks are noise

    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{path or 'value'}: {value!r} not in allowed {schema['enum']}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errs.append(f"{path}: longer than maxLength {schema['maxLength']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{path}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{path}: above maximum {schema['maximum']}")

    if isinstance(value, dict):
        for req in schema.get("required", []):
            if req not in value:
                errs.append(f"{path or 'object'}: missing required '{req}'")
        props = schema.get("properties", {})
        for k, sub in props.items():
            if k in value:
                errs += _validate_builtin(value[k], sub, f"{path}.{k}" if path else k)
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(props)
            if extra:
                errs.append(f"{path or 'object'}: unexpected keys {sorted(extra)}")

    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errs += _validate_builtin(item, schema["items"], f"{path}[{i}]")

    return errs


def validate(value: Any, schema: dict) -> list[str]:
    """Validate value against schema, using jsonschema if available and the
    built-in subset otherwise."""
    if _HAVE_JSONSCHEMA:
        v = _jsonschema.Draft7Validator(schema)
        return [f"{'.'.join(str(p) for p in e.path) or 'value'}: {e.message}"
                for e in v.iter_errors(value)]
    return _validate_builtin(value, schema)


def check_tool_call(args: dict, arg_schema: dict | None) -> SchemaViolation | None:
    """Return a violation if the call's arguments don't conform, else None."""
    if not arg_schema:
        return None
    errs = validate(args, arg_schema)
    if errs:
        return SchemaViolation("arguments", "; ".join(errs[:5]))
    return None


def check_output(payload: Any, out_schema: dict | None) -> SchemaViolation | None:
    """Return a violation if a tool's output doesn't conform, else None."""
    if not out_schema:
        return None
    errs = validate(payload, out_schema)
    if errs:
        return SchemaViolation("output", "; ".join(errs[:5]))
    return None
