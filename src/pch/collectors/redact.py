"""Redaction of raw API payloads before they are cached. Secret VALUES are never persisted."""

from __future__ import annotations

import re
from typing import Any

SECRET_NAME = re.compile(r"(?i)pass|pwd|secret|token|key|connstr|connectionstring|credential|\bpat\b")
SECRET_FIELD = re.compile(
    r"(?i)^(password|pwd|secret|client_?secret|access_?token|refresh_?token|token|api_?key|apikey|"
    r"accesskey|connection_?string|connectionstring|servicePrincipalKey|publishProfile|authorization)$"
)
# Field names that merely END in a secret-ish word (apiToken, authToken, privateKey, id_token, AWS_SECRET_ACCESS_KEY, ...).
# Paging cursors are not credentials and the collectors read them back from the cached body.
SECRET_FIELD_SUFFIX = re.compile(
    r"(?i)(secret|password|passwd|pwd|token|api_?key|private_?key|secret_?key|secret_?access_?key|access_?key|account_?key|sas_?token)$"
)
NOT_SECRET_FIELD = re.compile(r"(?i)^(continuation_?token|next_?page_?token|next_?token|page_?token|token_?type)$")
KNOWN_PREFIXES = re.compile(r"^(ghp_|gho_|github_pat_|xox[bap]-|AKIA|sk-|eyJ[A-Za-z0-9_-]{20,}\.)")
REDACTED = "***REDACTED***"
SUSPECTED = "<redacted:suspected-secret>"


def value_looks_secret(value: Any) -> str | None:
    """Return a reason string if a literal value looks like a credential (never the value itself)."""
    if not isinstance(value, str) or not value or value.startswith(("$(", "${{", "<redacted")):
        return None
    if value == SUSPECTED:
        return "value redacted at collection time as suspected secret"
    if KNOWN_PREFIXES.search(value):
        return "value matches a known credential prefix"
    if re.search(r"(?i)(password|pwd|accountkey|sharedaccesskey)\s*=\s*[^;\s]{4,}", value):
        return "value looks like a connection string with credentials"
    if len(value) >= 24 and re.fullmatch(r"[A-Za-z0-9+/=_\-]{24,}", value) and _entropy(value) > 4.0:
        return "value has high entropy"
    return None


def _entropy(s: str) -> float:
    import math
    from collections import Counter

    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _secret_field(name: str) -> bool:
    return bool(SECRET_FIELD.match(name) or (SECRET_FIELD_SUFFIX.search(name) and not NOT_SECRET_FIELD.match(name)))


def _is_var_entry(v: Any) -> bool:
    return isinstance(v, dict) and "value" in v and ("isSecret" in v or "allowOverride" in v or len(v) <= 3)


# NOTE (ReDoS): both patterns are linear. Indentation/spacing uses [ \t] (never \s, which also spans newlines and made
# "^\s*-?\s*" cubic on blank-line runs); the key word is found by a lookahead and consumed possessively.
_KEYWORDS = r"(?:pass|pwd|secret|token|key|connstr|connectionstring)"
_YAML_KV = re.compile(
    r"(?im)^(?P<pre>[ \t]*+-?[ \t]*+['\"]?(?=[\w.\-]*" + _KEYWORDS + r")[\w.\-]++['\"]?[ \t]*+:\s*+)(?P<val>[^\s$#].*)$"
)
_YAML_NAME_VALUE = re.compile(
    r"(?im)^(?P<pre>[ \t]*+-?[ \t]*+name:[ \t]*+['\"]?(?=[\w.\-]*" + _KEYWORDS + r")[\w.\-]++['\"]?[ \t]*+\n\s*+value:[ \t]*+)(?P<val>[^\s$].*)$"
)


def redact_text(text: str) -> str:
    """Best-effort redaction of YAML text (expanded pipelines)."""
    text = _YAML_NAME_VALUE.sub(lambda m: m.group("pre") + SUSPECTED, text)
    return _YAML_KV.sub(lambda m: m.group("pre") + SUSPECTED, text)


def redact_json(obj: Any, key_hint: str | None = None) -> Any:
    """Recursively redact: isSecret variables, secret-named fields and secret-named variable values."""
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if _is_var_entry(v) and isinstance(k, str):
                is_secret = bool(v.get("isSecret"))
                suspicious = bool(SECRET_NAME.search(k)) or value_looks_secret(v.get("value")) is not None
                nv = dict(v)
                if is_secret or (suspicious and v.get("value") not in (None, "")):
                    nv["value"] = None if is_secret else SUSPECTED
                out[k] = nv
            elif isinstance(k, str) and _secret_field(k) and isinstance(v, str | int | float):
                out[k] = REDACTED
            else:
                out[k] = redact_json(v, k)
        # {"name": "dbPassword", "value": "x", "isSecret": false}
        nm = out.get("name")
        if isinstance(nm, str) and "value" in out and isinstance(out["value"], str | type(None)):
            if out.get("isSecret"):
                out["value"] = None
            elif SECRET_NAME.search(nm) and out["value"] and not str(out["value"]).startswith("$("):
                out["value"] = SUSPECTED
        return out
    if isinstance(obj, list):
        return [redact_json(x, key_hint) for x in obj]
    if isinstance(obj, str) and key_hint in {"finalYaml", "yaml", "content"} and "\n" in obj:
        return redact_text(obj)
    return obj
