"""Best-effort credential redaction for bounded HTTP evidence, not a DLP system."""

from __future__ import annotations

import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_REDACTED = "<redacted>"
_SENSITIVE = ("password", "passwd", "passphrase", "secret", "token", "apikey", "credential", "authorization", "cookie", "privatekey", "sessionid", "signature", "csrf", "xsrf")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_ASSIGNMENT = re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)[\"']?\s*[:=]\s*[\"']?[^\"'\s<>,;&]+")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)


def _sensitive(key: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(part in normalized for part in _SENSITIVE)


def redact_url(url: str) -> str:
    parsed = urlsplit(url)
    query = [(key, _REDACTED if _sensitive(key) else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    # Credential-bearing URLs are rejected before a request; never echo them in evidence.
    authority = parsed.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parsed.scheme, authority, parsed.path, urlencode(query), ""))


def _secret_values(value: object) -> list[str]:
    if isinstance(value, dict):
        result = []
        for key, item in value.items():
            if _sensitive(key) and isinstance(item, (str, int, float)):
                result.append(str(item))
            else:
                result.extend(_secret_values(item))
        return result
    if isinstance(value, list):
        return [secret for item in value for secret in _secret_values(item)]
    return []


def secrets_for_request(url: str, headers: dict[str, str], body: str | None) -> tuple[str, ...]:
    values = list(headers.values())
    for name, value in headers.items():
        if name.lower() == "authorization" and " " in value:
            values.append(value.split(" ", 1)[1])
        if name.lower() == "cookie":
            values.extend(pair.partition("=")[2].strip() for pair in value.split(";"))
    values.extend(value for key, value in parse_qsl(urlsplit(url).query) if _sensitive(key))
    if body:
        try:
            values.extend(_secret_values(json.loads(body)))
        except (ValueError, RecursionError):
            values.extend(value for key, value in parse_qsl(body) if _sensitive(key))
    return tuple(sorted({value for value in values if value}, key=len, reverse=True))


def redact_text(text: str, secrets: tuple[str, ...] = ()) -> str:
    for secret in secrets:
        text = text.replace(secret, _REDACTED)
    text = _PRIVATE_KEY.sub(_REDACTED, text)
    text = _JWT.sub(_REDACTED, text)
    text = _BEARER.sub("Bearer " + _REDACTED, text)
    return _ASSIGNMENT.sub(lambda match: match.group(1) + "=" + _REDACTED, text)


def _redact_value(value: object, secrets: tuple[str, ...]) -> object:
    if isinstance(value, dict):
        return {key: _REDACTED if _sensitive(key) else _redact_value(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, secrets) for item in value]
    return redact_text(value, secrets) if isinstance(value, str) else value


def capture_body(body: bytes, content_type: str | None, secrets: tuple[str, ...]) -> object:
    media = (content_type or "").split(";", 1)[0].strip().lower()
    if media != "application/json" and not media.endswith("+json") and not media.startswith("text/"):
        return None  # Do not store binary responses.
    text = body.decode("utf-8", errors="replace")
    if media == "application/json" or media.endswith("+json"):
        try:
            return _redact_value(json.loads(text), secrets)
        except (ValueError, RecursionError):
            pass  # Truncated/malformed JSON is preserved as redacted text, never silently dropped.
    return redact_text(text, secrets)
