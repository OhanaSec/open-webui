"""CORS origin parsing (fail-closed).

Open WebUI serves the SvelteKit frontend and the API from the same origin, so a
production deployment needs no cross-origin allowlist at all. The default is
therefore an EMPTY allowlist (same-origin only). A wildcard is rejected unless
explicitly opted into, because the API's CORSMiddleware runs with
``allow_credentials=True`` -- with ``'*'`` Starlette reflects any request
Origin together with ``Access-Control-Allow-Credentials: true``, letting any
site make authenticated cross-origin requests with the user's cookies.
"""

from __future__ import annotations

WILDCARD = '*'


class CorsConfigError(ValueError):
    pass


def parse_cors_allow_origin(raw: str | None, allow_insecure_wildcard: bool = False) -> list[str]:
    """Parse a ``;``-separated CORS_ALLOW_ORIGIN value.

    - unset / blank -> ``[]`` (same-origin only)
    - ``'*'`` -> ``['*']`` only when ``allow_insecure_wildcard`` is true, else CorsConfigError
    - ``'*'`` mixed with explicit origins -> CorsConfigError (browsers reject it anyway)
    """
    origins = [o.strip() for o in (raw or '').split(';') if o.strip()]
    if WILDCARD in origins:
        if len(origins) > 1:
            raise CorsConfigError("CORS_ALLOW_ORIGIN cannot mix '*' with explicit origins.")
        if not allow_insecure_wildcard:
            raise CorsConfigError(
                "CORS_ALLOW_ORIGIN='*' is refused: set an explicit ';'-separated origin allowlist "
                '(or leave it empty for same-origin only). To accept the wildcard anyway, also set '
                'CORS_ALLOW_INSECURE_WILDCARD=true (credentials are then disabled for CORS requests).'
            )
    return origins


def is_wildcard(origins: list[str]) -> bool:
    return origins == [WILDCARD]


def socketio_cors_origins(origins: list[str]):
    """Map the HTTP allowlist to python-socketio's ``cors_allowed_origins``.

    python-socketio treats ``[]`` as "disable CORS checks" (allow every origin),
    so an empty allowlist must map to ``None`` (same-origin only), never ``[]``.
    """
    if is_wildcard(origins):
        return WILDCARD
    return list(origins) if origins else None
