"""Hostile-origin regression tests for the fail-closed CORS default (REM-MPT-4)."""

import pytest
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from open_webui.utils.cors import (
    CorsConfigError,
    is_wildcard,
    parse_cors_allow_origin,
    socketio_cors_origins,
)

HOSTILE = 'https://evil.example'
GOOD = 'https://webui.ohanasec.io'


def _client(raw, allow_insecure_wildcard=False):
    origins = parse_cors_allow_origin(raw, allow_insecure_wildcard)
    app = FastAPI()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=not is_wildcard(origins),
        allow_methods=['*'],
        allow_headers=['*'],
    )

    @app.get('/api/me')
    def me():
        return {'ok': True}

    return TestClient(app)


def test_default_is_empty_same_origin_only():
    assert parse_cors_allow_origin(None) == []
    assert parse_cors_allow_origin('') == []
    assert parse_cors_allow_origin(' ; ') == []
    assert socketio_cors_origins([]) is None  # never [] (python-socketio: [] disables checks)


def test_wildcard_refused_without_opt_in():
    with pytest.raises(CorsConfigError):
        parse_cors_allow_origin('*')


def test_wildcard_mixed_with_origins_refused():
    with pytest.raises(CorsConfigError):
        parse_cors_allow_origin(f'*;{GOOD}', allow_insecure_wildcard=True)


def test_explicit_allowlist_parsed():
    assert parse_cors_allow_origin(f'{GOOD}; http://localhost:5173') == [GOOD, 'http://localhost:5173']
    assert socketio_cors_origins([GOOD]) == [GOOD]


@pytest.mark.parametrize('raw', ['', GOOD])
def test_hostile_origin_gets_no_cors_grant(raw):
    client = _client(raw)
    r = client.get('/api/me', headers={'Origin': HOSTILE, 'Cookie': 'token=x'})
    assert 'access-control-allow-origin' not in r.headers
    pre = client.options(
        '/api/me',
        headers={'Origin': HOSTILE, 'Access-Control-Request-Method': 'GET'},
    )
    assert 'access-control-allow-origin' not in pre.headers


def test_allowlisted_origin_gets_credentialed_grant():
    client = _client(GOOD)
    r = client.get('/api/me', headers={'Origin': GOOD, 'Cookie': 'token=x'})
    assert r.headers.get('access-control-allow-origin') == GOOD
    assert r.headers.get('access-control-allow-credentials') == 'true'


def test_opted_in_wildcard_never_grants_credentials():
    client = _client('*', allow_insecure_wildcard=True)
    r = client.get('/api/me', headers={'Origin': HOSTILE, 'Cookie': 'token=x'})
    assert r.headers.get('access-control-allow-origin') == '*'
    assert 'access-control-allow-credentials' not in r.headers
    assert socketio_cors_origins(['*']) == '*'
