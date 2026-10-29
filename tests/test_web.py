"""Tests for the demo web interface."""

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from demo.web import Handler


def _serve():
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, 'http://127.0.0.1:%d' % server.server_address[1]


def _post(url, data):
    req = urllib.request.Request(url, json.dumps(data).encode())
    return json.load(urllib.request.urlopen(req))


def test_page_and_scenarios_are_served() -> None:
    server, base = _serve()
    try:
        assert b'AgentGuard' in urllib.request.urlopen(base + '/').read()
        names = [s['name'] for s in json.load(
            urllib.request.urlopen(base + '/api/scenarios'))]
        assert 'poisoned' in names and 'authority' in names
    finally:
        server.shutdown()


def test_poisoned_page_leaks_unprotected_but_not_protected() -> None:
    server, base = _serve()
    try:
        result = _post(base + '/api/run', {'name': 'poisoned'})
        assert result['unprotected']['leaked'] is True
        assert result['protected']['leaked'] is False
        assert result['protected']['blocked'] >= 1
    finally:
        server.shutdown()


def test_custom_page_and_unknown_scenario() -> None:
    server, base = _serve()
    try:
        result = _post(base + '/api/run', {'page': 'Just a normal report.'})
        assert result['protected']['leaked'] is False
        try:
            _post(base + '/api/run', {'name': 'nope'})
            assert False
        except urllib.error.HTTPError as error:
            assert error.code == 400
    finally:
        server.shutdown()


def test_vercel_entry_point_maps_rewritten_paths() -> None:
    from api.index import handler

    server = ThreadingHTTPServer(('127.0.0.1', 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = 'http://127.0.0.1:%d' % server.server_address[1]
    try:
        assert b'AgentGuard' in urllib.request.urlopen(base + '/api/index').read()
        names = json.load(urllib.request.urlopen(
            base + '/api/index?op=scenarios'))
        assert any(s['name'] == 'poisoned' for s in names)
        result = _post(base + '/api/index?op=run', {'name': 'poisoned'})
        assert result['unprotected']['leaked'] is True
        assert result['protected']['leaked'] is False
    finally:
        server.shutdown()
