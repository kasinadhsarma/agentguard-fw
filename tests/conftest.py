"""Shared fixtures: a throwaway real Redis server for the scale tests."""

from __future__ import annotations

import shutil
import socket
import subprocess
import time

import pytest


def _free_port() -> int:
    """Ask the OS for an unused TCP port."""
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


@pytest.fixture(scope='session')
def redis_url():
    """Start redis-server on a free port; skip when it is not installed."""
    pytest.importorskip('redis')
    binary = shutil.which('redis-server')
    if binary is None:
        pytest.skip('redis-server is not installed')

    import redis

    port = _free_port()
    process = subprocess.Popen(
        [binary, '--port', str(port), '--save', '', '--appendonly', 'no',
         '--bind', '127.0.0.1'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    url = 'redis://127.0.0.1:' + str(port) + '/0'
    client = redis.Redis.from_url(url)
    for _ in range(50):
        try:
            client.ping()
            break
        except redis.RedisError:
            time.sleep(0.1)
    else:
        process.kill()
        pytest.skip('redis-server did not start')

    yield url
    process.terminate()
    process.wait(timeout=5)


@pytest.fixture()
def redis_client(redis_url):
    """A clean Redis database for one test."""
    import redis

    client = redis.Redis.from_url(redis_url, decode_responses=True)
    client.flushall()
    return client
