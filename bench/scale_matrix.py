"""Run the load test against several server setups and save the results.

Starts its own redis-server and uvicorn processes (Linux, redis-server on
PATH), so nothing needs to be running beforehand:

    python3 -m bench.scale_matrix --agents 1500 --out bench/load_results.json

Setups:
  memory-1w   one worker, sessions in memory         (the default setup)
  memory-2w   two workers, sessions in memory        (WRONG on purpose: it
                                                      shows why Redis is needed)
  redis-1w    one worker, sessions in Redis
  redis-2w    two workers sharing sessions in Redis
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time

import httpx

from bench.load_test import run


def free_port() -> int:
    """Ask the OS for an unused TCP port."""
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(url: str) -> None:
    """Block until the server answers /health."""
    for _ in range(100):
        try:
            if httpx.get(url + '/health', timeout=1).status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(0.2)
    raise RuntimeError('server did not start: ' + url)


def main() -> None:
    """Run every setup and write one JSON report."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    parser.add_argument('--agents', type=int, default=1500)
    parser.add_argument('--concurrency', type=int, default=64)
    parser.add_argument('--out', default='bench/load_results.json')
    args = parser.parse_args()

    redis_bin = shutil.which('redis-server')
    if redis_bin is None:
        sys.exit('redis-server is required on PATH')
    redis_port = free_port()
    redis = subprocess.Popen(
        [redis_bin, '--port', str(redis_port), '--save', '',
         '--appendonly', 'no'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    redis_url = 'redis://127.0.0.1:' + str(redis_port) + '/0'

    setups = [
        ('memory-1w', 1, False),
        ('memory-2w', 2, False),
        ('redis-1w', 1, True),
        ('redis-2w', 2, True),
    ]
    results = {}
    try:
        for name, workers, shared in setups:
            port = free_port()
            env = {k: v for k, v in os.environ.items()
                   if k not in ('MODEL_API_KEY', 'AGENTGUARD_REDIS_URL')}
            if shared:
                env['AGENTGUARD_REDIS_URL'] = redis_url
            server = subprocess.Popen(
                [sys.executable, '-m', 'uvicorn', 'agentguard.proxy:app',
                 '--port', str(port), '--workers', str(workers),
                 '--timeout-keep-alive', '30', '--log-level', 'warning'],
                env=env,
            )
            url = 'http://127.0.0.1:' + str(port)
            try:
                wait_for(url)
                run_args = argparse.Namespace(
                    url=url, api_key='', agents=args.agents,
                    concurrency=args.concurrency, server_pid=server.pid,
                )
                print('running', name, flush=True)
                results[name] = asyncio.run(run(run_args))
                results[name]['workers'] = workers
            finally:
                server.terminate()
                server.wait(timeout=10)
    finally:
        redis.terminate()

    report = {
        'machine': {
            'cpus': os.cpu_count(),
            'python': platform.python_version(),
            'note': 'load generator and server share these CPUs',
        },
        'results': results,
    }
    with open(args.out, 'w', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)

    print('\n%-10s %-8s %-14s %-12s %s' % (
        'setup', 'workers', 'cpu ms/req', 'attacks ok', 'errors'))
    for name, result in results.items():
        cpu = result['server_cpu']['cpu_ms_per_request']
        correct = result['correctness']
        print('%-10s %-8s %-14s %-12s %s' % (
            name, result['workers'], cpu,
            str(correct['attacks_blocked']) + '/' + str(args.agents),
            result['errors'] or '-',
        ))


if __name__ == '__main__':
    main()
