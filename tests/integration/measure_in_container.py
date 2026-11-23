#!/usr/bin/env python3
"""Measurement run for a Docker build stage.

Starts the fake Workload API, an echo upstream, one Envoy with the filter and one
stock Envoy with the same configuration minus the filter, then prints latency,
Workload API RPC counts, idle RSS, and module size. No Docker daemon needed.
"""

import http.client as httpclient
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
ENVOY = "/usr/local/bin/envoy"
MODULE = "/usr/local/lib/envoy-spire-jwt/libspire_jwt.so"
SOCKET = "/run/spire/agent.sock"
COUNTER = "http://127.0.0.1:8099/count"

processes = []


def spawn(args, log_path=None):
    output = open(log_path, "w", encoding="utf-8") if log_path else subprocess.DEVNULL
    process = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT)
    processes.append(process)
    return process


def dump_log(path):
    try:
        with open(path, encoding="utf-8") as handle:
            print(handle.read()[-3000:], flush=True)
    except OSError:
        pass


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)


def http(url, headers=None, timeout=5):
    try:
        request = urllib.request.Request(url, headers=headers or {})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        return error.code, error.read()
    except Exception:
        return None, b""


def wait_status(url, expected, timeout=60, headers=None):
    deadline = time.time() + timeout
    while time.time() < deadline:
        status, _ = http(url, headers=headers)
        if status == expected:
            return True
        time.sleep(0.5)
    return False


def rpc_count():
    status, body = http(COUNTER)
    return json.loads(body)["calls"] if status == 200 else None


def load(port, host, requests, concurrency):
    latencies = [0.0] * requests
    cursor = [0]
    errors = [0]
    lock = threading.Lock()

    def worker():
        connection = httpclient.HTTPConnection("127.0.0.1", port, timeout=10)
        while True:
            with lock:
                index = cursor[0]
                if index >= requests:
                    return
                cursor[0] += 1
            started = time.perf_counter()
            try:
                connection.request("GET", "/", headers={"Host": host})
                response = connection.getresponse()
                response.read()
                if response.status != 200:
                    raise RuntimeError(response.status)
                latencies[index] = (time.perf_counter() - started) * 1e6
            except Exception:
                errors[0] += 1
                connection.close()
                connection = httpclient.HTTPConnection("127.0.0.1", port, timeout=10)

    threads = [threading.Thread(target=worker) for _ in range(concurrency)]
    started = time.perf_counter()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    elapsed = time.perf_counter() - started

    valid = sorted(value for value in latencies if value > 0)
    if not valid or errors[0] != 0:
        print(f"  {errors[0]} of {requests} requests failed", flush=True)
        return False
    percentile = lambda q: valid[min(len(valid) - 1, int(len(valid) * q))]
    print(f"  requests={requests} concurrency={concurrency} errors={errors[0]} "
          f"rps={requests / elapsed:.0f} p50={percentile(0.50):.0f}us "
          f"p95={percentile(0.95):.0f}us p99={percentile(0.99):.0f}us", flush=True)
    return True


def rss_kb(pid):
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8") as handle:
            match = re.search(r"VmRSS:\s+(\d+) kB", handle.read())
        return int(match.group(1)) if match else None
    except OSError:
        return None


def config_with_ports(source, target, listener_port, admin_port):
    with open(source, encoding="utf-8") as handle:
        text = handle.read()
    text = text.replace("port_value: 8181", f"port_value: {listener_port}")
    text = text.replace("port_value: 9901", f"port_value: {admin_port}")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(text)


def main():
    if os.path.exists(SOCKET):
        os.unlink(SOCKET)

    spawn([sys.executable, os.path.join(BASE, "echo.py")], "/tmp/echo.log")
    if not wait_status("http://127.0.0.1:8080/", 200, timeout=30):
        print("echo upstream did not start", flush=True)
        dump_log("/tmp/echo.log")
        return 1
    spawn([sys.executable, os.path.join(BASE, "workload_api.py")], "/tmp/workload.log")
    if not wait_status(COUNTER, 200, timeout=60):
        print("fake Workload API did not start", flush=True)
        dump_log("/tmp/workload.log")
        return 1

    with_filter = spawn([ENVOY, "-c", os.path.join(BASE, "envoy.yaml"), "-l", "warn",
                         "--disable-hot-restart"], "/tmp/filtered.log")
    if not wait_status("http://127.0.0.1:9901/ready", 200):
        print("envoy with the filter did not start", flush=True)
        dump_log("/tmp/filtered.log")
        return 1
    wait_status("http://127.0.0.1:8181/", 200, headers={"Host": "protected.test"})

    config_with_ports(os.path.join(BASE, "envoy-nofilter.yaml"), "/tmp/nofilter.yaml", 8182, 9902)
    without_filter = spawn([ENVOY, "-c", "/tmp/nofilter.yaml", "-l", "warn", "--disable-hot-restart"],
                           "/tmp/nofilter.log")
    if not wait_status("http://127.0.0.1:9902/ready", 200):
        print("baseline envoy did not start", flush=True)
        dump_log("/tmp/nofilter.log")
        return 1
    wait_status("http://127.0.0.1:8182/", 200, headers={"Host": "protected.test"})

    ok = True
    print("\n== latency, 1 client, with filter", flush=True)
    ok = load(8181, "protected.test", 3000, 1) and ok
    print("== latency, 1 client, no filter", flush=True)
    ok = load(8182, "protected.test", 3000, 1) and ok
    print("\n== latency, 8 clients, with filter", flush=True)
    before = rpc_count()
    ok = load(8181, "protected.test", 20000, 8) and ok
    after = rpc_count()
    print(f"  Workload API RPCs during 20000 requests: {after - before}", flush=True)
    print("== latency, 8 clients, no filter", flush=True)
    ok = load(8182, "protected.test", 20000, 8) and ok

    print("\n== storage and memory", flush=True)
    print(f"  module size: {os.path.getsize(MODULE)} bytes", flush=True)
    time.sleep(10)
    print(f"  idle RSS with filter:    {rss_kb(with_filter.pid)} kB", flush=True)
    print(f"  idle RSS without filter: {rss_kb(without_filter.pid)} kB", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        for process in reversed(processes):
            stop(process)
