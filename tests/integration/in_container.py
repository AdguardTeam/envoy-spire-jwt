#!/usr/bin/env python3
"""End-to-end test. The default and CI path runs it inside a Docker build stage:
no Docker daemon and no compose are needed there. A run against a real SPIRE
Agent is the same script executed with `docker run` on the e2e image, with
WORKLOAD_API_EXTERNAL=1 and the Agent socket mounted.

Starts the fake Workload API (unless external), an echo upstream, and the real
Envoy binary in one container, then asserts the documented behaviour.

Exit code 0 means every check passed.
"""

import base64
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

BASE = os.path.dirname(os.path.abspath(__file__))
ENVOY = "/usr/local/bin/envoy"
# A real SPIRE Agent run uses WORKLOAD_API_EXTERNAL=1 and, when the Agent socket
# is not in the default place, WORKLOAD_API_SOCKET=/some/path.sock.
SOCKET = os.environ.get("WORKLOAD_API_SOCKET", "/run/spire/agent.sock")
EXTERNAL_API = os.environ.get("WORKLOAD_API_EXTERNAL") == "1"
EXPECTED_ID = os.environ.get("EXPECTED_SPIFFE_ID",
                             "spiffe://infra.agrd.dev/environment/dev/service/reporter")
AUDIENCE = os.environ.get("AUDIENCE", "reporter-service")
LISTENER = "http://127.0.0.1:8181"
ADMIN = "http://127.0.0.1:9901"
COUNTER = "http://127.0.0.1:8099/count"

failures = []
skipped = []
processes = []


def check(name, ok, detail=""):
    print(("PASS  " if ok else "FAIL  ") + name + ((" :: " + detail) if detail and not ok else ""),
          flush=True)
    if not ok:
        failures.append(name)


def spawn(args):
    process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    processes.append(process)
    return process


def stop(process, sig=signal.SIGTERM):
    if process is None or process.poll() is not None:
        return
    process.send_signal(sig)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=10)


def cleanup():
    for process in reversed(processes):
        stop(process)


def http(url, headers=None, timeout=5):
    request = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()
    except Exception:
        return None, {}, b""


def wait_status(url, expected, timeout=60, headers=None):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        status, _, _ = http(url, headers=headers)
        last = status
        if status == expected:
            return status
        time.sleep(0.5)
    return last


def protected(headers=None):
    merged = {"Host": "protected.test"}
    merged.update(headers or {})
    return http(LISTENER + "/", headers=merged)


def open_route(headers=None):
    merged = {"Host": "open.test"}
    merged.update(headers or {})
    return http(LISTENER + "/", headers=merged)


def rpc_count():
    status, _, body = http(COUNTER)
    if status != 200:
        return None
    return json.loads(body)["calls"]


def envoy_config():
    with open(os.path.join(BASE, "envoy.yaml"), encoding="utf-8") as handle:
        text = handle.read()
    text = text.replace("/run/spire/agent.sock", SOCKET)
    text = text.replace("spiffe://infra.agrd.dev/environment/dev/service/reporter", EXPECTED_ID)
    text = text.replace('"audiences": ["reporter-service"]', f'"audiences": ["{AUDIENCE}"]')
    text = text.replace('"audience": "reporter-service"', f'"audience": "{AUDIENCE}"')
    with open("/tmp/envoy.yaml", "w", encoding="utf-8") as handle:
        handle.write(text)
    return "/tmp/envoy.yaml"


def start_envoy():
    return spawn([ENVOY, "-c", envoy_config(), "-l", "info", "--disable-hot-restart"])


def decode_claims(token):
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def skip(name):
    skipped.append(name)
    print(f"SKIP  {name}", flush=True)


def main():
    os.makedirs(os.path.dirname(SOCKET), exist_ok=True)
    if not EXTERNAL_API and os.path.exists(SOCKET):
        os.unlink(SOCKET)

    spawn([sys.executable, os.path.join(BASE, "echo.py")])
    check("echo upstream starts", wait_status("http://127.0.0.1:8080/", 200, timeout=30) == 200)

    envoy = start_envoy()
    check("envoy starts", wait_status(ADMIN + "/ready", 200) == 200)

    if EXTERNAL_API:
        skip("fail-closed startup and recovery checks: the Agent is reachable at startup")
    else:
        print("== scenario 1: no Workload API at startup", flush=True)
        status, _, _ = protected()
        check("protected request is rejected without credentials", status == 503, str(status))

        status, headers, _ = protected({"content-type": "application/grpc"})
        check("gRPC client receives a trailers-only 200 with grpc-status 14",
              status == 200 and headers.get("grpc-status") == "14",
              f"status={status} grpc-status={headers.get('grpc-status')}")

        status, _, _ = open_route()
        check("unprotected route works during the outage", status == 200, str(status))

        print("== scenario 2: Workload API becomes available", flush=True)
        spawn([sys.executable, os.path.join(BASE, "workload_api.py")])
        check("fake Workload API starts", wait_status(COUNTER, 200, timeout=60) == 200)
        status = wait_status(LISTENER + "/", 200, timeout=60, headers={"Host": "protected.test"})
        check("protected route recovers after the Workload API appears", status == 200, str(status))
    if EXTERNAL_API:
        print("== scenario 2: protected route with the Agent already available", flush=True)
        status = wait_status(LISTENER + "/", 200, timeout=60, headers={"Host": "protected.test"})
        check("protected route serves with the Agent available", status == 200, str(status))

    status, _, body = protected({"x-machine-token": "forged-value",
                                 "Authorization": "Bearer application-owned"})
    problems = []
    if status != 200:
        problems.append(f"status={status}")
    payload = {}
    try:
        payload = json.loads(body)
    except Exception:
        problems.append("body is not JSON")
    headers = payload.get("headers", {})
    tokens = headers.get("x-machine-token", [])
    claims = {}
    if len(tokens) != 1:
        problems.append(f"x-machine-token={tokens}")
    else:
        token = tokens[0]
        if token == "forged-value":
            problems.append("caller token was not overwritten")
        try:
            claims = decode_claims(token)
        except Exception:
            problems.append("token is not a JWS compact serialization")
        if claims.get("sub") != EXPECTED_ID:
            problems.append(f"sub={claims.get('sub')!r}")
        if AUDIENCE not in (claims.get("aud") or []):
            problems.append(f"aud={claims.get('aud')!r}")
        if not claims.get("exp"):
            problems.append("token has no exp")
    if headers.get("authorization") != ["Bearer application-owned"]:
        problems.append(f"authorization={headers.get('authorization')!r}")
    check("exactly one valid JWT-SVID, audience and identity correct", not problems,
          "; ".join(problems))
    check("caller token overwritten, Authorization untouched", not problems, "; ".join(problems))

    status, _, body = open_route({"x-machine-token": "application-value"})
    try:
        open_headers = json.loads(body).get("headers", {})
    except Exception:
        open_headers = {}
    check("unprotected route receives no injected credential",
          open_headers.get("x-machine-token") == ["application-value"], str(open_headers))

    status, _, _ = http(LISTENER + "/", headers={"Host": "bad-audience.test"})
    check("route with an audience outside the allowlist is rejected", status == 503, str(status))

    if EXTERNAL_API:
        skip("single-flight and cache-hit RPC counts: they need the fake API counter")
    else:
        print("== scenario 3: one RPC for a burst of concurrent requests", flush=True)
        stop(envoy)
        envoy = start_envoy()
        check("envoy restarted with an empty cache", wait_status(ADMIN + "/ready", 200) == 200)
        before = rpc_count()
        threads = [threading.Thread(target=protected) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        time.sleep(1)
        after = rpc_count()
        check("20 concurrent requests with an empty cache cause one RPC",
              before is not None and after is not None and after - before == 1,
              f"{before} -> {after}")

        status, _, _ = protected()
        check("cache hit serves subsequent requests", status == 200, str(status))
        stable = rpc_count()
        check("a cache hit causes no RPC", after is not None and stable == after,
              f"{after} -> {stable}")

    print(flush=True)
    if failures:
        print(f"{len(failures)} checks failed", flush=True)
        return 1
    if skipped:
        print(f"ALL INTEGRATION CHECKS PASSED ({len(skipped)} skipped: {'; '.join(skipped)})",
              flush=True)
    else:
        print("ALL INTEGRATION CHECKS PASSED", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        cleanup()
