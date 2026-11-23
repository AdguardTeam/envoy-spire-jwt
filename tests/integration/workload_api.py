#!/usr/bin/env python3
"""Fake SPIFFE Workload API for the integration test.

Serves spiffe.workload.v1.SPIFFEWorkloadAPI/FetchJWTSVID over a Unix domain
socket, exactly like the SPIRE Agent. Issues an HS256 JWT-SVID with the
audience from the request, the configured SPIFFE ID, and a TTL.

This server is a test double. It is not used by the filter's unit tests and it is
not a substitute for the real-attestation test against a real SPIRE Agent.
"""

import base64
import hashlib
import hmac
import json
import os
import threading
import time
from concurrent import futures
from http.server import BaseHTTPRequestHandler, HTTPServer

import grpc

SOCKET_PATH = os.environ.get("WORKLOAD_API_SOCKET", "/run/spire/agent.sock")
SPIFFE_ID = os.environ.get(
    "EXPECTED_SPIFFE_ID", "spiffe://infra.agrd.dev/environment/dev/service/reporter"
)
SVID_TTL = int(os.environ.get("SVID_TTL", "600"))
ISSUER = os.environ.get("JWT_ISSUER", "https://spire.int.agrd.dev")
SIGNING_KEY = b"integration-test-key"

state = {"calls": 0, "failures": 0}
lock = threading.Lock()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_jwt(audience: str) -> str:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(
        json.dumps(
            {
                "sub": SPIFFE_ID,
                "aud": [audience],
                "exp": now + SVID_TTL,
                "iat": now,
                "iss": ISSUER,
            },
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode()
    signature = b64url(hmac.new(SIGNING_KEY, signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def read_varint(buf: bytes, index: int):
    result = 0
    shift = 0
    while index < len(buf):
        byte = buf[index]
        index += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, index
        shift += 7
    raise ValueError("truncated varint")


def first_audience(message: bytes) -> str:
    index = 0
    while index < len(message):
        tag, index = read_varint(message, index)
        field, wire_type = tag >> 3, tag & 7
        if wire_type == 2:
            length, index = read_varint(message, index)
            value = message[index : index + length]
            index += length
            if field == 1:
                return value.decode()
        elif wire_type == 0:
            _, index = read_varint(message, index)
        else:
            raise ValueError("unsupported wire type")
    raise ValueError("request has no audience")


def encode_varint(value: int) -> bytes:
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def length_delimited(field: int, value: bytes) -> bytes:
    return encode_varint((field << 3) | 2) + encode_varint(len(value)) + value


def fetch_jwt_svid(request: bytes, context) -> bytes:
    with lock:
        state["calls"] += 1
    audience = first_audience(request)
    entry = length_delimited(1, SPIFFE_ID.encode()) + length_delimited(2, make_jwt(audience).encode())
    return length_delimited(1, entry)


handler = grpc.method_handlers_generic_handler(
    "spiffe.workload.v1.SPIFFEWorkloadAPI",
    {
        "FetchJWTSVID": grpc.unary_unary_rpc_method_handler(
            fetch_jwt_svid, request_deserializer=None, response_serializer=None
        )
    },
)


class CountHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        with lock:
            body = json.dumps(state).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # silence
        return


def main() -> None:
    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    os.umask(0)
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=8))
    server.add_generic_rpc_handlers((handler,))
    server.add_insecure_port(f"unix:{SOCKET_PATH}")
    os.chmod(SOCKET_PATH, 0o777)
    server.start()
    threading.Thread(
        target=HTTPServer(("0.0.0.0", 8099), CountHandler).serve_forever, daemon=True
    ).start()
    print(f"fake workload api on unix:{SOCKET_PATH}", flush=True)
    server.wait_for_termination()


if __name__ == "__main__":
    main()
