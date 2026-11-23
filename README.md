# envoy-spire-jwt

An Envoy HTTP filter that obtains JWT-SVIDs from a local SPIRE Agent and injects
them as `X-Machine-Token` on explicitly protected outbound routes.

- One process, no credential-helper sidecar, no ext_proc, no per-request RPC.
- A dynamic module (`.so`), so no Envoy fork and no custom Envoy build.
- Zero runtime dependencies beyond the Envoy ABI. About 2.7 MB on disk.
- Async everywhere: no worker thread ever waits on SPIRE.

```text
application
    |  HTTP
    v
Envoy worker
    |-- filter (libspire_jwt.so)
    |      |-- cache read, header write              (worker thread, no lock contention)
    |      `-- on a miss: pause the stream, ask the main thread for one fetch
    |
    |  main thread
    |      `-- one FetchJWTSVID per audience at a time
    |            over a cluster with a Unix socket, HTTP/2
    |                       v
    |                 SPIRE Agent (Workload API)
    `-- X-Machine-Token: <JWT-SVID>
```

## Compatibility

| Item | Value |
|---|---|
| Envoy dynamic modules ABI | `v0.2.0`, first released in Envoy 1.40.0 |
| Built and tested against | Envoy 1.40.2 |
| Architectures | `linux/amd64`, `linux/arm64` |
| libc | glibc 2.35 or newer (the module is built on bookworm and loads in the Ubuntu 22.04 Envoy image) |

A module built for ABI `v0.2.0` keeps working with later Envoy releases: the
released ABI is frozen and grows by addition only.

## Install

Download the asset for your architecture and verify it:

```sh
version=v0.1.0
arch=amd64   # or arm64

curl -fsSLO "https://github.com/AdguardTeam/envoy-spire-jwt/releases/download/${version}/libspire_jwt-linux-${arch}.so"
curl -fsSLO "https://github.com/AdguardTeam/envoy-spire-jwt/releases/download/${version}/libspire_jwt-linux-${arch}.so.sha256"
sha256sum -c "libspire_jwt-linux-${arch}.so.sha256"

install -D -m 0755 "libspire_jwt-linux-${arch}.so" /usr/local/lib/envoy-spire-jwt/libspire_jwt.so
```

Envoy finds the module through `ENVOY_DYNAMIC_MODULES_SEARCH_PATH`. Set it to
`/usr/local/lib/envoy-spire-jwt`, or place the file in the working directory.

Mount the SPIRE Agent socket into the Envoy container. The common path is
`/run/spire/agent-sockets/spire-agent.sock`.

## Configure

The filter reads the proto3 JSON encoding of
`agrd.envoy.filters.http.spire_jwt.v1.FilterConfig` from a
`google.protobuf.StringValue`. Envoy cannot resolve a custom `Any` type URL, so
`typed_config` must not be the custom type directly.

```yaml
- name: envoy.filters.http.dynamic_modules/spire_jwt
  typed_config:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilter
    filter_name: spire_jwt
    dynamic_module_config:
      name: spire_jwt
      metrics_namespace: spire_jwt
    filter_config:
      "@type": type.googleapis.com/google.protobuf.StringValue
      value: |
        {
          "workloadApiCluster": "spire_agent_workload_api",
          "expectedSpiffeId": "spiffe://example.org/environment/dev/service/reporter",
          "audiences": ["reporter-service"]
        }
```

`workloadApiCluster` names a static cluster that reaches the Workload API. A
dynamic module cannot open sockets, so the socket path lives in the cluster:

```yaml
- name: spire_agent_workload_api
  type: STATIC
  connect_timeout: 0.5s
  load_assignment:
    cluster_name: spire_agent_workload_api
    endpoints:
    - lb_endpoints:
      - endpoint:
          address:
            pipe: { path: /run/spire/agent-sockets/spire-agent.sock }
  typed_extension_protocol_options:
    envoy.extensions.upstreams.http.v3.HttpProtocolOptions:
      "@type": type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions
      explicit_http_config:
        http2_protocol_options: {}
```

Injection is off unless a route enables it:

```yaml
typed_per_filter_config:
  envoy.filters.http.dynamic_modules/spire_jwt:
    "@type": type.googleapis.com/envoy.extensions.filters.http.dynamic_modules.v3.DynamicModuleFilterPerRoute
    filter_name: spire_jwt
    dynamic_module_config: { name: spire_jwt }
    filter_config:
      "@type": type.googleapis.com/google.protobuf.StringValue
      value: |
        {"enabled": true, "audience": "reporter-service"}
```

The route key must match the filter chain name exactly, including the
`envoy.filters.http.dynamic_modules/` prefix.

| Field | Meaning | Default |
|---|---|---|
| `workloadApiCluster` | Cluster that reaches the Workload API over a Unix socket and HTTP/2 | required |
| `expectedSpiffeId` | The only identity this filter accepts | required |
| `audiences` | Allowlist a route audience must appear in | required |
| `refreshMarginSeconds` | Refresh in the background when this much life is left | 60 |
| `minRemainingSeconds` | Never inject a credential with less life than this | 30 |
| `maxTokenLifetimeSeconds` | Reject longer-lived credentials, 0 disables | 0 |
| `fetchTimeoutMs` | One `FetchJWTSVID` RPC budget | 500 |
| `retryInitialBackoffMs`, `retryMaxBackoffMs` | Bounded retry backoff with jitter | 200, 5000 |
| `maxPendingRequests` | Requests that may wait for one fetch | 128 |

Both `snake_case` and `camelCase` keys are accepted. Unknown keys are rejected, so
a typo cannot silently disable injection.

## Behaviour

| Cache state | Result |
|---|---|
| Fresh | Inject the cached token. No RPC |
| Stale | Inject the cached token and start one background refresh |
| Missing | Pause the request, start one fetch, resume or fail closed |
| Over `maxPendingRequests` | Reject immediately |
| Fetch failed, still in backoff | Reject immediately; no request waits for a fetch that will not happen |

- Exactly one `X-Machine-Token` reaches the upstream. Any caller value is removed.
  `Authorization` is never read or written.
- Unprotected routes pass through unchanged, including a caller-supplied
  `X-Machine-Token`.
- HTTP clients receive `503`. gRPC clients receive HTTP 200 with
  `grpc-status: 14` in a trailers-only response.
- A token is never injected with less than `minRemainingSeconds` of life. A fetch
  that returns an unusable token counts as a failure, so retries stay bounded.
- A fetch that finds a fresh credential in the cache does not start, so a queued
  request cannot cause a second RPC after the first one succeeded.

### Identity checks

The filter asks the Agent for `expectedSpiffeId`, then rejects the response unless
all of these hold: the returned `spiffe_id` equals the configured one, the JWT
`sub` equals it, the JWT carries the route audience, the token outlives
`minRemainingSeconds`, and its lifetime is within `maxTokenLifetimeSeconds` when
that is set. Signature verification is intentionally absent: SPIRE signed the
token and it arrived over a local Unix socket. See `docs/architecture.md`.

## Statistics

Set `metrics_namespace: spire_jwt` to publish these names:

`cache_hit`, `cache_miss`, `fetch_success`, `fetch_failure`, `refresh_success`,
`refresh_failure`, `requests_rejected`, `requests_waiting`,
`token_seconds_remaining`, `fetch_latency_ms`.

A refresh is a fetch started while a usable credential was cached. Tokens never
appear in statistics, logs, or metadata.

## Build and test

Only Docker is required. There is no apt, no PPA, and no package manager in any
stage.

```sh
# Unit tests (491 checks, ASan and UBSan)
docker build --target test .

# End-to-end: a real Envoy process, the module, a Workload API on a Unix socket,
# and an echo upstream in one container
docker build --target e2e .

# Release artifact: the .so plus the test results, and nothing else
docker build --target artifact --output type=local,dest=dist .

# Measurements (latency, RPC rate, idle RSS, module size)
docker build --target measure .
```

The `artifact` target copies the unit and end-to-end results, so an artifact
exists only when both passed.

The e2e suite covers: Envoy starting without the Workload API; protected routes
rejecting with 503 and gRPC `grpc-status: 14`; unprotected routes continuing to
work; recovery when the Workload API appears; exactly one injected token with the
right `sub` and `aud`; overwriting a caller token; an untouched `Authorization`
header; rejection of an audience outside the allowlist; and one Workload API RPC
for a burst of 20 concurrent requests on an empty cache.

To run the same fixtures against a real SPIRE Agent, outside a build:

```sh
docker build --target e2e -t envoy-spire-jwt:e2e .
docker run --rm --entrypoint python3 \
  -v /run/spire/agent-sockets:/run/spire/agent-sockets:ro \
  -e WORKLOAD_API_EXTERNAL=1 \
  -e WORKLOAD_API_SOCKET=/run/spire/agent-sockets/spire-agent.sock \
  -e EXPECTED_SPIFFE_ID=spiffe://example.org/environment/dev/service/reporter \
  -e AUDIENCE=reporter-service \
  envoy-spire-jwt:e2e /e2e/in_container.py
```

The Agent must be attested for that workload and must hold a registration entry
that issues exactly `EXPECTED_SPIFFE_ID` with `AUDIENCE`. The fail-closed startup
and recovery checks and the RPC-count checks are skipped in this mode; the summary
line lists what was skipped.

## Measured results

Two samples, 4 vCPU, 4 Envoy workers, Python keep-alive client, echo upstream in
the same container. The baseline is the same Envoy binary with the filter removed.

| Metric | With filter | Baseline |
|---|---|---|
| p50 / p95 / p99, 1 client | 163-166 / 226-245 / 385-398 us | 162-174 / 218-303 / 517-672 us |
| p50 / p95 / p99, 8 clients | 540-563 / 1,511-1,587 / 2,165-2,407 us | 539-548 / 1,542-1,596 / 2,237-2,385 us |
| Idle RSS after 10 s | 66,808-66,860 kB | 65,068-65,116 kB |
| Module size | 2,699,064 bytes | - |
| Workload API RPCs per 20,000 requests | 0 | - |
| RPCs for 20 concurrent requests, empty cache | 1 | - |

The difference between the columns is inside run-to-run noise at every percentile,
so this harness cannot resolve the filter's overhead. Absolute values include the
client and the echo upstream. Method and caveats: `docs/architecture.md`.

## Limitations

- **No timers.** The dynamic modules ABI has no timer for HTTP filters, so refresh
  is traffic-driven: the first request after the refresh margin starts one
  refresh. A Pod with no traffic performs no Workload API calls and fetches on its
  next request.
- **No signature verification.** See "Identity checks". The trust anchor is the
  Agent socket and the cluster that reaches it; do not expose that cluster to a
  route.
- **In-process trust.** A dynamic module runs with Envoy's privileges. Treat the
  `.so` and the image as trusted artifacts.

## License

Apache License 2.0. See `LICENSE`.

This is not an official SPIFFE, SPIRE, or Envoy project. SPIFFE and SPIRE are
projects of the Cloud Native Computing Foundation; Envoy is a project of the
Linux Foundation. The names are used only to describe what this filter talks to.
