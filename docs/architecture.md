# Architecture and security

## Shape

```text
application
    |  (loopback HTTP)
    v
Envoy worker thread
    |-- dynamic module HTTP filter (libspire_jwt.so)
    |       |-- cache read under one shared lock
    |       `-- on a miss: pause the stream, post a fetch request
    |
    |   main thread
    |       `-- one FetchJWTSVID call per (audience) at a time
    |             over the cluster `spire_agent_workload_api`
    |                       |  Unix socket, HTTP/2
    |                       v
    |                 SPIRE Agent (Workload API)
    `-- X-Machine-Token: <JWT-SVID>
```

The extension is a dynamic module: a shared library loaded by the pinned Envoy
binary. It implements the HTTP filter ABI of Envoy 1.40.2 (`v0.2.0`), which
provides per-route configuration, asynchronous HTTP callouts, per-filter and
per-config schedulers, statistics, logging, and local replies.

## Threading model

| Work | Thread | Blocking |
|---|---|---|
| Cache lookup, header write, pause/resume | Envoy worker | none |
| Fetch decision, single flight, backoff | main thread, through the config scheduler | none |
| `FetchJWTSVID` RPC | Envoy async client on the main thread | none |
| Completion, validation, cache publish | main thread | none |

A request that needs a credential returns `HeadersStatus::Stop` and is resumed
from the filter's own scheduler, so the worker runs other streams in the
meantime. No request ever calls SPIRE synchronously. There is no thread, thread
pool, or timer created by the module.

The cache is process-wide and shared by all workers: reads take a shared lock,
writes happen only on the main thread. This is the "shared immutable snapshot"
option: one token per audience for the whole process, no duplicated fetches from
four workers, and a hot path that is a map lookup plus a header set.

## State machine

| State | Decision |
|---|---|
| Fresh (remaining > `refreshMarginSeconds`) | inject |
| Stale (`minRemainingSeconds` < remaining <= margin) | inject, start one background refresh |
| Missing (absent, or remaining <= `minRemainingSeconds`) | wait for one fetch, or fail closed |

Fail-closed sources:

- no credential and the fetch fails;
- the fetch is inside the backoff window (waiters are woken and rejected at once
  instead of waiting for a fetch that will not start);
- more than `maxPendingRequests` waiters;
- the route audience is not in the allowlist;
- the response identity, subject, audience, or expiry does not match the
  configuration.

## Security boundaries

1. **Which routes may carry a credential** is decided by Envoy routing, not by any
   request header. A route receives a credential only when its
   `typed_per_filter_config` sets `enabled: true`. `Host` cannot enable injection:
   the route was already selected before the filter runs, and the filter reads the
   selected route.
2. **Which audience** is fixed by trusted configuration. The route names one
   audience and it must appear in `audiences`; otherwise the request is rejected
   with 503 instead of being forwarded without a token.
3. **Which identity** is fixed by `expectedSpiffeId`. The Workload API is asked for
   that identity, and the response is rejected when the returned `spiffe_id`, the
   JWT `sub`, or the JWT `aud` disagree. Selecting an identity in the request is
   not authentication: the SPIRE Agent attests the workload independently and
   decides what to issue. A Pod that fails attestation receives an error or a
   different identity, both of which the filter rejects.
4. **Header integrity**: the filter removes every caller `X-Machine-Token` on a
   protected route and sets exactly one value. `Authorization` is never read or
   written.
5. **No leakage to other destinations**: credentials are added on the request
   path, after routing. An internal redirect or a retry to another cluster keeps
   the route's decision; a route that does not enable injection never receives a
   token. The Workload API cluster must not be reachable by any route.
6. **No token in observability**: tokens are never logged, never turned into
   statistics, and never put in metadata. Logs carry the audience and the reason
   for a failure only. `token_seconds_remaining` is a single gauge, not a label.

## Failure handling

| Failure | Behaviour |
|---|---|
| SPIRE Agent absent at startup | Envoy starts, protected routes reject with 503, unrelated routes work |
| Agent restarts or the socket drops | the callout resets, the fetch counts as a failure, backoff applies, cached tokens keep serving until they expire |
| Fetch timeout | the callout timeout resets the stream; treated as a failure |
| Malformed or oversized response | rejected by the decoder; failure |
| Multiple eligible SVIDs | rejected as ambiguous; failure |
| Token with wrong identity, subject, audience, or short life | rejected; failure |
| Client disconnects while waiting | `onDestroy` cancels the waiter; the shared fetch continues for others |
| Config reload | not exercised: no xDS or in-process reload reaches the module today; see `assessment.md` risk 3 |
| Hot restart | new process, empty cache, first request triggers a fetch |

Retries are bounded: exponential backoff from `retryInitialBackoffMs` to
`retryMaxBackoffMs` with +-25 % jitter, and only one attempt per key at a time.
`maxPendingRequests` bounds memory; the wait list, the in-flight map, and the
backoff table are all bounded by the configured audience set (at most 8).

## Transport

`FetchJWTSVID` is a unary gRPC method. The module uses the ABI streaming callout,
which is Envoy's async HTTP client bound to a cluster. Envoy owns the Unix socket
connection, HTTP/2 framing, flow control, timeouts, and resets. The module adds
the mandatory gRPC length prefix and encodes two small messages. This is the only
async gRPC path a dynamic module can use: the ABI exposes 781 callbacks and none
of them is a gRPC client.

## Alternatives considered

| Option | Why it was not chosen |
|---|---|
| SPIRE Agent SDS for JWT-SVIDs | SDS serves X.509 only. `spiffe/spire#5931` asked for JWT support and was closed without code, redirecting the work to Envoy |
| Envoy `credential_injector` + `injected_credentials.generic` | The value can only come from SDS or a static secret, there is no audience field, and there is no per-route config. Marked "no production burn time" upstream |
| `ext_authz` gRPC bridge to the Workload API | Needs a helper process (github/emissary, archived, v2 config) and contradicts the one-process requirement |
| `ext_proc` | Requires an external processor by design |
| Custom Envoy build with the filter compiled in | It would remove the codec layer and add timers, but costs a Bazel Envoy build per release. The ABI is frozen and forward compatible, so the module is the smaller maintenance burden |
| Own gRPC runtime in the module | Adds a second gRPC stack, threads, and binary size for no benefit |

## Measurements

Method: `docker build --target measure`
(`tests/integration/measure_in_container.py`). Everything runs inside one
build container with the default Envoy concurrency (4 workers): a threaded Python
`http.client` keep-alive client, an echo upstream, one Envoy with the filter, and
one Envoy without it (`envoy-nofilter.yaml` on ports 8182/9902). Both are measured
with the same client and the same `Host`.

| Metric | With filter | Baseline |
|---|---|---|
| p50 / p95 / p99, 1 client, 3,000 requests | 163-166 / 226-245 / 385-398 µs | 162-174 / 218-303 / 517-672 µs |
| p50 / p95 / p99, 8 clients, 20,000 requests | 540-563 / 1,511-1,587 / 2,165-2,407 µs | 539-548 / 1,542-1,596 / 2,237-2,385 µs |
| Idle RSS after 10 s | 66,808-66,860 kB | 65,068-65,116 kB |
| Module size | 2,699,064 bytes | - |
| RPCs during 20,000 cached requests | 0 | - |
| RPCs for 20 concurrent requests, empty cache (measured by the `e2e` stage) | 1 | - |

Caveats, stated plainly:

- These are container numbers (4 vCPU), not production hardware. Absolute latency
  includes the client and the echo upstream.
- Two samples per row show that the difference between filtered and baseline is
  inside run-to-run noise at every percentile, including p99. This harness cannot
  resolve the filter's overhead.
- The 100 µs p99 target is therefore neither confirmed nor refuted. A controlled
  bare-metal run is needed before the claim is repeated or dropped.
- RSS includes about 2.5 MB of file-backed `.so` pages shared between processes.

## Deployment notes

The module is configuration-only: nothing in Envoy changes except the pieces below,
and the same steps apply to any static or xDS-generated configuration.

1. Put `libspire_jwt.so` where `ENVOY_DYNAMIC_MODULES_SEARCH_PATH` looks.
2. Add the `spire_agent_workload_api` cluster (pipe to the Agent socket, HTTP/2).
3. Add the `envoy.filters.http.dynamic_modules/spire_jwt` entry to `http_filters`
   with `metrics_namespace: spire_jwt` and the filter config JSON.
4. Add a per-route block with `enabled: true` and the receiver audience, only on
   routes that must carry a machine credential.
5. Mount the Agent socket into the Envoy process, read-only.

Rules that must hold in every deployment:

- No route may reach `spire_agent_workload_api`. It is a credential source, not an
  upstream.
- A route gets a credential only through its own per-route config. Host headers,
  redirects, and retries must not decide that.
- Do not enable two machine-token mechanisms on one route. Remove any other token
  stub in the same change.
