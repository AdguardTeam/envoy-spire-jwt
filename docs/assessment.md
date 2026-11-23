# Engineering assessment

Written after the simplification pass and the end-to-end run. Numbers come from
the `measure` build stage and from a plain line count of `src`.

## What exists

| Component | Lines | Purpose |
|---|---|---|
| `json.cc` | 317 | Strict JSON reader, shared by the configuration parser and the JWT claim reader |
| `config.cc` | 291 | Table-driven configuration parsing and validation |
| `coordinator.cc` | 154 | Cache validity, single flight, backoff, bounded wait list |
| `filter.cc` | 495 | Envoy glue: route scoping, pause and resume, callout, validation, metrics, replies |
| `workload_api.cc` | 222 | protobuf encoding of two messages and gRPC framing |
| `jwt_claims.cc` | 138 |
| `svid_validation.cc` | 71 | base64url plus claim extraction on top of `json.cc` |
| headers | 290 | |
| **Total, `wc -l`** | **1,978** | |
| Unit tests | 681 | 491 checks, ASan and UBSan clean |
| Configuration schema | 99 | `proto/.../spire_jwt.proto` |

## Change since the previous version

The review-driven pass removed the second JSON parser inside `jwt_claims.cc`
(about 190 lines), merged `pb_wire` and `spire_workload_api` into one
`workload_api.cc`, and replaced the hand-rolled cache with `coordinator.cc`.
Two later changes added lines back: `svid_validation.cc` (71 lines), extracted so
the identity, subject, audience, and expiry rejections have unit tests, and
`waiter_registry.h` (51 lines), extracted so the registry primitives used by the
register-before-admit order have unit tests.

The original estimate was about 1,200 lines. The current `wc -l` total is 1,978,
of which roughly 250 are comments and blank lines. The estimate was wrong: the
configuration validator is the bulk of `config.cc` and cannot shrink without
weakening validation, and the coordinator replaced the old cache almost one for
one.

## Dependencies and resources

- Runtime dependencies: none. The module links only libc and a statically linked
  libstdc++, and uses only the Envoy ABI.
- Build dependencies: the `gcc:13-bookworm` and `python:3.10-slim-bookworm` images,
  the pinned SDK files checked against recorded SHA-256 values, and one `grpcio`
  wheel from PyPI checked by hash. No apt repository, Launchpad PPA, or Ubuntu
  mirror is used: apt fails archive signature checks in some build environments,
  the SDK is fetched by Python's `urllib`, and the test stage runs on a python
  image with the Envoy binary copied in. An outage of GitHub, Docker Hub, or PyPI
  blocks publishing, not running. Base images are tag-pinned, not digest-pinned.
- Threads created by the module: none.
- Processes added per Pod: none.
- Module size: 2,699,064 bytes on disk, against a 103,837,096 byte Envoy binary.
- Idle RSS: +1,692 to +1,792 kB with the module loaded, of which about 2.7 MB is
  file-backed `.so` pages shared between containers.
- Memory per cached credential: one JWT string, roughly 1 kB, plus one map entry.
- Workload API traffic: one RPC per audience per credential lifetime, and zero RPCs
  for cached requests (measured: 0 during 20,000 requests).
- CI coverage: unit tests and the end-to-end test both run inside the image
  build, and the published image is only produced after both pass. No Docker
  daemon, compose plugin, or extra CI step is needed. The measurement stage is
  opt-in (`--target measure`) and is not part of publishing.
- Startup cost: the module loads in milliseconds; Envoy startup time is unchanged
  within noise.

## What could still be removed

| Candidate | Saving | Cost |
|---|---|---|
| `json.cc` replaced by protobuf `Struct` | ~150 lines of glue instead of 317 | Needs a protobuf runtime in the module. Ubuntu's `libprotobuf.a` is not PIC, so protobuf must be rebuilt from source; +2.9 MB, and two protobuf runtimes in one process |
| `workload_api.cc` reduced to the two known fields | ~40 lines | Loses forward compatibility with new Workload API fields |
| Validation rules in `config.cc` | up to 150 lines | Removes bounds and typo protection on security-relevant settings |
| `filter.cc` metrics plumbing | ~20 lines | None, but small |

None of these changes the correctness envelope. They are not worth the risk or
the build complexity.

## Residual risks

1. **No timers.** Refresh is traffic-driven. A Pod that receives no traffic holds
   an expired token and fetches on the next request, adding one fetch latency to
   that request. Accepted for now by the task owner. A compiled-in filter would use
   `Event::Dispatcher` timers.
2. **Refresh latency on the first request after expiry.** That request waits up to
   `fetchTimeoutMs` (500 ms default). All other requests wait with it and are
   resumed together. The queue is bounded by `maxPendingRequests`.
3. **No xDS or in-process config reload.** The tested path is a static
   configuration and a process restart, so the module never sees a live reload;
   only the empty-cache-on-startup path exists and is tested. If xDS is used, add a
   reload test with a callout in flight, because Envoy destroys pending callouts
   together with the filter config.
4. **ABI pin.** The module is built against ABI `v0.2.0`, which first shipped in
   Envoy 1.40.0. It will not load on 1.38 or 1.39. Envoy guarantees forward
   compatibility for released ABI and a four-release deprecation window.
5. **Dynamic-module trust.** A module runs in the Envoy process with Envoy's
   privileges. The socket mount, the image, and the module file must be treated as
   trusted artifacts.
6. **Host header and redirects.** The design relies on Envoy selecting the route
   before the filter runs, which is true for the supported configuration. A future
   configuration that adds a route rewrite or an internal redirect predicate could
   change the destination of an already-injected request. Review any such change.
7. **Attestation is outside this repository.** The filter proves only that the
   Agent returned the expected identity. Whether the Agent attested the correct
   workload depends on SPIRE registration entries, which are not automated yet.
8. **Test double, not SPIRE.** The end-to-end harness uses a fake Workload API that
   speaks the real protocol over a real Unix socket and issues a syntactically
   valid JWT. A run against a real SPIRE Server and Agent, with real attestation,
   is still required before production. The build-stage harness starts its own
   fake API inside the container and cannot mount a host socket. A real-Agent run
   executes the same fixtures outside a build with the Agent socket mounted, and
   sets `WORKLOAD_API_EXTERNAL=1`, `WORKLOAD_API_SOCKET`, `EXPECTED_SPIFFE_ID`, and
   `AUDIENCE` when needed. The fail-closed startup checks and the recovery
   transition are skipped because the Agent is reachable from the start, and the
   single-flight and cache-hit RPC counts are skipped because they read the fake
   API's counter; the run's summary line lists what was skipped.

## Verdict

The extension is a working, tested, single-process credential injector that meets
the functional and security requirements it can meet as a dynamic module. It is
not production-ready yet, for two reasons only:

1. the end-to-end run against a real SPIRE Agent with real attestation has not
   been done;
2. there is no load or soak test on production-grade hardware, so the latency
   claims are container measurements with wide error bars.

Everything else in the acceptance criteria is demonstrated: one process, no helper
containers, real JWT-SVID format and claims, exactly one token on protected
routes, no token elsewhere, asynchronous retrieval, caching, refresh before
expiry, fail-closed behaviour during outages, no fetch storms, identity and
audience rejection, HTTP/2 and gRPC behaviour, bounded memory, a build whose SDK
sources and Python wheel are checksum-pinned, real-protocol integration tests that
run in the image build, and base images pinned by tag.
