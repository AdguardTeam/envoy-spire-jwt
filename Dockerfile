# syntax=docker/dockerfile:1

# Everything runs through `docker build`: unit tests, the end-to-end test, and the
# release artifact are stages. There is no apt, no PPA, and no package manager in
# any stage: apt archive verification fails in some build environments, so the SDK
# is fetched with Python's urllib and the compiler comes from the official gcc
# image.
#
# The module is compiled against the dynamic modules SDK of Envoy v1.40.2 and loads
# in any Envoy that supports the same ABI (v0.2.0, first released in 1.40.0).

ARG ENVOY_VERSION=1.40.2

# ---------------------------------------------------------------------------
# Stage: sdk - fetch the dynamic modules SDK for the pinned Envoy tag and verify
# every file against a recorded SHA-256.
# ---------------------------------------------------------------------------
FROM python:3.10-slim-bookworm AS sdk

ARG ENVOY_VERSION

ENV ENVOY_VERSION=${ENVOY_VERSION}
COPY build/fetch_sdk.py /fetch_sdk.py
RUN python3 /fetch_sdk.py

# ---------------------------------------------------------------------------
# Stage: build - compile the module.
#
# gcc 13 is needed for std::format. libstdc++ is linked statically so the module
# does not depend on the libstdc++ inside the Envoy image. bookworm's glibc is
# newer than the Envoy image's, and the e2e stage loads the module into the real
# Envoy image on every build, so a symbol newer than glibc 2.35 fails here instead
# of in production.
# ---------------------------------------------------------------------------
FROM gcc:13-bookworm AS build

ARG ENVOY_VERSION

COPY --from=sdk /sdk /sdk
WORKDIR /src
COPY src/ ./src/
COPY tests/ ./tests/

ENV CXX=g++
RUN set -eux; \
    CXXFLAGS="-std=c++20 -O2 -fPIC -DNDEBUG -isystem /sdk -isystem /sdk/source/extensions/dynamic_modules/sdk/cpp -Isrc"; \
    mkdir -p /out; \
    for f in sdk/source/extensions/dynamic_modules/sdk/cpp/sdk.cc \
             sdk/source/extensions/dynamic_modules/sdk/cpp/sdk_internal.cc; do \
      $CXX $CXXFLAGS -c "/$f" -o "/out/$(basename "$f" .cc).o"; \
    done; \
    for f in src/*.cc; do \
      $CXX $CXXFLAGS -Wall -Wextra -Werror -c "$f" -o "/out/$(basename "$f" .cc).o"; \
    done; \
    $CXX -shared -static-libstdc++ -static-libgcc -o /out/libspire_jwt.so /out/*.o

# ---------------------------------------------------------------------------
# Stage: test - unit tests for the parts that do not need an Envoy process. A
# failing test, a sanitizer report, or a leak fails the build.
# ---------------------------------------------------------------------------
FROM build AS test

RUN set -eux; \
    CXXFLAGS="-std=c++20 -O1 -g -fsanitize=address,undefined -pthread -Isrc"; \
    mkdir -p /test; \
    $CXX $CXXFLAGS -Wall -Wextra -Werror \
      tests/unit/test_main.cc src/json.cc src/config.cc src/jwt_claims.cc \
      src/coordinator.cc src/workload_api.cc src/svid_validation.cc \
      -o /test/unit_tests; \
    if ! ASAN_OPTIONS=detect_leaks=1 /test/unit_tests > /test/result 2>&1; then \
      cat /test/result; \
      exit 1; \
    fi; \
    cat /test/result; \
    grep -q "ALL TESTS PASSED" /test/result

# ---------------------------------------------------------------------------
# Stage: envoy - the pinned upstream binary, used only as the e2e runtime.
# ---------------------------------------------------------------------------
FROM envoyproxy/envoy:v${ENVOY_VERSION} AS envoy

# ---------------------------------------------------------------------------
# Stage: e2e - the real Envoy binary, the real module, a Workload API on a Unix
# socket, and an echo upstream, all inside one container.
#
# The base is a python image, not the Envoy image: the Envoy image ships a 2018
# ubuntu-archive keyring, so apt-get there fails every signature check. Envoy
# links only libc, libm, librt, libdl, and libpthread, and bookworm's glibc is
# newer than the Envoy image's, so the binary runs unchanged.
# ---------------------------------------------------------------------------
FROM python:3.10-slim-bookworm AS e2e

COPY --from=envoy /usr/local/bin/envoy /usr/local/bin/envoy
COPY --from=build /out/libspire_jwt.so /usr/local/lib/envoy-spire-jwt/libspire_jwt.so
COPY tests/integration/requirements.txt /e2e/requirements.txt
RUN python3 -m pip install --no-cache-dir --require-hashes --target /e2e/pylib \
      -r /e2e/requirements.txt

COPY tests/integration/ /e2e/
ENV PYTHONPATH=/e2e/pylib
ENV ENVOY_DYNAMIC_MODULES_SEARCH_PATH=/usr/local/lib/envoy-spire-jwt

RUN set -eux; \
    if ! python3 /e2e/in_container.py > /e2e/result.txt 2>&1; then \
      cat /e2e/result.txt; \
      exit 1; \
    fi; \
    cat /e2e/result.txt

# ---------------------------------------------------------------------------
# Stage: measure - latency, Workload API RPC rate, idle RSS, and module size.
# Opt-in: `docker build --target measure ...`.
# ---------------------------------------------------------------------------
FROM e2e AS measure

RUN set -eux; \
    if ! python3 /e2e/measure_in_container.py > /e2e/measure.txt 2>&1; then \
      cat /e2e/measure.txt; \
      exit 1; \
    fi; \
    cat /e2e/measure.txt

# ---------------------------------------------------------------------------
# Stage: artifact - the release payload. It exists only when the unit and e2e
# stages passed, because it copies their results.
#
#   docker build --target artifact --output type=local,dest=dist .
# ---------------------------------------------------------------------------
FROM scratch AS artifact

COPY --from=test /test/result /unit-test-result.txt
COPY --from=e2e /e2e/result.txt /e2e-result.txt
COPY --from=build /out/libspire_jwt.so /libspire_jwt.so
