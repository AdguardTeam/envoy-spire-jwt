#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

#include "config.h"
#include "coordinator.h"
#include "json.h"
#include "jwt_claims.h"
#include "svid_validation.h"
#include "waiter_registry.h"
#include "workload_api.h"

namespace {

int g_failures = 0;
int g_checks = 0;

void check(bool ok, const char* what, int line) {
  ++g_checks;
  if (!ok) {
    ++g_failures;
    std::printf("FAIL line %d: %s\n", line, what);
  }
}

#define CHECK(cond) check((cond), #cond, __LINE__)

using namespace agrd::spire_jwt;

constexpr std::string_view kSpiffeId = "spiffe://infra.agrd.dev/environment/dev/service/reporter";
constexpr std::string_view kAudience = "reporter-service";

std::string base64Url(std::string_view input) {
  static constexpr char kAlphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  uint32_t accumulator = 0;
  int bits = 0;
  for (const char c : input) {
    accumulator = (accumulator << 8) | static_cast<uint8_t>(c);
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      out.push_back(kAlphabet[(accumulator >> bits) & 0x3f]);
    }
  }
  if (bits > 0) {
    out.push_back(kAlphabet[(accumulator << (6 - bits)) & 0x3f]);
  }
  return out;
}

std::string makeJwt(std::string_view payload) {
  return base64Url(R"({"alg":"RS256","typ":"JWT"})") + "." + base64Url(payload) + "." +
         base64Url("signature");
}

void putVarint(std::string& out, uint64_t value) {
  while (value >= 0x80) {
    out.push_back(static_cast<char>((value & 0x7f) | 0x80));
    value >>= 7;
  }
  out.push_back(static_cast<char>(value));
}

void putBytes(std::string& out, uint32_t field, std::string_view value) {
  putVarint(out, (static_cast<uint64_t>(field) << 3) | 2);
  putVarint(out, value.size());
  out.append(value);
}

std::string lengthDelimited(uint32_t field, std::string_view value) {
  std::string out;
  putVarint(out, (static_cast<uint64_t>(field) << 3) | 2);
  putVarint(out, value.size());
  out.append(value);
  return out;
}

std::string buildResponse(const std::vector<std::pair<std::string, std::string>>& svids,
                          const std::vector<std::string>& hints = {}) {
  std::string payload;
  for (size_t i = 0; i < svids.size(); ++i) {
    std::string entry;
    putBytes(entry, 1, svids[i].first);
    putBytes(entry, 2, svids[i].second);
    if (i < hints.size() && !hints[i].empty()) {
      putBytes(entry, 3, hints[i]);
    }
    putBytes(payload, 1, entry);
  }
  return grpcFrame(payload);
}

std::string baseFilterJson(std::string_view extra = "") {
  std::string out = R"({"workloadApiCluster":"spire_agent",)"
                    R"("expectedSpiffeId":"spiffe://infra.agrd.dev/environment/dev/service/reporter",)"
                    R"("audiences":["reporter-service"] )";
  out.back() = '}';
  if (!extra.empty()) {
    out.insert(out.size() - 1, "," + std::string(extra));
  }
  return out;
}

FilterConfig testConfig(uint32_t max_pending = 128) {
  FilterConfig cfg;
  cfg.workload_api_cluster = "spire_agent";
  cfg.expected_spiffe_id = std::string(kSpiffeId);
  cfg.audiences = {std::string(kAudience)};
  cfg.refresh_margin_seconds = 60;
  cfg.min_remaining_seconds = 30;
  cfg.max_pending_requests = max_pending;
  cfg.retry_initial_backoff_ms = 200;
  cfg.retry_max_backoff_ms = 5000;
  return cfg;
}

std::shared_ptr<const Credential> credential(int64_t expires_at, int64_t now_s) {
  auto value = std::make_shared<Credential>();
  value->svid = "token-" + std::to_string(expires_at);
  value->audience = std::string(kAudience);
  value->expires_at = expires_at;
  (void)now_s;
  return value;
}

void testJson() {
  json::Value value;
  std::string error;
  CHECK(json::parse(R"({"a":1,"b":"x","c":[true,null,2.5],"d":{"e":-3}})", value, error));
  CHECK(value.type == json::Type::Object);
  CHECK(value.object.size() == 4);
  const json::Value* a = value.find("a");
  CHECK(a != nullptr && a->is_integer && a->integer_value == 1);
  const json::Value* c = value.find("c");
  CHECK(c != nullptr && c->type == json::Type::Array && c->array.size() == 3);
  CHECK(c->array[0].bool_value);
  CHECK(c->array[2].type == json::Type::Number && !c->array[2].is_integer);
  const json::Value* d = value.find("d");
  CHECK(d != nullptr && d->find("e")->integer_value == -3);

  CHECK(json::parse("{\"s\":\"a\\\"b\\\\c\\u0041\"}", value, error));
  CHECK(value.find("s")->string_value == "a\"b\\cA");

  CHECK(!json::parse("{\"a\":1,\"a\":2}", value, error));
  CHECK(!json::parse("{\"a\":}", value, error));
  CHECK(!json::parse("{\"a\":1}x", value, error));
  CHECK(!json::parse("", value, error));
  CHECK(json::parse("[]", value, error));
  CHECK(value.type == json::Type::Array);
  CHECK(json::parse("{}", value, error));
  CHECK(value.type == json::Type::Object);
}

void testConfigValid() {
  FilterConfig cfg;
  std::string error;
  CHECK(parseFilterConfig(baseFilterJson(), cfg, error));
  CHECK(cfg.workload_api_cluster == "spire_agent");
  CHECK(cfg.expected_spiffe_id == kSpiffeId);
  CHECK(cfg.refresh_margin_seconds == 60);
  CHECK(cfg.min_remaining_seconds == 30);
  CHECK(cfg.max_token_lifetime_seconds == 0);
  CHECK(cfg.fetch_timeout_ms == 500);
  CHECK(cfg.retry_initial_backoff_ms == 200);
  CHECK(cfg.retry_max_backoff_ms == 5000);
  CHECK(cfg.max_pending_requests == 128);
  CHECK(cfg.allowsAudience(kAudience));
  CHECK(!cfg.allowsAudience("other"));
}

void testConfigOverridesAndAliases() {
  FilterConfig cfg;
  std::string error;
  const std::string json =
      R"({"workload_api_cluster":"spire_agent",)"
      R"("expected_spiffe_id":"spiffe://infra.agrd.dev/environment/dev/service/reporter",)"
      R"("audiences":["billing","reporter-service"],)"
      R"("refresh_margin_seconds":30,"minRemainingSeconds":10,)"
      R"("max_token_lifetime_seconds":600,"fetch_timeout_ms":250,)"
      R"("retry_initial_backoff_ms":50,"retryMaxBackoffMs":1000,"maxPendingRequests":7} )";
  CHECK(parseFilterConfig(json, cfg, error));
  CHECK(cfg.refresh_margin_seconds == 30);
  CHECK(cfg.min_remaining_seconds == 10);
  CHECK(cfg.max_token_lifetime_seconds == 600);
  CHECK(cfg.fetch_timeout_ms == 250);
  CHECK(cfg.retry_initial_backoff_ms == 50);
  CHECK(cfg.retry_max_backoff_ms == 1000);
  CHECK(cfg.max_pending_requests == 7);
  CHECK(cfg.allowsAudience("billing"));
  CHECK(cfg.allowsAudience("reporter-service"));
}

void testConfigRejects() {
  FilterConfig cfg;
  std::string error;
  CHECK(!parseFilterConfig("", cfg, error));
  CHECK(!parseFilterConfig("   ", cfg, error));
  CHECK(!parseFilterConfig("[]", cfg, error));
  CHECK(!parseFilterConfig(R"({"audiences":["a"]})", cfg, error));
  CHECK(!parseFilterConfig(
      R"({"workloadApiCluster":"spire agent",)"
      R"("expectedSpiffeId":"spiffe://infra.agrd.dev/x","audiences":["a"]})",
      cfg, error));
  CHECK(!parseFilterConfig(
      R"({"workloadApiCluster":"spire",)"
      R"("expectedSpiffeId":"http://infra.agrd.dev/x","audiences":["a"]})",
      cfg, error));
  CHECK(!parseFilterConfig(
      R"({"workloadApiCluster":"spire",)"
      R"("expectedSpiffeId":"spiffe://infra.agrd.dev","audiences":["a"]})",
      cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("audiences":["a","a"] )"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("audiences":["a b"] )"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("audiences":"reporter-service" )"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("audiences":["a",1] )"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("refreshMarginSeconds":90000)"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("fetchTimeoutMs":5)"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("retryInitialBackoffMs":6000)"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("retryMaxBackoffMs":5)"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("maxPendingRequests":0)"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("maxPendingRequests":100001)"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("fetchTimeoutMs":-1)"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("fetchTimeoutMs":"500")"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("fetchTimeoutMs":1.5)"), cfg, error));
  CHECK(!parseFilterConfig(baseFilterJson(R"("unknownKey":1)"), cfg, error));
  CHECK(!parseFilterConfig(std::string(70 * 1024, 'x'), cfg, error));
}

void testPerRoute() {
  PerRouteConfig route;
  std::string error;
  CHECK(parsePerRouteConfig(R"({"enabled":true,"audience":"reporter-service"})", route, error));
  CHECK(route.enabled && route.audience == "reporter-service");
  CHECK(parsePerRouteConfig(R"({"enabled":false,"audience":"reporter-service"})", route, error));
  CHECK(!route.enabled && route.audience.empty());
  CHECK(parsePerRouteConfig("", route, error));
  CHECK(!route.enabled);
  CHECK(parsePerRouteConfig("   ", route, error));
  CHECK(!parsePerRouteConfig(R"({"enabled":true})", route, error));
  CHECK(!parsePerRouteConfig(R"({"enabled":"yes","audience":"a"})", route, error));
  CHECK(!parsePerRouteConfig(R"({"enabled":true,"audience":"a","extra":1})", route, error));
}

void testJwtClaims() {
  const std::string payload =
      R"({"sub":"spiffe://infra.agrd.dev/environment/dev/service/reporter",)"
      R"("aud":["reporter-service","billing"],"exp":1700000000,)"
      R"("iat":1699999400,"iss":"https://spire.int.agrd.dev",)"
      R"("nested":{"aud":["leak"],"x":[1,2,{"b":"c"}]}})";
  JwtClaims claims;
  std::string error;
  CHECK(parseJwtClaims(makeJwt(payload), claims, error));
  CHECK(claims.has_exp && claims.expires_at == 1700000000);
  CHECK(claims.has_iat && claims.issued_at == 1699999400);
  CHECK(claims.subject == kSpiffeId);
  CHECK(claims.audiences.size() == 2);
  CHECK(containsAudience(claims.audiences, "billing"));
  CHECK(!containsAudience(claims.audiences, "leak"));

  JwtClaims single;
  CHECK(parseJwtClaims(makeJwt(R"({"aud":"only","exp":1700000000})"), single, error));
  CHECK(single.audiences.size() == 1);

  JwtClaims bad;
  CHECK(!parseJwtClaims(makeJwt(R"({"aud":["a"]})"), bad, error));
  CHECK(!parseJwtClaims(makeJwt(R"({"aud":[1],"exp":1700000000})"), bad, error));
  CHECK(!parseJwtClaims(makeJwt(R"({"aud":"a","exp":"soon"})"), bad, error));
  CHECK(!parseJwtClaims("not-a-jwt", bad, error));
  CHECK(!parseJwtClaims("a.b", bad, error));
  CHECK(!parseJwtClaims("a.!!!.c", bad, error));
}

void testWorkloadApiEncoding() {
  const std::string message = encodeFetchJwtSvidRequest(kSpiffeId, kAudience);
  std::string_view rest = message;
  std::vector<std::pair<int, std::string>> fields;
  size_t pos = 0;
  while (pos < message.size()) {
    const auto field = static_cast<uint32_t>(static_cast<uint8_t>(message[pos])) >> 3;
    ++pos;
    size_t length = 0;
    uint32_t shift = 0;
    while (pos < message.size()) {
      const auto byte = static_cast<uint8_t>(message[pos++]);
      length |= static_cast<size_t>(byte & 0x7f) << shift;
      shift += 7;
      if ((byte & 0x80) == 0) {
        break;
      }
    }
    fields.emplace_back(static_cast<int>(field),
                        std::string(message.substr(pos, std::min(length, message.size() - pos))));
    pos += length;
  }
  CHECK(fields.size() == 2);
  CHECK(fields[0].first == 1 && fields[0].second == kAudience);
  CHECK(fields[1].first == 2 && fields[1].second == kSpiffeId);

  const std::string framed = grpcFrame(message);
  CHECK(framed.size() == message.size() + 5);
  CHECK(framed[0] == 0);
  const size_t length = (static_cast<uint8_t>(framed[1]) << 24) |
                        (static_cast<uint8_t>(framed[2]) << 16) |
                        (static_cast<uint8_t>(framed[3]) << 8) | static_cast<uint8_t>(framed[4]);
  CHECK(length == message.size());
  (void)rest;
}

void testWorkloadApiDecoding() {
  const std::string id(kSpiffeId);
  std::vector<JwtSvid> svids;
  std::string error;

  CHECK(decodeFetchJwtSvidResponse(buildResponse({{id, "token"}}), svids, error));
  CHECK(svids.size() == 1);
  CHECK(svids[0].spiffe_id == id && svids[0].svid == "token");

  CHECK(decodeFetchJwtSvidResponse(buildResponse({{id, "t1"}, {id, "t2"}}, {"internal", "external"}),
                                   svids, error));
  CHECK(svids.size() == 2);
  CHECK(svids[1].hint == "external");

  CHECK(!decodeFetchJwtSvidResponse(buildResponse({}), svids, error));
  CHECK(!decodeFetchJwtSvidResponse(buildResponse({{"", "token"}}), svids, error));
  CHECK(!decodeFetchJwtSvidResponse(buildResponse({{id, ""}}), svids, error));
  CHECK(!decodeFetchJwtSvidResponse("", svids, error));
  CHECK(!decodeFetchJwtSvidResponse("abc", svids, error));

  std::string compressed = buildResponse({{id, "token"}});
  compressed[0] = 1;
  CHECK(!decodeFetchJwtSvidResponse(compressed, svids, error));

  std::string truncated = buildResponse({{id, "token"}});
  truncated.resize(truncated.size() - 1);
  CHECK(!decodeFetchJwtSvidResponse(truncated, svids, error));

  std::string oversized(7, '\0');
  oversized[3] = static_cast<char>(0xff);
  oversized[4] = static_cast<char>(0xff);
  CHECK(!decodeFetchJwtSvidResponse(oversized, svids, error));
}

std::string svidPayload(std::string_view subject, std::string_view audience, int64_t exp,
                        int64_t iat) {
  return "{\"sub\":\"" + std::string(subject) + "\",\"aud\":[\"" + std::string(audience) +
         "\"],\"exp\":" + std::to_string(exp) + ",\"iat\":" + std::to_string(iat) + "}";
}

void testWaiterRegistry() {
  WaiterRegistry<int> registry;
  const uint64_t first = registry.add(1);
  const uint64_t second = registry.add(2);
  CHECK(first != second);
  CHECK(registry.size() == 2);

  const auto taken = registry.take(first);
  CHECK(taken.has_value() && *taken == 1);
  CHECK(!registry.take(first).has_value());
  CHECK(registry.size() == 1);

  const uint64_t rejected = registry.add(3);
  CHECK(registry.erase(rejected));
  CHECK(!registry.take(rejected).has_value());

  CHECK(registry.erase(second));
  CHECK(!registry.erase(second));
  CHECK(registry.size() == 0);
  CHECK(registry.add(4) > second);
}

void testSvidValidation() {
  const std::string id(kSpiffeId);
  const std::string audience(kAudience);
  const int64_t now = 1700000000;
  auto response = [&](std::string_view spiffe_id, std::string_view jwt) {
    return buildResponse({{std::string(spiffe_id), std::string(jwt)}});
  };

  const auto valid = validateSvidResponse(
      response(id, makeJwt(svidPayload(id, audience, now + 600, now))), id, audience, now, 30, 0);
  CHECK(valid.ok);
  CHECK(valid.expires_at == now + 600);
  CHECK(valid.remaining_seconds == 600);
  CHECK(!valid.svid.empty());

  const auto wrong_identity = validateSvidResponse(
      response("spiffe://infra.agrd.dev/environment/dev/service/other",
               makeJwt(svidPayload(id, audience, now + 600, now))),
      id, audience, now, 30, 0);
  CHECK(!wrong_identity.ok);
  CHECK(!wrong_identity.error.empty());

  const auto wrong_subject = validateSvidResponse(
      response(id, makeJwt(svidPayload("spiffe://infra.agrd.dev/environment/dev/service/other",
                                       audience, now + 600, now))),
      id, audience, now, 30, 0);
  CHECK(!wrong_subject.ok);

  const auto wrong_audience = validateSvidResponse(
      response(id, makeJwt(svidPayload(id, "other-service", now + 600, now))), id, audience, now,
      30, 0);
  CHECK(!wrong_audience.ok);

  const auto short_lived = validateSvidResponse(
      response(id, makeJwt(svidPayload(id, audience, now + 30, now))), id, audience, now, 30, 0);
  CHECK(!short_lived.ok);

  const auto expired = validateSvidResponse(
      response(id, makeJwt(svidPayload(id, audience, now - 1, now - 601))), id, audience, now, 30,
      0);
  CHECK(!expired.ok);

  const auto too_long = validateSvidResponse(
      response(id, makeJwt(svidPayload(id, audience, now + 600, now - 600))), id, audience, now,
      30, 600);
  CHECK(!too_long.ok);

  const auto malformed = validateSvidResponse("not-a-grpc-frame", id, audience, now, 30, 0);
  CHECK(!malformed.ok);

  const auto ambiguous = validateSvidResponse(
      grpcFrame(
          lengthDelimited(1, lengthDelimited(1, id) + lengthDelimited(2, makeJwt(svidPayload(
                                                                     id, audience, now + 600, now)))) +
          lengthDelimited(1, lengthDelimited(1, id) + lengthDelimited(2, makeJwt(svidPayload(
                                                                     id, audience, now + 600, now))))),
      id, audience, now, 30, 0);
  CHECK(!ambiguous.ok);
}

void testBackoff() {
  for (uint32_t failures = 1; failures <= 12; ++failures) {
    for (const uint32_t entropy : {0u, 1u, 7u, 123456u}) {
      const int64_t delay = computeBackoffMs(200, 5000, failures, entropy);
      CHECK(delay > 0 && delay <= 5000);
    }
  }
  CHECK(computeBackoffMs(200, 5000, 1, 0) == 150);
  CHECK(computeBackoffMs(200, 5000, 1, 100) == 250);
  CHECK(computeBackoffMs(200, 5000, 6, 0) == 3750);
  CHECK(computeBackoffMs(200, 5000, 6, 2500) == 5000);
}

// Scenario: a request keeps using a valid token while a refresh is in progress.
void testServeStaleWhileRefreshing() {
  Coordinator coordinator(testConfig());
  const int64_t now = 1000;
  coordinator.store(credential(now + 45, now)); // 45s left: inside the 60s margin

  std::shared_ptr<const Credential> out;
  CHECK(coordinator.lookup(kAudience, now, out) == CacheState::Stale);
  CHECK(out != nullptr && out->expires_at == now + 45);

  CHECK(coordinator.admit(kAudience, 1));
  const auto first = coordinator.ensureFetch(kAudience, 0, now);
  CHECK(first.start);
  CHECK(first.wake_now.empty());

  // While the refresh is in flight the stale token still serves requests.
  CHECK(coordinator.lookup(kAudience, now, out) == CacheState::Stale);
  CHECK(out->expires_at == now + 45);
  CHECK(coordinator.finishFetch(kAudience, true, 0).size() == 1);
}

// Scenario: only the first eligible request starts a refresh, across workers.
void testSingleFlightAcrossWorkers() {
  Coordinator coordinator(testConfig());
  const int64_t now = 0;
  constexpr int kWorkers = 100;
  for (int i = 1; i <= kWorkers; ++i) {
    CHECK(coordinator.admit(kAudience, static_cast<uint64_t>(i)));
  }

  int starts = 0;
  for (int i = 0; i < kWorkers; ++i) {
    const auto decision = coordinator.ensureFetch(kAudience, 0, now);
    if (decision.start) {
      ++starts;
    }
    CHECK(decision.wake_now.empty());
  }
  CHECK(starts == 1);
  CHECK(coordinator.pending() == kWorkers);

  coordinator.store(credential(1000 + 600, 1000));
  const auto woken = coordinator.finishFetch(kAudience, true, 0);
  CHECK(woken.size() == static_cast<size_t>(kWorkers));
  CHECK(coordinator.pending() == 0);
  CHECK(!coordinator.inFlight(kAudience));

  // A second finish for the same audience wakes nobody.
  CHECK(coordinator.finishFetch(kAudience, true, 0).empty());
}

// Scenario: no request ever receives an expired or nearly expired token.
void testExpiredNeverServed() {
  Coordinator coordinator(testConfig());
  const int64_t now = 1000;
  std::shared_ptr<const Credential> out;

  coordinator.store(credential(now + 31, now));
  CHECK(coordinator.lookup(kAudience, now, out) == CacheState::Stale);

  coordinator.store(credential(now + 30, now));
  CHECK(coordinator.lookup(kAudience, now, out) == CacheState::Missing);
  CHECK(out == nullptr);

  coordinator.store(credential(now - 1, now));
  CHECK(coordinator.lookup(kAudience, now, out) == CacheState::Missing);

  coordinator.store(credential(now + 1, now));
  CHECK(coordinator.lookup(kAudience, now, out) == CacheState::Missing);
}

// Scenario: after a long idle period the first request must fetch again.
void testIdleExpiryTriggersNewFetch() {
  Coordinator coordinator(testConfig());
  const int64_t issued_at = 1000;
  coordinator.store(credential(issued_at + 600, issued_at));

  const int64_t idle_at = issued_at + 86400;
  std::shared_ptr<const Credential> out;
  CHECK(coordinator.lookup(kAudience, idle_at, out) == CacheState::Missing);

  CHECK(coordinator.admit(kAudience, 7));
  const auto decision = coordinator.ensureFetch(kAudience, 0, idle_at);
  CHECK(decision.start);

  coordinator.store(credential(idle_at + 600, idle_at));
  CHECK(coordinator.finishFetch(kAudience, true, 0).size() == 1);
  CHECK(coordinator.lookup(kAudience, idle_at, out) == CacheState::Fresh);
}

// Scenario: SPIRE failures back off and never accumulate waiters or retries.
void testFailuresBackOffAndDrain() {
  const FilterConfig config = testConfig(4);
  Coordinator coordinator(config);

  CHECK(coordinator.admit(kAudience, 1));
  CHECK(coordinator.admit(kAudience, 2));
  const auto decision = coordinator.ensureFetch(kAudience, 1000, 1000);
  CHECK(decision.start);

  const auto woken = coordinator.finishFetch(kAudience, false, 1000);
  CHECK(woken.size() == 2);
  CHECK(coordinator.pending() == 0);
  CHECK(coordinator.failures(kAudience) == 1);

  // Inside the backoff window nothing starts and nobody waits.
  const auto during = coordinator.ensureFetch(kAudience, 1100, 1000);
  CHECK(!during.start);
  CHECK(during.wake_now.empty());
  CHECK(coordinator.pending() == 0);

  // After the window the next eligible request starts exactly one fetch.
  bool started = false;
  for (int64_t t = 1000; t < 1000 + 5000 && !started; t += 50) {
    started = coordinator.ensureFetch(kAudience, t, 1000).start;
  }
  CHECK(started);

  // Repeated failures stay bounded by retry_max_backoff_ms.
  int64_t now = 20000;
  for (int i = 0; i < 20; ++i) {
    coordinator.finishFetch(kAudience, false, now);
    const auto retry = coordinator.ensureFetch(kAudience, now, 1000);
    CHECK(!retry.start);
    CHECK(retry.wake_now.empty());
    now += 5000;
  }
  CHECK(coordinator.pending() == 0);
  CHECK(coordinator.failures(kAudience) == 21);
}

// Scenario: the wait list is bounded and cancellations release capacity.
void testPendingLimitAndCancellation() {
  Coordinator coordinator(testConfig(3));
  const int64_t now = 0;
  CHECK(coordinator.admit(kAudience, 1));
  CHECK(coordinator.admit(kAudience, 2));
  CHECK(coordinator.admit(kAudience, 3));
  CHECK(!coordinator.admit(kAudience, 4));
  CHECK(coordinator.pending() == 3);

  coordinator.cancel(2);
  CHECK(coordinator.pending() == 2);
  coordinator.cancel(2); // idempotent
  CHECK(coordinator.pending() == 2);
  CHECK(coordinator.admit(kAudience, 5));
  CHECK(coordinator.pending() == 3);

  const auto decision = coordinator.ensureFetch(kAudience, 0, now);
  CHECK(decision.start);
  const auto woken = coordinator.finishFetch(kAudience, false, 0);
  CHECK(woken.size() == 3);
  CHECK(coordinator.pending() == 0);
}

// Scenario: audiences do not share single-flight state.
void testFreshCacheSuppressesExtraFetch() {
  Coordinator coordinator(testConfig());
  const int64_t now = 1000;
  coordinator.store(credential(now + 600, now));

  const auto decision = coordinator.ensureFetch(kAudience, 0, now);
  CHECK(!decision.start);
  CHECK(!decision.refresh);
  CHECK(!coordinator.inFlight(kAudience));

  // A queued request that runs after a usable credential is cached must not
  // fetch again; any waiter it carries is resumed instead of left waiting.
  CHECK(coordinator.admit(kAudience, 1));
  const auto queued = coordinator.ensureFetch(kAudience, 0, now);
  CHECK(!queued.start);
  CHECK(queued.wake_now.size() == 1);
  CHECK(coordinator.finishFetch(kAudience, true, 0).empty());
  const auto after = coordinator.ensureFetch(kAudience, 0, now);
  CHECK(!after.start);
  CHECK(after.wake_now.empty());
}

void testAudiencesAreIndependent() {
  Coordinator coordinator(testConfig());
  const int64_t now = 1000;
  CHECK(coordinator.admit(kAudience, 1));
  CHECK(coordinator.admit("billing", 2));
  CHECK(coordinator.ensureFetch(kAudience, 0, now).start);
  CHECK(coordinator.ensureFetch("billing", 0, now).start);
  CHECK(coordinator.inFlight(kAudience));
  CHECK(coordinator.inFlight("billing"));
  CHECK(!coordinator.ensureFetch(kAudience, 0, now).start);
  CHECK(!coordinator.ensureFetch("billing", 0, now).start);

  auto billing = std::make_shared<Credential>();
  billing->svid = "billing-token";
  billing->audience = "billing";
  billing->expires_at = 100000;
  coordinator.store(billing);
  CHECK(coordinator.cached() == 1);
  std::shared_ptr<const Credential> out;
  CHECK(coordinator.lookup("billing", 1000, out) == CacheState::Fresh);
  CHECK(coordinator.lookup(kAudience, 1000, out) == CacheState::Missing);
}

} // namespace

int main() {
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  testJson();
  testConfigValid();
  testConfigOverridesAndAliases();
  testConfigRejects();
  testPerRoute();
  testJwtClaims();
  testWorkloadApiEncoding();
  testWorkloadApiDecoding();
  testWaiterRegistry();
  testSvidValidation();
  testBackoff();
  testServeStaleWhileRefreshing();
  testSingleFlightAcrossWorkers();
  testExpiredNeverServed();
  testIdleExpiryTriggersNewFetch();
  testFailuresBackOffAndDrain();
  testPendingLimitAndCancellation();
  testFreshCacheSuppressesExtraFetch();
  testAudiencesAreIndependent();

  std::printf("%d checks, %d failures\n", g_checks, g_failures);
  if (g_failures != 0) {
    std::printf("TESTS FAILED\n");
    return 1;
  }
  std::printf("ALL TESTS PASSED\n");
  return 0;
}
