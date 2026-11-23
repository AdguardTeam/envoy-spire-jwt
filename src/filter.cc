#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "config.h"
#include "coordinator.h"
#include "svid_validation.h"
#include "waiter_registry.h"
#include "sdk.h"
#include "workload_api.h"

namespace Envoy {
namespace DynamicModules {

namespace {

using agrd::spire_jwt::CacheState;
using agrd::spire_jwt::Coordinator;
using agrd::spire_jwt::Credential;
using agrd::spire_jwt::FilterConfig;
using agrd::spire_jwt::PerRouteConfig;
using agrd::spire_jwt::WaiterRegistry;

constexpr std::string_view kHeaderName = "x-machine-token";
constexpr std::string_view kWorkloadApiPath = "/spiffe.workload.v1.SPIFFEWorkloadAPI/FetchJWTSVID";

int64_t nowMs() {
  return std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now().time_since_epoch())
      .count();
}

int64_t nowSeconds() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

struct Metrics {
  MetricID cache_hit{0};
  MetricID cache_miss{0};
  MetricID fetch_success{0};
  MetricID fetch_failure{0};
  MetricID refresh_success{0};
  MetricID refresh_failure{0};
  MetricID requests_rejected{0};
  MetricID requests_waiting{0};
  MetricID token_seconds_remaining{0};
  MetricID fetch_latency{0};
};

struct Waiter {
  std::mutex mutex;
  uint64_t id{0};
  HttpFilterHandle* handle{nullptr};
  std::shared_ptr<Scheduler> scheduler;
  std::string audience;
};

class PerRoute : public RouteSpecificConfig {
public:
  explicit PerRoute(PerRouteConfig config) : config_(std::move(config)) {}
  const PerRouteConfig& config() const { return config_; }

private:
  PerRouteConfig config_;
};

using FinishCallback =
    std::function<void(bool transport_ok, std::string_view grpc_status, const std::string& body,
                       int64_t start_ms)>;

class FetchClient : public HttpStreamCallback {
public:
  explicit FetchClient(int64_t start_ms) : start_ms_(start_ms) {}

  void setFinishCallback(FinishCallback on_finish) { on_finish_ = std::move(on_finish); }
  void setId(uint64_t id) { id_ = id; }
  uint64_t id() const { return id_; }

  void onHttpStreamHeaders(uint64_t, std::span<const HeaderView> headers, bool) override {
    for (const auto& header : headers) {
      if (header.key() == "grpc-status") {
        grpc_status_ = std::string(header.value());
      } else if (header.key() == ":status") {
        http_status_ = std::string(header.value());
      }
    }
  }

  void onHttpStreamData(uint64_t, std::span<const BufferView> chunks, bool) override {
    for (const auto& chunk : chunks) {
      if (body_.size() + chunk.size() > agrd::spire_jwt::kMaxWorkloadApiResponseBytes) {
        too_large_ = true;
        return;
      }
      body_.append(chunk.toStringView());
    }
  }

  void onHttpStreamTrailers(uint64_t, std::span<const HeaderView> trailers) override {
    for (const auto& header : trailers) {
      if (header.key() == "grpc-status") {
        grpc_status_ = std::string(header.value());
      }
    }
  }

  void onHttpStreamComplete(uint64_t) override { finish(true); }
  void onHttpStreamReset(uint64_t, HttpStreamResetReason) override { finish(false); }

private:
  void finish(bool transport_ok) {
    if (done_) {
      return;
    }
    done_ = true;
    on_finish_(transport_ok && !too_large_ && http_status_ != "0", grpc_status_, body_, start_ms_);
  }

  FinishCallback on_finish_;
  uint64_t id_{0};
  const int64_t start_ms_;
  std::string grpc_status_{"unset"};
  std::string http_status_{"unset"};
  std::string body_;
  bool too_large_{false};
  bool done_{false};
};

void sendUnavailable(HttpFilterHandle& handle, const Metrics& metrics, uint32_t pending,
                     std::string_view detail) {
  handle.incrementCounterValue(metrics.requests_rejected, 1);
  const auto content_type = handle.requestHeaders().getOne("content-type");
  if (content_type.substr(0, 16) == "application/grpc") {
    const HeaderView headers[] = {
        HeaderView("content-type", "application/grpc"),
        HeaderView("grpc-status", "14"),
        HeaderView("grpc-message", "machine credential unavailable"),
    };
    handle.sendLocalResponse(200, headers, "", detail);
  } else {
    const HeaderView headers[] = {HeaderView("content-type", "text/plain")};
    handle.sendLocalResponse(503, headers, "machine credential unavailable\n", detail);
  }
  handle.setGaugeValue(metrics.requests_waiting, pending);
}

class SharedState : public std::enable_shared_from_this<SharedState> {
public:
  SharedState(FilterConfig config, HttpFilterConfigHandle* handle, Metrics metrics,
              std::shared_ptr<Scheduler> main_scheduler)
      : coordinator_(std::move(config)), handle_(handle), metrics_(metrics),
        main_scheduler_(std::move(main_scheduler)) {}

  const FilterConfig& config() const { return coordinator_.config(); }
  const Metrics& metrics() const { return metrics_; }
  uint32_t pending() const { return coordinator_.pending(); }
  CacheState lookup(std::string_view audience, std::shared_ptr<const Credential>& out) const {
    return coordinator_.lookup(audience, nowSeconds(), out);
  }

  // Worker thread.
  bool request(const std::shared_ptr<Waiter>& waiter) {
    const uint64_t id = registry_.add(waiter);
    waiter->id = id;
    if (!coordinator_.admit(waiter->audience, id)) {
      registry_.erase(id);
      std::lock_guard lock(waiter->mutex);
      waiter->handle = nullptr;
      return false;
    }
    postFetch(waiter->audience);
    postWaitingGauge();
    return true;
  }

  // Worker thread.
  void forget(const std::shared_ptr<Waiter>& waiter) {
    registry_.erase(waiter->id);
    coordinator_.cancel(waiter->id);
    postWaitingGauge();
  }

  // Worker thread. Refresh a credential that is still valid.
  void requestRefresh(std::string_view audience) { postFetch(audience); }

private:
  void postFetch(std::string_view audience) {
    auto self = shared_from_this();
    const std::string key(audience);
    main_scheduler_->schedule([self, key]() { self->onEnsureFetch(key); });
  }

  void onEnsureFetch(const std::string& audience) {
    const auto decision = coordinator_.ensureFetch(audience, nowMs(), nowSeconds());
    for (const uint64_t id : decision.wake_now) {
      wake(id);
    }
    if (decision.start) {
      startFetch(audience, decision.refresh);
    }
  }

  void startFetch(const std::string& audience, bool refresh) {
    const std::string body = agrd::spire_jwt::grpcFrame(
        agrd::spire_jwt::encodeFetchJwtSvidRequest(config().expected_spiffe_id, audience));
    auto& client = *makeClient(audience, refresh);
    const HeaderView headers[] = {
        HeaderView(":method", "POST"),
        HeaderView(":path", kWorkloadApiPath),
        HeaderView(":scheme", "http"),
        HeaderView(":authority", "spire-agent"),
        HeaderView("content-type", "application/grpc"),
        HeaderView("te", "trailers"),
        HeaderView("user-agent", "envoy-spire-jwt/1"),
    };
    const auto result =
        handle_->startHttpStream(config().workload_api_cluster, headers, body, true,
                                 config().fetch_timeout_ms, client);
    if (result.first == HttpCalloutInitResult::Success) {
      return;
    }
    inflight_.erase(audience);
    recordFetchOutcome(false, refresh, "cannot start Workload API call", audience);
    for (const uint64_t id : coordinator_.finishFetch(audience, false, nowMs())) {
      wake(id);
    }
  }

  FetchClient* makeClient(const std::string& audience, bool refresh) {
    auto self = shared_from_this();
    auto client = std::make_unique<FetchClient>(nowMs());
    const uint64_t id = ++next_fetch_id_;
    client->setId(id);
    client->setFinishCallback([self, audience, id, refresh](bool transport_ok,
                                                           std::string_view grpc_status,
                                                           const std::string& body,
                                                           int64_t start_ms) {
      self->onFetchDone(audience, id, refresh, transport_ok, grpc_status, body, start_ms);
    });
    FetchClient* raw = client.get();
    inflight_[audience] = std::move(client);
    return raw;
  }

  void onFetchDone(const std::string& audience, uint64_t fetch_id, bool refresh, bool transport_ok,
                   std::string_view grpc_status, const std::string& body, int64_t start_ms) {
    handle_->recordHistogramValue(
        metrics_.fetch_latency, static_cast<uint64_t>(std::max<int64_t>(0, nowMs() - start_ms)));
    std::string error;
    bool success = false;
    if (!transport_ok) {
      error = "Workload API call failed";
    } else if (grpc_status != "0") {
      error = "Workload API returned grpc-status " + std::string(grpc_status);
    } else {
      success = acceptCredential(audience, body, error);
    }
    recordFetchOutcome(success, refresh, error, audience);

    const auto ids = coordinator_.finishFetch(audience, success, nowMs());
    auto self = shared_from_this();
    main_scheduler_->schedule(
        [self, audience, fetch_id]() { self->eraseClient(audience, fetch_id); });
    for (const uint64_t id : ids) {
      wake(id);
    }
  }

  bool acceptCredential(const std::string& audience, const std::string& body, std::string& error) {
    const auto validation = agrd::spire_jwt::validateSvidResponse(
        body, config().expected_spiffe_id, audience, nowSeconds(),
        config().min_remaining_seconds, config().max_token_lifetime_seconds);
    if (!validation.ok) {
      error = validation.error;
      return false;
    }
    auto credential = std::make_shared<Credential>();
    credential->svid = validation.svid;
    credential->audience = audience;
    credential->expires_at = validation.expires_at;
    coordinator_.store(std::move(credential));
    handle_->setGaugeValue(metrics_.token_seconds_remaining,
                           static_cast<uint64_t>(validation.remaining_seconds));
    return true;
  }

  void recordFetchOutcome(bool success, bool refresh, std::string_view error,
                          const std::string& audience) {
    if (success) {
      handle_->incrementCounterValue(metrics_.fetch_success, 1);
      if (refresh) {
        handle_->incrementCounterValue(metrics_.refresh_success, 1);
      }
      return;
    }
    handle_->incrementCounterValue(metrics_.fetch_failure, 1);
    if (refresh) {
      handle_->incrementCounterValue(metrics_.refresh_failure, 1);
    }
    DYM_LOG((*handle_), LogLevel::Warn, "spire_jwt: {} for audience '{}'", error, audience);
  }

  void eraseClient(const std::string& audience, uint64_t fetch_id) {
    const auto it = inflight_.find(audience);
    if (it != inflight_.end() && it->second->id() == fetch_id) {
      inflight_.erase(it);
    }
  }

  void postWaitingGauge() {
    auto self = shared_from_this();
    main_scheduler_->schedule([self]() {
      self->handle_->setGaugeValue(self->metrics_.requests_waiting, self->coordinator_.pending());
    });
  }

  void wake(uint64_t id) {
    auto waiter = registry_.take(id);
    if (!waiter) {
      return;
    }
    auto scheduler = (*waiter)->scheduler;
    if (!scheduler) {
      return;
    }
    auto self = shared_from_this();
    scheduler->schedule([self, waiter]() { self->resume(*waiter); });
  }

  void resume(const std::shared_ptr<Waiter>& waiter) {
    HttpFilterHandle* handle = nullptr;
    {
      std::lock_guard lock(waiter->mutex);
      handle = waiter->handle;
      waiter->handle = nullptr;
    }
    if (handle == nullptr) {
      return;
    }
    std::shared_ptr<const Credential> credential;
    if (coordinator_.lookup(waiter->audience, nowSeconds(), credential) == CacheState::Missing) {
      sendUnavailable(*handle, metrics_, coordinator_.pending(), "no_machine_credential");
      return;
    }
    handle->requestHeaders().remove(kHeaderName);
    handle->requestHeaders().set(kHeaderName, credential->svid);
    handle->incrementCounterValue(metrics_.cache_hit, 1);
    handle->setGaugeValue(metrics_.requests_waiting, coordinator_.pending());
    handle->continueRequest();
  }

  Coordinator coordinator_;
  HttpFilterConfigHandle* handle_;
  Metrics metrics_;
  std::shared_ptr<Scheduler> main_scheduler_;
  uint64_t next_fetch_id_{0};
  WaiterRegistry<std::shared_ptr<Waiter>> registry_;
  std::map<std::string, std::unique_ptr<FetchClient>, std::less<>> inflight_;
};

class SpireJwtFilter : public HttpFilter {
public:
  SpireJwtFilter(HttpFilterHandle& handle, std::shared_ptr<SharedState> state)
      : handle_(handle), state_(std::move(state)) {}

  HeadersStatus onRequestHeaders(HeaderMap& headers, bool) override {
    const auto* route = dynamic_cast<const PerRoute*>(handle_.getMostSpecificConfig());
    if (route == nullptr || !route->config().enabled) {
      return HeadersStatus::Continue;
    }
    if (!state_->config().allowsAudience(route->config().audience)) {
      sendUnavailable(handle_, state_->metrics(), state_->pending(), "audience_not_allowed");
      return HeadersStatus::Stop;
    }
    const std::string audience = route->config().audience;
    headers.remove(kHeaderName);

    std::shared_ptr<const Credential> credential;
    const CacheState state = state_->lookup(audience, credential);
    if (state != CacheState::Missing) {
      handle_.incrementCounterValue(state_->metrics().cache_hit, 1);
      headers.set(kHeaderName, credential->svid);
      if (state == CacheState::Stale) {
        state_->requestRefresh(audience);
      }
      return HeadersStatus::Continue;
    }

    handle_.incrementCounterValue(state_->metrics().cache_miss, 1);
    auto waiter = std::make_shared<Waiter>();
    waiter->handle = &handle_;
    waiter->scheduler = handle_.getScheduler();
    waiter->audience = audience;
    if (!state_->request(waiter)) {
      sendUnavailable(handle_, state_->metrics(), state_->pending(), "pending_limit_exceeded");
      return HeadersStatus::Stop;
    }
    handle_.setGaugeValue(state_->metrics().requests_waiting, state_->pending());
    waiter_ = std::move(waiter);
    return HeadersStatus::Stop;
  }

  BodyStatus onRequestBody(BodyBuffer&, bool) override { return BodyStatus::Continue; }
  TrailersStatus onRequestTrailers(HeaderMap&) override { return TrailersStatus::Continue; }
  HeadersStatus onResponseHeaders(HeaderMap&, bool) override { return HeadersStatus::Continue; }
  BodyStatus onResponseBody(BodyBuffer&, bool) override { return BodyStatus::Continue; }
  TrailersStatus onResponseTrailers(HeaderMap&) override { return TrailersStatus::Continue; }
  void onStreamComplete() override {}

  void onDestroy() override {
    if (!waiter_) {
      return;
    }
    {
      std::lock_guard lock(waiter_->mutex);
      waiter_->handle = nullptr;
    }
    state_->forget(waiter_);
    waiter_.reset();
  }

private:
  HttpFilterHandle& handle_;
  std::shared_ptr<SharedState> state_;
  std::shared_ptr<Waiter> waiter_;
};

class SpireJwtFilterFactory : public HttpFilterFactory {
public:
  explicit SpireJwtFilterFactory(std::shared_ptr<SharedState> state) : state_(std::move(state)) {}
  std::unique_ptr<HttpFilter> create(HttpFilterHandle& handle) override {
    return std::make_unique<SpireJwtFilter>(handle, state_);
  }

private:
  std::shared_ptr<SharedState> state_;
};

class SpireJwtConfigFactory : public HttpFilterConfigFactory {
public:
  std::unique_ptr<HttpFilterFactory> create(HttpFilterConfigHandle& handle,
                                            std::string_view config_view) override {
    FilterConfig config;
    std::string error;
    if (!agrd::spire_jwt::parseFilterConfig(config_view, config, error)) {
      DYM_LOG(handle, LogLevel::Error, "spire_jwt: invalid filter config: {}", error);
      return nullptr;
    }
    auto main_scheduler = handle.getScheduler();
    if (!main_scheduler) {
      DYM_LOG(handle, LogLevel::Error, "spire_jwt: no main thread scheduler available");
      return nullptr;
    }
    Metrics metrics;
    metrics.cache_hit = handle.defineCounter("cache_hit").first;
    metrics.cache_miss = handle.defineCounter("cache_miss").first;
    metrics.fetch_success = handle.defineCounter("fetch_success").first;
    metrics.fetch_failure = handle.defineCounter("fetch_failure").first;
    metrics.refresh_success = handle.defineCounter("refresh_success").first;
    metrics.refresh_failure = handle.defineCounter("refresh_failure").first;
    metrics.requests_rejected = handle.defineCounter("requests_rejected").first;
    metrics.requests_waiting = handle.defineGauge("requests_waiting").first;
    metrics.token_seconds_remaining = handle.defineGauge("token_seconds_remaining").first;
    metrics.fetch_latency = handle.defineHistogram("fetch_latency_ms").first;
    auto state = std::make_shared<SharedState>(std::move(config), &handle, metrics,
                                               std::move(main_scheduler));
    return std::make_unique<SpireJwtFilterFactory>(std::move(state));
  }

  std::unique_ptr<RouteSpecificConfig> createPerRoute(std::string_view config_view) override {
    PerRouteConfig config;
    std::string error;
    if (!agrd::spire_jwt::parsePerRouteConfig(config_view, config, error)) {
      return nullptr;
    }
    return std::make_unique<PerRoute>(std::move(config));
  }
};

REGISTER_HTTP_FILTER_CONFIG_FACTORY(SpireJwtConfigFactory, "spire_jwt");

} // namespace
} // namespace DynamicModules
} // namespace Envoy
