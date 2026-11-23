#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <vector>

#include "config.h"

namespace agrd::spire_jwt {

struct Credential {
  std::string svid;
  std::string audience;
  int64_t expires_at{0};
};

enum class CacheState {
  // Valid and outside the refresh margin: inject, do nothing else.
  Fresh,
  // Valid but inside the refresh margin: inject and refresh in the background.
  Stale,
  // Absent or too close to expiration: the request must wait or fail closed.
  Missing,
};

struct FetchDecision {
  bool start{false};
  // A usable credential was cached when the fetch was requested, so this fetch
  // is a background refresh of a token that keeps serving.
  bool refresh{false};
  // Waiters that cannot be served: the cache is already fresh or no fetch is
  // allowed right now (backoff), so they must be resumed instead of waiting for
  // a fetch that will not happen.
  std::vector<uint64_t> wake_now;
};

// Coordinator owns every piece of policy that must be identical in production
// and in tests: cache validity, the refresh margin, single flight, backoff, and
// the bounded wait list. It has no Envoy dependency and no locks on the cache
// read path beyond one shared lock.
class Coordinator {
public:
  explicit Coordinator(FilterConfig config);

  const FilterConfig& config() const { return config_; }

  // Any thread.
  CacheState lookup(std::string_view audience, int64_t now_seconds,
                    std::shared_ptr<const Credential>& out) const;
  void store(std::shared_ptr<const Credential> credential);
  bool admit(std::string_view audience, uint64_t waiter_id);
  void cancel(uint64_t waiter_id);
  uint32_t pending() const { return pending_.load(std::memory_order_relaxed); }
  size_t cached() const;

  // Fetch thread only. Returns no start when the cache already holds a fresh
  // credential, which stops a queued request from starting a second fetch after
  // the first one succeeded.
  FetchDecision ensureFetch(std::string_view audience, int64_t now_ms, int64_t now_seconds);
  // Returns the waiters to resume. They either receive a fresh credential or
  // fail closed, depending on what lookup says when they are resumed.
  std::vector<uint64_t> finishFetch(std::string_view audience, bool success, int64_t now_ms);

  bool inFlight(std::string_view audience) const;
  uint32_t failures(std::string_view audience) const;

private:
  std::vector<uint64_t> takeWaiters(std::string_view audience);

  FilterConfig config_;
  mutable std::shared_mutex store_mutex_;
  std::map<std::string, std::shared_ptr<const Credential>, std::less<>> credentials_;

  struct FetchState {
    bool in_flight{false};
    uint32_t failures{0};
    int64_t next_attempt_ms{0};
  };
  std::map<std::string, FetchState, std::less<>> fetch_;

  mutable std::mutex waiters_mutex_;
  std::map<uint64_t, std::string> waiters_;
  std::map<std::string, std::vector<uint64_t>, std::less<>> waiters_by_audience_;
  std::atomic<uint32_t> pending_{0};
};

// Exposed for tests: exponential backoff with +-25% jitter, clamped to max_ms.
int64_t computeBackoffMs(uint32_t initial_ms, uint32_t max_ms, uint32_t failures, uint32_t entropy);

} // namespace agrd::spire_jwt
