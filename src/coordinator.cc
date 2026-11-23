#include "coordinator.h"

#include <algorithm>

namespace agrd::spire_jwt {

Coordinator::Coordinator(FilterConfig config) : config_(std::move(config)) {}

CacheState Coordinator::lookup(std::string_view audience, int64_t now_seconds,
                               std::shared_ptr<const Credential>& out) const {
  out.reset();
  std::shared_lock lock(store_mutex_);
  const auto it = credentials_.find(audience);
  if (it == credentials_.end()) {
    return CacheState::Missing;
  }
  const int64_t remaining = it->second->expires_at - now_seconds;
  if (remaining <= static_cast<int64_t>(config_.min_remaining_seconds)) {
    return CacheState::Missing;
  }
  out = it->second;
  return remaining <= static_cast<int64_t>(config_.refresh_margin_seconds) ? CacheState::Stale
                                                                          : CacheState::Fresh;
}

void Coordinator::store(std::shared_ptr<const Credential> credential) {
  std::unique_lock lock(store_mutex_);
  credentials_[credential->audience] = std::move(credential);
}

size_t Coordinator::cached() const {
  std::shared_lock lock(store_mutex_);
  return credentials_.size();
}

bool Coordinator::admit(std::string_view audience, uint64_t waiter_id) {
  std::lock_guard lock(waiters_mutex_);
  if (pending_.load(std::memory_order_relaxed) >= config_.max_pending_requests) {
    return false;
  }
  waiters_[waiter_id] = std::string(audience);
  waiters_by_audience_[std::string(audience)].push_back(waiter_id);
  pending_.fetch_add(1, std::memory_order_relaxed);
  return true;
}

void Coordinator::cancel(uint64_t waiter_id) {
  bool removed = false;
  std::string audience;
  {
    std::lock_guard lock(waiters_mutex_);
    const auto it = waiters_.find(waiter_id);
    if (it == waiters_.end()) {
      return;
    }
    audience = it->second;
    waiters_.erase(it);
    const auto list_it = waiters_by_audience_.find(audience);
    if (list_it != waiters_by_audience_.end()) {
      auto& list = list_it->second;
      list.erase(std::remove(list.begin(), list.end(), waiter_id), list.end());
      if (list.empty()) {
        waiters_by_audience_.erase(list_it);
      }
    }
    removed = true;
  }
  if (removed) {
    pending_.fetch_sub(1, std::memory_order_relaxed);
  }
}

std::vector<uint64_t> Coordinator::takeWaiters(std::string_view audience) {
  std::vector<uint64_t> ids;
  {
    std::lock_guard lock(waiters_mutex_);
    const auto it = waiters_by_audience_.find(audience);
    if (it == waiters_by_audience_.end()) {
      return ids;
    }
    ids.swap(it->second);
    waiters_by_audience_.erase(it);
    for (const uint64_t id : ids) {
      waiters_.erase(id);
    }
  }
  if (!ids.empty()) {
    pending_.fetch_sub(static_cast<uint32_t>(ids.size()), std::memory_order_relaxed);
  }
  return ids;
}

FetchDecision Coordinator::ensureFetch(std::string_view audience, int64_t now_ms,
                                       int64_t now_seconds) {
  std::shared_ptr<const Credential> cached;
  const CacheState state = lookup(audience, now_seconds, cached);
  if (state == CacheState::Fresh) {
    return FetchDecision{false, false, takeWaiters(audience)};
  }
  const auto it = fetch_.find(audience);
  if (it != fetch_.end() && it->second.in_flight) {
    return FetchDecision{};
  }
  if (it != fetch_.end() && now_ms < it->second.next_attempt_ms) {
    return FetchDecision{false, false, takeWaiters(audience)};
  }
  fetch_[std::string(audience)].in_flight = true;
  return FetchDecision{true, state == CacheState::Stale, {}};
}

std::vector<uint64_t> Coordinator::finishFetch(std::string_view audience, bool success,
                                               int64_t now_ms) {
  auto& state = fetch_[std::string(audience)];
  state.in_flight = false;
  if (success) {
    state.failures = 0;
    state.next_attempt_ms = 0;
  } else {
    ++state.failures;
    const uint32_t entropy = static_cast<uint32_t>(now_ms) ^ (state.failures * 2654435761u);
    state.next_attempt_ms =
        now_ms + computeBackoffMs(config_.retry_initial_backoff_ms, config_.retry_max_backoff_ms,
                                  state.failures, entropy);
  }
  return takeWaiters(audience);
}

bool Coordinator::inFlight(std::string_view audience) const {
  const auto it = fetch_.find(audience);
  return it != fetch_.end() && it->second.in_flight;
}

uint32_t Coordinator::failures(std::string_view audience) const {
  const auto it = fetch_.find(audience);
  return it == fetch_.end() ? 0 : it->second.failures;
}

int64_t computeBackoffMs(uint32_t initial_ms, uint32_t max_ms, uint32_t failures, uint32_t entropy) {
  uint64_t delay = initial_ms;
  for (uint32_t i = 1; i < failures && delay < max_ms; ++i) {
    delay *= 2;
  }
  delay = std::min<uint64_t>(delay, max_ms);
  const uint32_t jitter_range = static_cast<uint32_t>(delay / 4);
  if (jitter_range == 0) {
    return static_cast<int64_t>(delay);
  }
  const uint32_t jitter = entropy % (jitter_range * 2 + 1);
  const int64_t signed_jitter = static_cast<int64_t>(jitter) - static_cast<int64_t>(jitter_range);
  const int64_t result = static_cast<int64_t>(delay) + signed_jitter;
  return std::max<int64_t>(1, std::min<int64_t>(result, static_cast<int64_t>(max_ms)));
}

} // namespace agrd::spire_jwt
