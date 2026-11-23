#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace agrd::spire_jwt {

constexpr size_t kMaxConfigBytes = 64 * 1024;

struct FilterConfig {
  std::string workload_api_cluster;
  std::string expected_spiffe_id;
  std::string header_name{"x-machine-token"};
  std::vector<std::string> audiences;
  uint32_t refresh_margin_seconds{60};
  uint32_t min_remaining_seconds{30};
  uint32_t max_token_lifetime_seconds{0};
  uint32_t fetch_timeout_ms{500};
  uint32_t retry_initial_backoff_ms{200};
  uint32_t retry_max_backoff_ms{5000};
  uint32_t max_pending_requests{128};

  bool allowsAudience(std::string_view audience) const;
};

struct PerRouteConfig {
  bool enabled{false};
  std::string audience;
};

bool parseFilterConfig(std::string_view bytes, FilterConfig& out, std::string& error);
bool parsePerRouteConfig(std::string_view bytes, PerRouteConfig& out, std::string& error);

} // namespace agrd::spire_jwt
