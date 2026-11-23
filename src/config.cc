#include "config.h"

#include <algorithm>
#include <iterator>

#include "json.h"

namespace agrd::spire_jwt {
namespace {

using json::Type;
using json::Value;

struct Uint32Field {
  std::string_view snake;
  std::string_view camel;
  uint32_t FilterConfig::*member;
  uint32_t fallback;
};

constexpr Uint32Field kUint32Fields[] = {
    {"refresh_margin_seconds", "refreshMarginSeconds", &FilterConfig::refresh_margin_seconds, 60},
    {"min_remaining_seconds", "minRemainingSeconds", &FilterConfig::min_remaining_seconds, 30},
    {"max_token_lifetime_seconds", "maxTokenLifetimeSeconds",
     &FilterConfig::max_token_lifetime_seconds, 0},
    {"fetch_timeout_ms", "fetchTimeoutMs", &FilterConfig::fetch_timeout_ms, 500},
    {"retry_initial_backoff_ms", "retryInitialBackoffMs", &FilterConfig::retry_initial_backoff_ms,
     200},
    {"retry_max_backoff_ms", "retryMaxBackoffMs", &FilterConfig::retry_max_backoff_ms, 5000},
    {"max_pending_requests", "maxPendingRequests", &FilterConfig::max_pending_requests, 128},
};

constexpr std::string_view kFilterStringKeys[] = {"workload_api_cluster", "workloadApiCluster",
                                                 "expected_spiffe_id", "expectedSpiffeId",
                                                 "audiences", "header_name", "headerName"};

bool isPrintableNoSpace(std::string_view value) {
  if (value.empty()) {
    return false;
  }
  for (const char c : value) {
    const auto u = static_cast<unsigned char>(c);
    if (u <= 0x20 || u == 0x7f) {
      return false;
    }
  }
  return true;
}

bool isValidHeaderName(std::string_view value) {
  if (value.empty() || value.size() > 64 || value == "authorization" || value.front() == ':') {
    return false;
  }
  for (const char c : value) {
    const bool token_char = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                            c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
                            c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
                            c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
    if (!token_char) {
      return false;
    }
  }
  return true;
}

bool isValidClusterName(std::string_view value) {
  if (value.empty() || value.size() > 253) {
    return false;
  }
  for (const char c : value) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                    c == '_' || c == '-' || c == '.';
    if (!ok) {
      return false;
    }
  }
  return true;
}

bool isValidSpiffeId(std::string_view value) {
  constexpr std::string_view kScheme = "spiffe://";
  if (value.size() > 2048 || value.compare(0, kScheme.size(), kScheme) != 0) {
    return false;
  }
  const std::string_view rest = value.substr(kScheme.size());
  const size_t slash = rest.find('/');
  if (slash == std::string_view::npos || slash == 0 || slash + 1 >= rest.size()) {
    return false;
  }
  if (rest.back() == '/') {
    return false;
  }
  for (const char c : rest) {
    const auto u = static_cast<unsigned char>(c);
    if (u <= 0x20 || u == 0x7f) {
      return false;
    }
  }
  return rest.find("..") == std::string_view::npos;
}

bool isKnownFilterKey(const std::string& key) {
  if (std::find(std::begin(kFilterStringKeys), std::end(kFilterStringKeys), key) !=
      std::end(kFilterStringKeys)) {
    return true;
  }
  for (const auto& field : kUint32Fields) {
    if (key == field.snake || key == field.camel) {
      return true;
    }
  }
  return false;
}

bool readString(const Value& object, std::initializer_list<std::string_view> names, bool required,
                std::string& out, std::string& error) {
  for (const auto name : names) {
    const Value* value = object.find(name);
    if (value == nullptr) {
      continue;
    }
    if (value->type != Type::String) {
      error = "key '" + std::string(name) + "' must be a string";
      return false;
    }
    out = value->string_value;
    return true;
  }
  if (required) {
    error = "missing required key '" + std::string(*names.begin()) + "'";
    return false;
  }
  return true;
}

bool readUint32Fields(const Value& object, FilterConfig& cfg, std::string& error) {
  for (const auto& field : kUint32Fields) {
    const Value* value = object.find(field.snake);
    if (value == nullptr && !field.camel.empty()) {
      value = object.find(field.camel);
    }
    if (value == nullptr) {
      cfg.*field.member = field.fallback;
      continue;
    }
    if (value->type != Type::Number || !value->is_integer || value->integer_value < 0 ||
        value->integer_value > 0xffffffffLL) {
      error = "key '" + std::string(field.snake) + "' must be a non-negative integer";
      return false;
    }
    cfg.*field.member = static_cast<uint32_t>(value->integer_value);
  }
  return true;
}

bool validateFilterConfig(FilterConfig& cfg, std::string& error) {
  if (!isValidClusterName(cfg.workload_api_cluster)) {
    error = "workload_api_cluster must be a non-empty Envoy cluster name";
    return false;
  }
  if (!isValidSpiffeId(cfg.expected_spiffe_id)) {
    error = "expected_spiffe_id must be a spiffe:// URI with a path";
    return false;
  }
  if (!isValidHeaderName(cfg.header_name)) {
    error = "header_name must be a lowercase HTTP token of 1-64 characters, "
            "not a pseudo-header, and not authorization";
    return false;
  }
  if (cfg.audiences.empty() || cfg.audiences.size() > 8) {
    error = "audiences must list between 1 and 8 entries";
    return false;
  }
  std::sort(cfg.audiences.begin(), cfg.audiences.end());
  for (size_t i = 0; i < cfg.audiences.size(); ++i) {
    if (!isPrintableNoSpace(cfg.audiences[i]) || cfg.audiences[i].size() > 255) {
      error = "audience entries must be 1-255 printable characters without spaces";
      return false;
    }
    if (i > 0 && cfg.audiences[i] == cfg.audiences[i - 1]) {
      error = "audiences must not contain duplicates";
      return false;
    }
  }
  if (cfg.refresh_margin_seconds > 86400) {
    error = "refresh_margin_seconds must not exceed 86400";
    return false;
  }
  if (cfg.min_remaining_seconds > 3600) {
    error = "min_remaining_seconds must not exceed 3600";
    return false;
  }
  if (cfg.max_token_lifetime_seconds != 0 &&
      (cfg.max_token_lifetime_seconds < 60 || cfg.max_token_lifetime_seconds > 86400)) {
    error = "max_token_lifetime_seconds must be 0 or 60-86400";
    return false;
  }
  if (cfg.fetch_timeout_ms < 10 || cfg.fetch_timeout_ms > 30000) {
    error = "fetch_timeout_ms must be 10-30000";
    return false;
  }
  if (cfg.retry_initial_backoff_ms == 0 || cfg.retry_initial_backoff_ms > cfg.retry_max_backoff_ms ||
      cfg.retry_max_backoff_ms > 60000) {
    error =
        "retry backoff must satisfy 0 < retry_initial_backoff_ms <= retry_max_backoff_ms <= 60000";
    return false;
  }
  if (cfg.max_pending_requests == 0 || cfg.max_pending_requests > 100000) {
    error = "max_pending_requests must be 1-100000";
    return false;
  }
  return true;
}

} // namespace

bool FilterConfig::allowsAudience(std::string_view audience) const {
  return std::binary_search(audiences.begin(), audiences.end(), audience);
}

bool parseFilterConfig(std::string_view bytes, FilterConfig& out, std::string& error) {
  out = FilterConfig{};
  if (bytes.size() > kMaxConfigBytes) {
    error = "filter config exceeds the maximum size";
    return false;
  }
  if (bytes.find_first_not_of(" \t\r\n") == std::string_view::npos) {
    error = "empty filter config";
    return false;
  }
  Value doc;
  if (!json::parse(bytes, doc, error)) {
    return false;
  }
  if (doc.type != Type::Object) {
    error = "filter config must be a JSON object";
    return false;
  }
  for (const auto& entry : doc.object) {
    if (!isKnownFilterKey(entry.first)) {
      error = "unknown configuration key '" + entry.first + "'";
      return false;
    }
  }
  if (!readString(doc, {"workload_api_cluster", "workloadApiCluster"}, true,
                  out.workload_api_cluster, error) ||
      !readString(doc, {"expected_spiffe_id", "expectedSpiffeId"}, true, out.expected_spiffe_id,
                  error) ||
      !readString(doc, {"header_name", "headerName"}, false, out.header_name, error)) {
    return false;
  }
  const Value* audiences = doc.find("audiences");
  if (audiences == nullptr || audiences->type != Type::Array) {
    error = "audiences must be an array of strings";
    return false;
  }
  for (const auto& entry : audiences->array) {
    if (entry.type != Type::String) {
      error = "audiences must be an array of strings";
      return false;
    }
    out.audiences.push_back(entry.string_value);
  }
  if (!readUint32Fields(doc, out, error)) {
    return false;
  }
  return validateFilterConfig(out, error);
}

bool parsePerRouteConfig(std::string_view bytes, PerRouteConfig& out, std::string& error) {
  out = PerRouteConfig{};
  if (bytes.size() > kMaxConfigBytes) {
    error = "per-route config exceeds the maximum size";
    return false;
  }
  if (bytes.find_first_not_of(" \t\r\n") == std::string_view::npos) {
    return true;
  }
  Value doc;
  if (!json::parse(bytes, doc, error)) {
    return false;
  }
  if (doc.type != Type::Object) {
    error = "per-route config must be a JSON object";
    return false;
  }
  for (const auto& entry : doc.object) {
    if (entry.first != "enabled" && entry.first != "audience") {
      error = "unknown per-route key '" + entry.first + "'";
      return false;
    }
  }
  if (const Value* enabled = doc.find("enabled"); enabled != nullptr) {
    if (enabled->type != Type::Bool) {
      error = "enabled must be a boolean";
      return false;
    }
    out.enabled = enabled->bool_value;
  }
  if (!readString(doc, {"audience"}, false, out.audience, error)) {
    return false;
  }
  if (out.enabled && out.audience.empty()) {
    error = "an enabled route must name an audience";
    return false;
  }
  if (!out.enabled) {
    out.audience.clear();
  }
  return true;
}

} // namespace agrd::spire_jwt
