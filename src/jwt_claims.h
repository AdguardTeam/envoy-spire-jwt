#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace agrd::spire_jwt {

struct JwtClaims {
  std::string subject;
  std::vector<std::string> audiences;
  int64_t expires_at{0};
  int64_t issued_at{0};
  bool has_exp{false};
  bool has_iat{false};
};

// Reads claims from a JWS compact serialization. Signature verification is
// intentionally absent: SPIRE issued and signed the token, and the filter only
// consumes it. Parsing uses the same JSON reader as the filter configuration.
bool parseJwtClaims(std::string_view jwt, JwtClaims& out, std::string& error);

bool containsAudience(const std::vector<std::string>& audiences, std::string_view audience);

} // namespace agrd::spire_jwt
