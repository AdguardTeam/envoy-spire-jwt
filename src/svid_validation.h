#pragma once

#include <cstdint>
#include <string>

namespace agrd::spire_jwt {

struct SvidValidation {
  bool ok{false};
  std::string error;
  int64_t expires_at{0};
  int64_t remaining_seconds{0};
  std::string svid;
};

// Decodes a JWTSVIDResponse and checks everything the filter trusts: exactly one
// eligible identity, the JWT subject, the requested audience, the remaining
// lifetime, and the lifetime cap. Kept free of Envoy types so every rejection
// path is unit tested.
SvidValidation validateSvidResponse(const std::string& body, const std::string& expected_spiffe_id,
                                    const std::string& audience, int64_t now_seconds,
                                    uint32_t min_remaining_seconds,
                                    uint32_t max_token_lifetime_seconds);

} // namespace agrd::spire_jwt
