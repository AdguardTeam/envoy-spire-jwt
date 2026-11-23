#include "svid_validation.h"

#include <string_view>
#include <utility>
#include <vector>

#include "jwt_claims.h"
#include "workload_api.h"

namespace agrd::spire_jwt {
namespace {

SvidValidation reject(std::string error) {
  SvidValidation result;
  result.error = std::move(error);
  return result;
}

} // namespace

SvidValidation validateSvidResponse(const std::string& body, const std::string& expected_spiffe_id,
                                    const std::string& audience, int64_t now_seconds,
                                    uint32_t min_remaining_seconds,
                                    uint32_t max_token_lifetime_seconds) {
  std::vector<JwtSvid> svids;
  std::string error;
  if (!decodeFetchJwtSvidResponse(body, svids, error)) {
    return reject("Workload API response rejected: " + error);
  }
  const JwtSvid* match = nullptr;
  for (const auto& svid : svids) {
    if (svid.spiffe_id != expected_spiffe_id) {
      continue;
    }
    if (match != nullptr) {
      return reject("Workload API returned more than one eligible JWT-SVID");
    }
    match = &svid;
  }
  if (match == nullptr) {
    return reject("Workload API returned an unexpected SPIFFE ID");
  }
  JwtClaims claims;
  if (!parseJwtClaims(match->svid, claims, error)) {
    return reject("JWT-SVID claims rejected: " + error);
  }
  if (claims.subject != expected_spiffe_id) {
    return reject("JWT-SVID subject does not match the configured SPIFFE ID");
  }
  if (!containsAudience(claims.audiences, audience)) {
    return reject("JWT-SVID does not carry the requested audience");
  }
  const int64_t remaining = claims.expires_at - now_seconds;
  if (remaining <= static_cast<int64_t>(min_remaining_seconds)) {
    return reject("JWT-SVID expires too soon to be used");
  }
  if (max_token_lifetime_seconds != 0) {
    const int64_t issued_at = claims.has_iat ? claims.issued_at : now_seconds;
    if (claims.expires_at - issued_at > static_cast<int64_t>(max_token_lifetime_seconds)) {
      return reject("JWT-SVID lifetime exceeds max_token_lifetime_seconds");
    }
  }
  SvidValidation result;
  result.ok = true;
  result.expires_at = claims.expires_at;
  result.remaining_seconds = remaining;
  result.svid = match->svid;
  return result;
}

} // namespace agrd::spire_jwt
