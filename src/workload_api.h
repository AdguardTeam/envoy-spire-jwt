#pragma once

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace agrd::spire_jwt {

constexpr size_t kMaxWorkloadApiResponseBytes = 64 * 1024;

struct JwtSvid {
  std::string spiffe_id;
  std::string svid;
  std::string hint;
};

// protobuf encoding of spiffe.workload.v1.JWTSVIDRequest:
//   repeated string audience = 1; string spiffe_id = 2;
std::string encodeFetchJwtSvidRequest(std::string_view spiffe_id, std::string_view audience);

// gRPC framing of one unary message: 1 byte flags, 4 bytes big-endian length.
std::string grpcFrame(std::string_view message);

// Decodes spiffe.workload.v1.JWTSVIDResponse from a gRPC response body.
bool decodeFetchJwtSvidResponse(std::string_view body, std::vector<JwtSvid>& out,
                                std::string& error);

} // namespace agrd::spire_jwt
