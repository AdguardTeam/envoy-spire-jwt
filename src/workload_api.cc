#include "workload_api.h"

#include <cstdint>

namespace agrd::spire_jwt {
namespace {

constexpr uint32_t kVarint = 0;
constexpr uint32_t kFixed64 = 1;
constexpr uint32_t kLengthDelimited = 2;
constexpr uint32_t kFixed32 = 5;

class Reader {
public:
  explicit Reader(std::string_view data) : data_(data) {}

  bool next(uint32_t& field, uint32_t& wire_type) {
    if (pos_ >= data_.size()) {
      return false;
    }
    uint64_t tag = 0;
    if (!varint(tag) || tag > 0xffffffffULL) {
      return fail();
    }
    field = static_cast<uint32_t>(tag >> 3);
    wire_type = static_cast<uint32_t>(tag & 0x7);
    if (field == 0) {
      return fail();
    }
    return true;
  }

  bool bytes(std::string_view& out) {
    uint64_t length = 0;
    if (!varint(length) || length > data_.size() - pos_) {
      return fail();
    }
    out = data_.substr(pos_, static_cast<size_t>(length));
    pos_ += static_cast<size_t>(length);
    return true;
  }

  bool skip(uint32_t wire_type) {
    std::string_view ignored;
    switch (wire_type) {
    case kVarint: {
      uint64_t value = 0;
      return varint(value);
    }
    case kFixed64:
      return take(8);
    case kLengthDelimited:
      return bytes(ignored);
    case kFixed32:
      return take(4);
    default:
      return fail();
    }
  }

  bool failed() const { return failed_; }

private:
  bool take(size_t count) {
    if (count > data_.size() - pos_) {
      return fail();
    }
    pos_ += count;
    return true;
  }

  bool varint(uint64_t& value) {
    uint64_t result = 0;
    for (uint32_t shift = 0; shift < 64; shift += 7) {
      if (pos_ >= data_.size()) {
        return fail();
      }
      const auto byte = static_cast<uint8_t>(data_[pos_++]);
      result |= static_cast<uint64_t>(byte & 0x7f) << shift;
      if ((byte & 0x80) == 0) {
        value = result;
        return true;
      }
    }
    return fail();
  }

  bool fail() {
    failed_ = true;
    return false;
  }

  std::string_view data_;
  size_t pos_{0};
  bool failed_{false};
};

void putVarint(std::string& out, uint64_t value) {
  while (value >= 0x80) {
    out.push_back(static_cast<char>((value & 0x7f) | 0x80));
    value >>= 7;
  }
  out.push_back(static_cast<char>(value));
}

void putBytes(std::string& out, uint32_t field, std::string_view value) {
  putVarint(out, (static_cast<uint64_t>(field) << 3) | kLengthDelimited);
  putVarint(out, value.size());
  out.append(value);
}

bool parseJwtSvid(std::string_view message, JwtSvid& out, std::string& error) {
  Reader reader(message);
  uint32_t field = 0;
  uint32_t wire_type = 0;
  while (reader.next(field, wire_type)) {
    if (field >= 1 && field <= 3) {
      std::string_view text;
      if (wire_type != kLengthDelimited || !reader.bytes(text)) {
        error = "malformed JWTSVID";
        return false;
      }
      if (field == 1) {
        out.spiffe_id = std::string(text);
      } else if (field == 2) {
        out.svid = std::string(text);
      } else {
        out.hint = std::string(text);
      }
      continue;
    }
    if (!reader.skip(wire_type)) {
      error = "malformed JWTSVID";
      return false;
    }
  }
  if (reader.failed()) {
    error = "malformed JWTSVID";
    return false;
  }
  if (out.spiffe_id.empty() || out.svid.empty()) {
    error = "JWTSVID is missing spiffe_id or svid";
    return false;
  }
  return true;
}

} // namespace

std::string encodeFetchJwtSvidRequest(std::string_view spiffe_id, std::string_view audience) {
  std::string message;
  putBytes(message, 1, audience);
  putBytes(message, 2, spiffe_id);
  return message;
}

std::string grpcFrame(std::string_view message) {
  std::string framed(5, '\0');
  const auto length = static_cast<uint32_t>(message.size());
  framed[1] = static_cast<char>((length >> 24) & 0xff);
  framed[2] = static_cast<char>((length >> 16) & 0xff);
  framed[3] = static_cast<char>((length >> 8) & 0xff);
  framed[4] = static_cast<char>(length & 0xff);
  framed.append(message);
  return framed;
}

bool decodeFetchJwtSvidResponse(std::string_view body, std::vector<JwtSvid>& out,
                                std::string& error) {
  out.clear();
  if (body.size() > kMaxWorkloadApiResponseBytes) {
    error = "Workload API response exceeds the size limit";
    return false;
  }
  if (body.size() < 5) {
    error = "Workload API response is shorter than a gRPC frame header";
    return false;
  }
  if (body[0] != 0) {
    error = "compressed gRPC responses are not supported";
    return false;
  }
  const auto byte = [&](size_t i) { return static_cast<uint32_t>(static_cast<uint8_t>(body[i])); };
  const uint32_t length = (byte(1) << 24) | (byte(2) << 16) | (byte(3) << 8) | byte(4);
  if (static_cast<size_t>(length) + 5 > body.size()) {
    error = "truncated gRPC frame";
    return false;
  }
  Reader reader(body.substr(5, length));
  uint32_t field = 0;
  uint32_t wire_type = 0;
  while (reader.next(field, wire_type)) {
    if (field != 1) {
      if (!reader.skip(wire_type)) {
        error = "malformed JWTSVIDResponse";
        return false;
      }
      continue;
    }
    std::string_view svid_message;
    if (wire_type != kLengthDelimited || !reader.bytes(svid_message)) {
      error = "malformed JWTSVIDResponse";
      return false;
    }
    JwtSvid svid;
    if (!parseJwtSvid(svid_message, svid, error)) {
      return false;
    }
    out.push_back(std::move(svid));
  }
  if (reader.failed()) {
    error = "malformed JWTSVIDResponse";
    return false;
  }
  if (out.empty()) {
    error = "Workload API returned no JWT-SVID";
    return false;
  }
  return true;
}

} // namespace agrd::spire_jwt
