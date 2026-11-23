#include "jwt_claims.h"

#include <algorithm>

#include "json.h"

namespace agrd::spire_jwt {
namespace {

int base64UrlValue(char c) {
  if (c >= 'A' && c <= 'Z') {
    return c - 'A';
  }
  if (c >= 'a' && c <= 'z') {
    return c - 'a' + 26;
  }
  if (c >= '0' && c <= '9') {
    return c - '0' + 52;
  }
  if (c == '-') {
    return 62;
  }
  if (c == '_') {
    return 63;
  }
  return -1;
}

bool base64UrlDecode(std::string_view in, std::string& out) {
  out.clear();
  out.reserve(in.size() * 3 / 4 + 3);
  uint32_t accumulator = 0;
  int bits = 0;
  for (const char c : in) {
    if (c == '=') {
      break;
    }
    const int value = base64UrlValue(c);
    if (value < 0) {
      return false;
    }
    accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((accumulator >> bits) & 0xff));
    }
  }
  return true;
}

bool splitJwt(std::string_view jwt, std::string_view& payload) {
  const size_t first = jwt.find('.');
  if (first == std::string_view::npos || first == 0) {
    return false;
  }
  const size_t second = jwt.find('.', first + 1);
  if (second == std::string_view::npos || second == first + 1 ||
      jwt.find('.', second + 1) != std::string_view::npos || second + 1 >= jwt.size()) {
    return false;
  }
  payload = jwt.substr(first + 1, second - first - 1);
  return true;
}

bool readInt(const json::Value& object, std::string_view key, int64_t& out, bool& present) {
  const json::Value* value = object.find(key);
  if (value == nullptr) {
    return true;
  }
  if (value->type != json::Type::Number || !value->is_integer) {
    return false;
  }
  out = value->integer_value;
  present = true;
  return true;
}

} // namespace

bool containsAudience(const std::vector<std::string>& audiences, std::string_view audience) {
  return std::find(audiences.begin(), audiences.end(), audience) != audiences.end();
}

bool parseJwtClaims(std::string_view jwt, JwtClaims& out, std::string& error) {
  out = JwtClaims{};
  std::string_view payload;
  if (!splitJwt(jwt, payload)) {
    error = "svid is not a JWS compact serialization";
    return false;
  }
  std::string decoded;
  if (!base64UrlDecode(payload, decoded)) {
    error = "svid payload is not base64url";
    return false;
  }
  json::Value doc;
  if (!json::parse(decoded, doc, error)) {
    error = "svid payload is not valid JSON: " + error;
    return false;
  }
  if (doc.type != json::Type::Object) {
    error = "svid payload is not a JSON object";
    return false;
  }
  if (const json::Value* subject = doc.find("sub");
      subject != nullptr && subject->type == json::Type::String) {
    out.subject = subject->string_value;
  }
  if (const json::Value* audience = doc.find("aud"); audience != nullptr) {
    if (audience->type == json::Type::String) {
      out.audiences.push_back(audience->string_value);
    } else if (audience->type == json::Type::Array) {
      for (const auto& entry : audience->array) {
        if (entry.type != json::Type::String) {
          error = "svid aud contains a non-string element";
          return false;
        }
        out.audiences.push_back(entry.string_value);
      }
    } else {
      error = "svid aud is neither a string nor an array";
      return false;
    }
  }
  if (!readInt(doc, "exp", out.expires_at, out.has_exp) ||
      !readInt(doc, "iat", out.issued_at, out.has_iat)) {
    error = "svid exp or iat is not an integer";
    return false;
  }
  if (!out.has_exp || out.expires_at <= 0) {
    error = "svid has no usable exp claim";
    return false;
  }
  return true;
}

} // namespace agrd::spire_jwt
