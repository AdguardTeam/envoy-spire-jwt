#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace agrd::spire_jwt::json {

enum class Type { Null, Bool, Number, String, Array, Object };

struct Value {
  Type type{Type::Null};
  bool bool_value{false};
  double number_value{0};
  int64_t integer_value{0};
  bool is_integer{false};
  std::string string_value;
  std::vector<Value> array;
  std::vector<std::pair<std::string, Value>> object;

  const Value* find(std::string_view key) const;
};

bool parse(std::string_view text, Value& out, std::string& error);

} // namespace agrd::spire_jwt::json
