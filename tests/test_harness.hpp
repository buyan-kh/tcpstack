#pragma once

#include <cstdlib>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

struct TestFailure : std::exception {
  std::string msg;
  explicit TestFailure(std::string m) : msg(std::move(m)) {}
  const char* what() const noexcept override { return msg.c_str(); }
};

struct TestSkip : std::exception {};

inline std::vector<std::pair<const char*, void (*)()>>& test_registry() {
  static std::vector<std::pair<const char*, void (*)()>> tests;
  return tests;
}

struct TestReg {
  TestReg(const char* name, void (*fn)()) { test_registry().push_back({name, fn}); }
};

#define TEST(name)                 \
  void name();                     \
  static TestReg reg_##name {      \
#name, &name                   \
  }                                \
  ;                                \
  void name()

#define EXPECT(cond)                                                                 \
  do {                                                                               \
    if (!(cond))                                                                     \
      throw TestFailure(std::string(#cond) + " @ " + __FILE__ + ":" + std::to_string(__LINE__)); \
  } while (0)

template <typename A, typename B>
void expect_eq_impl(const A& a, const B& b, const char* expr, const char* file, int line) {
  if (a == b) return;
  std::ostringstream os;
  os << expr << " (" << a << " vs " << b << ") @ " << file << ":" << line;
  throw TestFailure(os.str());
}

#define EXPECT_EQ(a, b) expect_eq_impl((a), (b), #a " == " #b, __FILE__, __LINE__)
