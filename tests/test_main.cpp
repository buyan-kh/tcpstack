#include "test_harness.hpp"

#include <iostream>

int main() {
  int failed = 0;
  int skipped = 0;
  for (auto& [name, fn] : test_registry()) {
    try {
      fn();
      std::cout << "ok   " << name << '\n';
    } catch (const TestSkip&) {
      std::cout << "skip " << name << '\n';
      ++skipped;
    } catch (const std::exception& ex) {
      std::cout << "FAIL " << name << " " << ex.what() << '\n';
      ++failed;
    }
  }
  std::cout << test_registry().size() << " tests, " << failed << " failed, " << skipped << " skipped\n";
  return failed == 0 ? 0 : 1;
}
