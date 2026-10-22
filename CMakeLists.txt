cmake_minimum_required(VERSION 3.16)
project(netstack LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NETSTACK_SANITIZE "Build with AddressSanitizer and UBSan" OFF)

add_library(netstack
  src/device.cpp
  src/congestion.cpp
  src/ip.cpp
  src/tcp.cpp
  src/stack.cpp
)
target_include_directories(netstack PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_options(netstack PRIVATE -Wall -Wextra -Wpedantic -Werror -Wshadow)

add_executable(http_server apps/http_server.cpp src/http.cpp)
target_include_directories(http_server PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_link_libraries(http_server PRIVATE netstack)
target_compile_options(http_server PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(netstack_tests
  tests/test_main.cpp
  tests/test_checksum.cpp
  tests/test_ip.cpp
  tests/test_tcp.cpp
  tests/test_http.cpp
  src/http.cpp
)
target_include_directories(netstack_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_SOURCE_DIR}/tests)
target_link_libraries(netstack_tests PRIVATE netstack)
target_compile_options(netstack_tests PRIVATE -Wall -Wextra -Wpedantic -Werror)

if(NETSTACK_SANITIZE)
  foreach(tgt netstack http_server netstack_tests)
    target_compile_options(${tgt} PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(${tgt} PRIVATE -fsanitize=address,undefined)
  endforeach()
endif()

enable_testing()
add_test(NAME unit COMMAND netstack_tests)
set_tests_properties(unit PROPERTIES TIMEOUT 120)
