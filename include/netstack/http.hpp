#pragma once

#include "netstack/stack.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace netstack {

struct HttpRequest {
  std::string method;
  std::string target;
  std::string version;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;
  // Header names are stored lowercase.
  std::string header(std::string_view name) const;
};

// Incremental HTTP/1.x request parser. One message at a time; bytes after
// the message stay buffered for the next take().
class HttpParser {
 public:
  void feed(std::span<const std::uint8_t> data);
  bool complete() const { return complete_; }
  bool error() const { return error_; }
  HttpRequest take();

 private:
  std::string buf_;
  bool headers_done_ = false;
  bool complete_ = false;
  bool error_ = false;
  std::size_t body_need_ = 0;
  HttpRequest req_;
  bool parse_headers();
};

struct HttpResult {
  std::string bytes;
  bool close_after = false;
};

// Serves a tiny site on an already-listening socket. Call service() after
// each poll(); it never blocks.
class HttpApp {
 public:
  explicit HttpApp(Stack& stack);
  void service(TcpListener& listener);
  std::uint64_t requests() const { return requests_; }
  void set_download_cap(std::size_t n) { cap_ = n; }

  HttpResult respond(const HttpRequest& req) const;

 private:
  struct Conn {
    std::unique_ptr<TcpSocket> sock;
    HttpParser parser;
    std::string pending;
    std::size_t off = 0;
    bool close_after = false;
    bool done = false;
  };
  void flush(Conn& c);
  Stack* stack_;
  std::vector<Conn> conns_;
  std::uint64_t requests_ = 0;
  std::size_t cap_ = 8 * 1024 * 1024;
};

}  // namespace netstack
