#include "netstack/http.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace netstack {
namespace {

std::string lower(std::string_view s) {
  std::string o(s);
  for (char& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return o;
}

std::string reason(int code) {
  switch (code) {
    case 200: return "OK";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 413: return "Payload Too Large";
    default: return "Error";
  }
}

HttpResult respond_with(int code, std::string_view type, std::string body, bool close_after, bool head) {
  std::ostringstream o;
  o << "HTTP/1.1 " << code << ' ' << reason(code) << "\r\n"
    << "Server: netstack\r\n"
    << "Content-Type: " << type << "\r\n"
    << "Content-Length: " << body.size() << "\r\n"
    << "Connection: " << (close_after ? "close" : "keep-alive") << "\r\n"
    << "\r\n";
  if (!head) o << body;
  return HttpResult{o.str(), close_after};
}

std::optional<std::uint64_t> query_u64(std::string_view target, std::string_view key) {
  const auto q = target.find('?');
  if (q == std::string_view::npos) return std::nullopt;
  std::string_view qs = target.substr(q + 1);
  while (!qs.empty()) {
    auto amp = qs.find('&');
    auto part = qs.substr(0, amp);
    auto eq = part.find('=');
    if (eq != std::string_view::npos && part.substr(0, eq) == key) {
      try {
        return std::stoull(std::string(part.substr(eq + 1)));
      } catch (...) {
        return std::nullopt;
      }
    }
    if (amp == std::string_view::npos) break;
    qs.remove_prefix(amp + 1);
  }
  return std::nullopt;
}

}  // namespace

std::string HttpRequest::header(std::string_view name) const {
  const auto want = lower(name);
  for (const auto& [k, v] : headers) {
    if (k == want) return v;
  }
  return {};
}

bool HttpParser::parse_headers() {
  const auto end = buf_.find("\r\n\r\n");
  if (end == std::string::npos) return false;
  std::string head = buf_.substr(0, end);
  const std::string rest = buf_.substr(end + 4);
  std::size_t line_end = head.find("\r\n");
  std::string reqline = line_end == std::string::npos ? head : head.substr(0, line_end);
  std::istringstream rl(reqline);
  if (!(rl >> req_.method >> req_.target >> req_.version)) {
    error_ = true;
    return false;
  }
  std::string line;
  if (line_end != std::string::npos) {
    std::size_t pos = line_end + 2;
    while (pos < head.size()) {
      auto next = head.find("\r\n", pos);
      auto raw = head.substr(pos, next == std::string::npos ? std::string::npos : next - pos);
      auto colon = raw.find(':');
      if (colon != std::string::npos) {
        auto key = lower(std::string_view(raw).substr(0, colon));
        std::string val = raw.substr(colon + 1);
        while (!val.empty() && (val.front() == ' ' || val.front() == '\t')) val.erase(val.begin());
        req_.headers.emplace_back(std::move(key), std::move(val));
      }
      if (next == std::string::npos) break;
      pos = next + 2;
    }
  }
  headers_done_ = true;
  buf_ = rest;
  const auto cl = req_.header("content-length");
  body_need_ = 0;
  if (!cl.empty()) {
    try {
      body_need_ = static_cast<std::size_t>(std::stoull(cl));
    } catch (...) {
      error_ = true;
      return false;
    }
  }
  return true;
}

void HttpParser::feed(std::span<const std::uint8_t> data) {
  if (complete_ || error_ || data.empty()) return;
  buf_.append(reinterpret_cast<const char*>(data.data()), data.size());
  if (!headers_done_) {
    if (!parse_headers()) return;
  }
  if (buf_.size() >= body_need_) {
    req_.body = buf_.substr(0, body_need_);
    buf_.erase(0, body_need_);
    complete_ = true;
  }
}

HttpRequest HttpParser::take() {
  HttpRequest out = std::move(req_);
  const std::string leftover = std::move(buf_);
  req_ = {};
  buf_ = leftover;
  headers_done_ = false;
  complete_ = false;
  error_ = false;
  body_need_ = 0;
  if (!buf_.empty()) feed({});
  // feed ignores empty. Re-parse leftover by calling parse if headers present.
  if (!buf_.empty()) {
    // parse_headers / body using the leftover already in buf_.
    if (!headers_done_) {
      if (parse_headers() && buf_.size() >= body_need_) {
        req_.body = buf_.substr(0, body_need_);
        buf_.erase(0, body_need_);
        complete_ = true;
      }
    }
  }
  return out;
}

HttpApp::HttpApp(Stack& stack) : stack_(&stack) {}

HttpResult HttpApp::respond(const HttpRequest& req) const {
  const bool head = req.method == "HEAD";
  const bool get = req.method == "GET" || head;
  const auto conn = lower(req.header("connection"));
  const bool http10 = req.version == "HTTP/1.0";
  bool close_after = http10 || conn == "close";
  if (conn == "keep-alive") close_after = false;
  if (!get && req.method != "POST") {
    return respond_with(405, "text/plain; charset=utf-8", "method not allowed\n", true, false);
  }
  const auto path = req.target.substr(0, req.target.find('?'));
  if (path == "/download") {
    const auto n = query_u64(req.target, "n").value_or(1024);
    if (n > cap_) {
      return respond_with(413, "text/plain; charset=utf-8", "download cap exceeded\n", true, false);
    }
    std::string body(static_cast<std::size_t>(n), 'x');
    return respond_with(200, "application/octet-stream", std::move(body), close_after, head);
  }
  if (path == "/health") {
    return respond_with(200, "text/plain; charset=utf-8", "ok\n", close_after, head);
  }
  if (path == "/stats") {
    const auto& c = stack_->counters();
    std::ostringstream o;
    o << "rx_frames " << c.rx_frames << "\n"
      << "tx_frames " << c.tx_frames << "\n"
      << "rx_tcp " << c.rx_tcp << "\n"
      << "tx_tcp " << c.tx_tcp << "\n"
      << "retx " << c.tcp_retx << "\n"
      << "fast_retx " << c.tcp_fast_retx << "\n"
      << "timeouts " << c.tcp_timeouts << "\n"
      << "checksum_drops " << c.checksum_drops << "\n"
      << "frag_reassembled " << c.frag_reassembled << "\n"
      << "requests " << requests_ << "\n";
    return respond_with(200, "text/plain; charset=utf-8", o.str(), close_after, head);
  }
  if (path == "/") {
    const char* html =
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>netstack</title></head>"
        "<body><h1>netstack</h1><p>Userspace TCP/IP stack. This page was generated by the "
        "in-process HTTP server and delivered by its own TCP.</p>"
        "<ul><li><a href=\"/health\">/health</a></li>"
        "<li><a href=\"/stats\">/stats</a></li>"
        "<li><a href=\"/download?n=1048576\">/download?n=1048576</a></li></ul></body></html>";
    return respond_with(200, "text/html; charset=utf-8", html, close_after, head);
  }
  return respond_with(404, "text/plain; charset=utf-8", "not found\n", close_after, head);
}

void HttpApp::flush(Conn& c) {
  while (c.off < c.pending.size()) {
    auto r = c.sock->send(std::span<const std::uint8_t>(
        reinterpret_cast<const std::uint8_t*>(c.pending.data() + c.off), c.pending.size() - c.off));
    if (r.code != IoResult::Code::Ok || r.n == 0) break;
    c.off += r.n;
  }
  if (c.close_after && c.off >= c.pending.size() && !c.pending.empty()) {
    c.sock->close();
    c.done = true;
  }
}

void HttpApp::service(TcpListener& listener) {
  while (auto s = listener.accept_nb()) {
    Conn c;
    c.sock = std::move(s);
    conns_.push_back(std::move(c));
  }
  for (auto& c : conns_) {
    if (c.done || !c.sock) continue;
    std::uint8_t buf[8192];
    for (;;) {
      auto r = c.sock->recv(buf);
      if (r.code == IoResult::Code::WouldBlock) break;
      if (r.code == IoResult::Code::Closed || r.code == IoResult::Code::Reset) {
        c.done = true;
        break;
      }
      if (r.code != IoResult::Code::Ok) {
        c.done = true;
        break;
      }
      c.parser.feed({buf, r.n});
      if (c.parser.error()) {
        auto resp = respond_with(400, "text/plain; charset=utf-8", "bad request\n", true, false);
        c.pending += resp.bytes;
        c.close_after = true;
        break;
      }
      while (c.parser.complete()) {
        auto req = c.parser.take();
        auto resp = respond(req);
        c.pending += resp.bytes;
        c.close_after = resp.close_after;
        requests_++;
      }
    }
    flush(c);
  }
  conns_.erase(std::remove_if(conns_.begin(), conns_.end(), [](const Conn& c) { return c.done; }), conns_.end());
}

}  // namespace netstack
