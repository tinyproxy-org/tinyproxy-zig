# tinyproxy-zig

A Zig implementation of the [tinyproxy](https://github.com/tinyproxy/tinyproxy) HTTP/HTTPS proxy daemon.

Built on top of the [zio](https://github.com/lalinsky/zio) coroutine and async I/O framework.

## Design

- **Single-threaded coroutine model**: one coroutine per connection
- **Async I/O**: zio provides io_uring (Linux), kqueue (macOS), epoll fallback, iocp (Windows)
- **Feature parity goal**: implement all tinyproxy features in idiomatic Zig

## Features

### Phase 1: Infrastructure
- [x] Configuration file parsing (tinyproxy-compatible directives)
- [x] Logging system (file/stderr/syslog + rotation on SIGUSR1)

### Phase 2: Core Proxy
- [x] Forward proxy (HTTP)
- [x] HTTPS CONNECT tunnel
- [x] HTTP header processing (Via, hop-by-hop removal, response headers)
- [x] Anonymous mode (header whitelist)
- [x] Custom headers (AddHeader)

### Phase 3: Access Control
- [x] ACL (Allow/Deny by IP/subnet)
- [x] Basic Auth (with BasicAuthRealm)
- [x] Connect port restriction
- [x] URL/domain filtering (fnmatch, bre/ere patterns)

### Phase 4: Advanced Proxy Modes
- [x] Upstream proxy (HTTP + SOCKS4/SOCKS5 + NoUpstream)
- [x] Reverse proxy (ReversePath, ReverseOnly, ReverseMagic, ReverseBaseURL)
- [x] Transparent proxy (Linux SO_ORIGINAL_DST)

### Phase 5: Production
- [x] Statistics page (StatHost, StatFile)
- [x] Signal handling (SIGTERM/SIGINT/SIGUSR1/SIGHUP)
- [x] Config reload on SIGHUP (runtime settings reload; Listen/Port changes require restart)
- [x] Daemon mode (daemonize, PID file, privilege drop)
- [x] Custom error pages (ErrorFile, DefaultErrorFile)

## Quick Start

### Build

```shell
zig build
```

### Run

```shell
zig build run
```

Proxy will listen on `127.0.0.1:9999` (see `src/config.zig`).

### Test

```shell
# Run unit tests
zig build test

# Test HTTP proxy
curl -x http://127.0.0.1:9999 http://ipinfo.io/ip

# Test HTTPS tunnel
curl -x http://127.0.0.1:9999 https://ipinfo.io/ip

# Benchmark
wrk -c 100 -t 4 http://127.0.0.1:9999
```

## Development

See project docs for detailed implementation plans.

### Project Structure

```
src/
├── main.zig          # Entry point
├── child.zig         # Connection accept loop
├── request.zig       # Request handling
├── relay.zig         # Bidirectional data relay
├── buffer.zig        # Line reader
├── config.zig        # Runtime configuration
└── ...
```

### Debugging

Use `mitmproxy` for HTTP layer inspection or `wireshark` for TCP layer.

## License

MIT License - Copyright Dacheng Gao
