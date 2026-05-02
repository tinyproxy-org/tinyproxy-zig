# tinyproxy-zig

`tinyproxy-zig` is a Zig implementation of the
[tinyproxy](https://github.com/tinyproxy/tinyproxy) HTTP/HTTPS proxy daemon.
It targets behavior compatibility with upstream tinyproxy while using
[zio](https://github.com/lalinsky/zio) for coroutine-based async I/O.

The project is parity-focused: do not treat it as a new proxy product or a
place to invent incompatible configuration, protocol, or error behavior.

## Status

Current code covers the main tinyproxy feature areas:

- HTTP forward proxy and HTTPS `CONNECT`
- tinyproxy-style configuration parsing
- ACLs, Basic authentication, anonymous header filtering, and `ConnectPort`
- request and response header handling, including `Via` and custom headers
- upstream HTTP, SOCKS4, SOCKS5, and `NoUpstream` routing
- reverse proxy paths, reverse-only mode, magic cookie support, and base URL rewriting
- URL/domain filtering, statistics pages, and custom error pages
- log files, stderr/syslog logging, `SIGUSR1` log reopen, and `SIGHUP` config reload
- daemon mode, PID files, privilege drop, and graceful shutdown handling
- Linux transparent proxy support through `SO_ORIGINAL_DST`

Known constraints:

- Zig `0.16.0` is required.
- The `zio` dependency is expected at `../zio` relative to this repository.
- Upstream tinyproxy C behavior remains the source of truth for parity work.
- Prefork directives are accepted for config compatibility but ignored by the
  single-threaded coroutine runtime.
- Transparent proxy mode is Linux-only.
- Production deployment should be validated against the exact target
  configuration, operating system, and traffic patterns before rollout.

## Build

```sh
zig build
```

The executable is installed at:

```sh
zig-out/bin/tinyproxy
```

For optimized builds:

```sh
zig build -Doptimize=ReleaseSafe
```

## Run

Run in the foreground with the example configuration:

```sh
zig build run -- -d -c tinyproxy.conf.example
```

Or run the installed binary:

```sh
zig-out/bin/tinyproxy -d -c tinyproxy.conf.example
```

Without `-d` / `--foreground`, the process daemonizes on Unix-like systems.
Without `-c`, built-in defaults are used.

Default settings include:

- listen address: wildcard when no `Listen` directive is configured
- port: `9999`
- max clients: `100`
- idle timeout: `600` seconds

## Configuration

Start from `tinyproxy.conf.example`. Supported directive families include:

- network: `Port`, `Listen`, `Bind`, `BindSame`, `Timeout`, `MaxClients`
- logging: `LogFile`, `Syslog`, `LogLevel`
- daemon: `User`, `Group`, `PidFile`
- proxy headers: `ViaProxyName`, `DisableViaHeader`, `XTinyproxy`, `AddHeader`
- access control: `Allow`, `Deny`, `BasicAuth`, `BasicAuthRealm`
- policy: `Anonymous`, `ConnectPort`, `Filter`, `FilterType`, `FilterDefaultDeny`
- routing: `Upstream`, `NoUpstream`, `ReversePath`, `ReverseOnly`,
  `ReverseMagic`, `ReverseBaseURL`, `Transparent`
- responses: `StatHost`, `StatFile`, `ErrorFile`, `DefaultErrorFile`

Unknown directives are rejected. Obsolete tinyproxy prefork directives are
ignored because this implementation uses a single-threaded coroutine model.

## Test

Run the Zig test suite:

```sh
zig build test
```

Basic manual checks:

```sh
curl -x http://127.0.0.1:9999 http://example.com/
curl -x http://127.0.0.1:9999 https://example.com/
```

For proxy behavior changes, compare the result with upstream tinyproxy C and
cover HTTP, `CONNECT`, config parsing, ACL/auth/filter/upstream/reverse, and
failure-path cases relevant to the change.

## Development

Repository layout:

```text
src/main.zig       process entry point and CLI options
src/conf.zig       tinyproxy-compatible config parser
src/config.zig     runtime configuration state
src/child.zig      listener, accept loop, signals, reload, shutdown
src/request.zig    request processing pipeline
src/relay.zig      bidirectional relay
src/upstream.zig   upstream proxy selection
src/reverse.zig    reverse proxy rewriting
```

Before changing behavior:

1. Inspect the matching upstream C implementation in `../tinyproxy/src/`.
2. Preserve externally observable tinyproxy semantics unless a difference is
   explicitly approved and documented.
3. Add or update focused Zig tests for the changed module.
4. Run `zig build test`; also run `zig build` when build behavior changes.

## License

MIT License.
