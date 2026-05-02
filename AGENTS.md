# Agent Development Guide

## Mission

`tinyproxy-zig` is a production-grade, 1:1 Zig implementation of the original tinyproxy C proxy daemon, built on `zio` async I/O.

The goal is functional parity, not product reinvention. Every directive, protocol behavior, response, error path, and edge case should match upstream tinyproxy unless a difference is explicitly approved and documented.

## Source of Truth

- Upstream behavior: `../tinyproxy/src/`
- Zig implementation: this repository
- Async runtime: `../zio`
- Zig version: `0.16.0`

Before implementing or changing behavior, inspect the corresponding C source and preserve the same externally observable semantics.

## Non-Negotiables

- Keep feature parity with tinyproxy C: do not add, remove, rename, or reinterpret behavior without explicit approval.
- Use idiomatic Zig: standard library conventions, explicit error unions, optionals, `defer`/`errdefer`, allocator ownership, and clear lifetimes.
- Use `zio` for async networking and coroutine orchestration; do not introduce a competing I/O model.
- Preserve the original module responsibilities where practical: each tinyproxy C source area should map to a clear Zig module.
- Keep changes small and local. Avoid broad rewrites, speculative abstractions, or cleanup unrelated to the requested behavior.
- Treat production safety as required: bounded parsing, deterministic cleanup, useful errors/logs, no leaks, no hidden global mutable state.

## Implementation Standards

- Prefer explicit state, dependency injection, and owned data over global mutable state.
- Validate all external input: config, HTTP syntax, headers, addresses, ports, paths, credentials, and upstream responses.
- Make resource ownership obvious for sockets, buffers, files, allocators, timers, and coroutine state.
- Hot paths must avoid avoidable allocation, copying, formatting, repeated parsing, and O(n^2) scans.
- Keep CPU and memory behavior predictable under many concurrent connections, slow clients, large headers, and relay backpressure.
- Use `std.log.scoped` for module logs; keep structured details useful for operations without exposing secrets.
- Public APIs should have concise `///` comments when they are part of a module contract.

## Verification

For every behavior change:

- Compare against upstream tinyproxy C behavior before coding.
- Add or update focused Zig tests for the changed module.
- Run `zig build test`; run `zig build` when build behavior or dependencies changed.
- For proxy behavior, verify with representative HTTP, HTTPS CONNECT, config, ACL/auth/filter/upstream/reverse, and failure-path cases as applicable.
- For performance-sensitive paths, check allocation count, unnecessary copies, relay throughput, and memory growth before claiming improvement.

Do not claim parity, production readiness, performance improvement, or test success without fresh evidence from the current workspace.

## Common Workflow

- New feature parity work: inspect upstream C, implement the matching Zig module behavior, integrate config/request flow, update README checklist if needed.
- Bug or mismatch: reproduce the Zig behavior, compare with upstream C, fix the smallest responsible module, add regression coverage.
- Refactor: preserve observable behavior exactly and prove it with existing or added tests.

## Project Shape

- `src/conf.zig` / `src/config.zig`: tinyproxy-compatible configuration parsing and runtime config.
- `src/request.zig`: request processing pipeline.
- `src/relay.zig`: bidirectional proxy relay and backpressure-sensitive data flow.
- `src/<feature>.zig`: focused modules matching tinyproxy feature areas.
