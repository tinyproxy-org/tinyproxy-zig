# Agent Development Guide

## Project Overview

**tinyproxy-zig** is a Zig implementation of the tinyproxy HTTP/HTTPS proxy, built on top of the zio async I/O framework.

### Important: Rewrite Guidelines

This project is a **rewrite of tinyproxy in Zig**. When implementing features:

1. **Maintain Functional Parity**: Keep the same functionality as the original tinyproxy C implementation. Do not add, remove, or change behavior unless explicitly discussed.

2. **Idiomatic Zig Implementation**: While functionality must match, the implementation should be native Zig - use Zig idioms, error handling patterns, and standard library conventions rather than direct C-to-Zig translation.

3. **Preserve Module Structure**: Keep the same (or similar) module/file structure as the original tinyproxy. Each C source file should have a corresponding Zig module with equivalent responsibilities.

**Reference**: Always consult `../../tinyproxy/src/` for the original C implementation when implementing new features or debugging behavior differences.

## Tech Stack

- **Language**: Zig 0.16.0
- **Async Runtime**: zio (stackful coroutines + io_uring/kqueue/epoll)
- **Reference**: tinyproxy (C version) - functionality parity goal

## Code Style

- Follow Zig standard library conventions strictly
- Use `error union` and `optional` for error handling
- Avoid global mutable state (use dependency injection)
- Naming: `snake_case` for functions/variables, `PascalCase` for types
- Documentation: use `///` doc comments for public APIs

## Architecture

- **Single-threaded coroutine model**: one coroutine per connection
- **Modular design**: each feature is a separate `.zig` file
- **Configuration-driven**: all features controllable via config file

## Common Tasks

### Adding a new feature

1. Create `src/<feature>.zig`
2. Add config options to `conf.zig`
3. Integrate into `request.zig` processing pipeline
4. Update README.md feature checklist

### Debugging

- Use `std.log.scoped` for module-specific logging
- Enable debug allocator in `main.zig`

## Reference Repositories

- **tinyproxy (C)**: `../../tinyproxy` - functionality reference
- **zio**: `../../dacheng-zig/zio` - async I/O library
