const std = @import("std");
const zio = @import("zio");

const acl = @import("acl.zig");
const conf_parser = @import("conf.zig");
const daemon = @import("daemon.zig");
const logger = @import("log.zig");
const Config = @import("config.zig").Config;
const request = @import("request.zig");
const socket = @import("socket.zig");
const stats = @import("stats.zig");

const log = std.log.scoped(.child);

/// Error response for denied connections
const ERROR_403_DENIED = "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nAccess denied by ACL";
const ERROR_503_BUSY = "HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain\r\nContent-Length: 20\r\nConnection: close\r\n\r\nProxy at max clients";

var listen_servers: std.ArrayList(zio.net.Server) = .empty;
var listen_servers_allocator: ?std.mem.Allocator = null;

/// Active connection counter (atomic for thread safety)
var active_connections: std.atomic.Value(usize) = std.atomic.Value(usize).init(0);
var shutting_down: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

fn listeningPort(server: zio.net.Server) u16 {
    return server.socket.address.ip.getPort();
}

pub fn listen_socket(_: *zio.Runtime, config: *Config) !void {
    // Reset previous listeners if needed (defensive in tests/restarts).
    close_listen_sockets();
    listen_servers_allocator = config.allocator;
    errdefer {
        close_listen_sockets();
    }

    if (config.listen_addrs.items.len == 0) {
        // tinyproxy behavior: no Listen directive => wildcard listen.
        var bound_any = false;
        const any_v4 = zio.net.IpAddress.parseIp("0.0.0.0", config.port) catch unreachable;
        if (any_v4.listen(.{ .kernel_backlog = 1024, .reuse_address = true })) |server| {
            try listen_servers.append(config.allocator, server);
            bound_any = true;
            log.info("listening on 0.0.0.0:{d}", .{listeningPort(server)});
        } else |err| {
            log.warn("Failed to listen on 0.0.0.0:{d}: {}", .{ config.port, err });
        }

        const any_v6 = zio.net.IpAddress.parseIp("::", config.port) catch unreachable;
        if (any_v6.listen(.{ .kernel_backlog = 1024, .reuse_address = true })) |server| {
            try listen_servers.append(config.allocator, server);
            bound_any = true;
            log.info("listening on [::]:{d}", .{listeningPort(server)});
        } else |err| {
            log.warn("Failed to listen on [::]:{d}: {}", .{ config.port, err });
        }

        if (!bound_any) return error.AddressNotAvailable;
    } else {
        for (config.listen_addrs.items) |listen_addr| {
            const ip = try zio.net.IpAddress.parseIp(listen_addr, config.port);
            const server = try ip.listen(.{ .kernel_backlog = 1024, .reuse_address = true });
            try listen_servers.append(config.allocator, server);
            log.info("listening on {s}:{d}", .{ listen_addr, listeningPort(server) });
        }
    }

    // Drop privileges after binding (allows binding to privileged ports as root)
    if (config.user != null or config.group != null) {
        daemon.dropPrivileges(config.user, config.group) catch |err| {
            log.err("Failed to drop privileges: {}", .{err});
            return err;
        };
        if (config.user) |u| {
            log.info("Dropped privileges to user: {s}", .{u});
        }
    }
}

pub fn close_listen_sockets() void {
    for (listen_servers.items) |server| {
        server.close();
    }
    if (listen_servers_allocator) |alloc| {
        listen_servers.deinit(alloc);
        listen_servers = .empty;
        listen_servers_allocator = null;
    }
}

fn reloadConfigAndLogging(io: std.Io, config: *Config, config_path: []const u8) void {
    if (config_path.len == 0) {
        log.warn("SIGHUP received but no config file path is configured", .{});
        return;
    }

    conf_parser.reloadConfig(io, config, config_path) catch |err| {
        log.err("Config reload failed for '{s}': {}", .{ config_path, err });
        return;
    };

    // Match tinyproxy behavior: reload also reopens/reconfigures logging backend.
    logger.deinit();
    logger.init(io, config) catch |err| {
        log.err("Logger reinit failed after config reload: {}", .{err});
        return;
    };

    log.info("Configuration reloaded from '{s}'", .{config_path});
}

fn rotateLogFile(io: std.Io, config: *const Config) void {
    if (config.use_syslog) {
        // No file descriptor to reopen when syslog backend is active.
        log.info("SIGUSR1 received, ignoring reopen because syslog is enabled", .{});
        return;
    }

    const path = config.log_file orelse {
        log.info("SIGUSR1 received, but no log file configured", .{});
        return;
    };

    logger.reopen(io, path) catch |err| {
        log.err("Failed to reopen log file '{s}': {}", .{ path, err });
        return;
    };

    log.info("Log file reopened: '{s}'", .{path});
}

pub fn main_loop(rt: *zio.Runtime, io: std.Io, config: *Config, config_path: []const u8) !void {
    log.info("main_loop: starting main loop", .{});
    if (listen_servers.items.len == 0) return error.NotListening;
    shutting_down.store(false, .release);

    var accept_handles = std.ArrayList(zio.JoinHandle(void)).empty;
    defer {
        for (accept_handles.items) |*handle| {
            handle.cancel();
            _ = handle.join();
        }
        accept_handles.deinit(rt.allocator);
        close_listen_sockets();
    }
    for (listen_servers.items) |server| {
        const handle = try rt.spawn(acceptLoop, .{ rt, io, server, config });
        try accept_handles.append(rt.allocator, handle);
    }

    // Process signals in the main select loop.
    var sig_term = try zio.Signal.init(.terminate);
    defer sig_term.deinit();
    var sig_int = try zio.Signal.init(.interrupt);
    defer sig_int.deinit();
    var sig_hup = try zio.Signal.init(.hangup);
    defer sig_hup.deinit();
    var sig_usr1 = try zio.Signal.init(.user1);
    defer sig_usr1.deinit();

    // Safe reload policy:
    // active connection handlers receive a shared *Config. We defer deinit+swap
    // until there are no active handlers to avoid use-after-free.
    var reload_pending: bool = false;
    var tick: zio.Timeout = .{ .duration = .fromMilliseconds(200) };

    while (true) {
        if (reload_pending and active_connections.load(.acquire) == 0) {
            reload_pending = false;
            reloadConfigAndLogging(io, config, config_path);
        }

        const result = zio.select(.{
            .term = &sig_term,
            .int = &sig_int,
            .hup = &sig_hup,
            .usr1 = &sig_usr1,
            .tick = &tick,
        }) catch {
            log.info("Main loop interrupted, exiting...", .{});
            break;
        };

        switch (result) {
            .term, .int => {
                log.info("Shutdown requested, exiting...", .{});
                break;
            },
            .hup => {
                if (active_connections.load(.acquire) == 0) {
                    reloadConfigAndLogging(io, config, config_path);
                } else {
                    reload_pending = true;
                    log.info("SIGHUP received, deferring reload until active connections drain", .{});
                }
            },
            .usr1 => {
                rotateLogFile(io, config);
            },
            .tick => {},
        }
    }
    shutting_down.store(true, .release);
    close_listen_sockets();

    // Wait briefly for active connection handlers to drain (max 2s)
    {
        var attempts: u32 = 0;
        while (active_connections.load(.acquire) > 0 and attempts < 20) : (attempts += 1) {
            rt.sleep(.fromMilliseconds(100)) catch break;
        }
        const remaining = active_connections.load(.acquire);
        if (remaining > 0) {
            log.info("Shutting down with {d} active connections", .{remaining});
        }
    }

    log.info("Main loop exited", .{});
}

fn acceptLoop(rt: *zio.Runtime, io: std.Io, server: zio.net.Server, config: *Config) void {
    while (!shutting_down.load(.acquire)) {
        const stream = server.accept(.{}) catch |err| {
            if (shutting_down.load(.acquire)) break;
            log.err("accept failed on {f}: {}", .{ server.socket.address, err });
            continue;
        };
        handleAcceptedConnection(rt, io, stream, config);
    }
}

fn handleAcceptedConnection(rt: *zio.Runtime, io: std.Io, stream: zio.net.Stream, config: *Config) void {
    stats.global.recordOpen();

    // Check MaxClients limit
    const current_connections = active_connections.load(.acquire);
    if (current_connections >= config.max_clients) {
        log.info("MaxClients ({d}) reached, rejecting connection", .{config.max_clients});
        stats.global.recordRefused();
        stream.writeAll(ERROR_503_BUSY, .none) catch {};
        stream.close();
        stats.global.recordClose();
        return;
    }

    // Check ACL if rules are configured
    if (config.acl.hasRules()) {
        const client_addr = stream.socket.address.ip;
        const action = config.acl.check(client_addr);
        if (action == .deny) {
            log.info("Connection denied by ACL from {f}", .{stream.socket.address.ip});
            stats.global.recordRefused();
            stream.writeAll(ERROR_403_DENIED, .none) catch {};
            stream.close();
            stats.global.recordClose();
            return;
        }
    }

    // Set socket timeout for idle connections
    if (config.idle_timeout > 0) {
        socket.set_socket_timeout(stream.socket.handle, config.idle_timeout) catch |err| {
            log.warn("Failed to set socket timeout: {}", .{err});
        };
    }

    // Increment active connections before handing over ownership to handler.
    _ = active_connections.fetchAdd(1, .monotonic);

    _ = rt.spawn(handleConnectionWithCounter, .{ rt, io, stream, config }) catch |err| {
        _ = active_connections.fetchSub(1, .monotonic);
        stats.global.recordClose();
        stream.close();
        log.err("Failed to spawn connection handler: {}", .{err});
        return;
    };
    rt.yield() catch {};
}

/// Wrapper that handles connection and decrements counter on completion
fn handleConnectionWithCounter(rt: *zio.Runtime, io: std.Io, stream: zio.net.Stream, config: *const Config) void {
    defer {
        _ = active_connections.fetchSub(1, .monotonic);
        stats.global.recordClose();
    }
    request.handle_connection(rt, io, stream, config) catch |err| {
        if (isExpectedConnectionClose(err)) {
            log.debug("Connection closed: {}", .{err});
            return;
        }
        log.err("Connection handler error: {}", .{err});
    };
}

fn isExpectedConnectionClose(err: anyerror) bool {
    return err == error.EndOfStream;
}

pub fn accept_once(_: *zio.Runtime) !void {
    if (listen_servers.items.len == 0) return error.NotListening;
    const stream = try listen_servers.items[0].accept(.{});
    stream.close();
}

test "accepts one connection" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    var ready = zio.ResetEvent.init;

    var test_config = Config.init(gpa.allocator());
    try test_config.addListenAddress("127.0.0.1");
    test_config.port = 0;
    defer test_config.deinit();

    var server_task = try rt.spawn(struct {
        fn run(rt2: *zio.Runtime, ready2: *zio.ResetEvent, config: *Config) !void {
            try listen_socket(rt2, config);
            defer close_listen_sockets();
            ready2.set();
            try accept_once(rt2);
        }
    }.run, .{ rt, &ready, &test_config });

    try ready.wait();

    const listen_addr = listen_servers.items[0].socket.address.ip;
    var stream = try listen_addr.connect(.{});
    stream.close();

    try server_task.join();
}

test "logs actual assigned port when configured port is zero" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    var test_config = Config.init(gpa.allocator());
    try test_config.addListenAddress("127.0.0.1");
    test_config.port = 0;
    defer test_config.deinit();

    try listen_socket(rt, &test_config);
    defer close_listen_sockets();

    const actual_port = listen_servers.items[0].socket.address.ip.getPort();
    try std.testing.expect(actual_port != 0);
    try std.testing.expectEqual(actual_port, listeningPort(listen_servers.items[0]));
    try std.testing.expect(listeningPort(listen_servers.items[0]) != test_config.port);
}

test "connection handler treats EOF as normal close" {
    try std.testing.expect(isExpectedConnectionClose(error.EndOfStream));
    try std.testing.expect(!isExpectedConnectionClose(error.BadRequest));
}
