const std = @import("std");
const mem = std.mem;
const net = std.net;
const posix = std.posix;
const zio = @import("zio");

const Config = @import("config.zig").Config;

const log = std.log.scoped(.socket);

/// Connect to target with optional local address binding.
/// Uses zio's async connect — does not block the coroutine runtime.
/// If bind_addr is provided, the socket is bound to that local address before connecting.
pub fn connectWithBind(
    _: *zio.Runtime,
    target_addr: zio.net.IpAddress,
    bind_addr: ?[]const u8,
) !zio.net.Stream {
    // If no bind address, use standard async connect
    const bind_ip = bind_addr orelse return target_addr.connect(.{});

    // Open socket matching target address family
    var socket = try zio.net.Socket.open(.stream, .fromPosix(target_addr.any.family), .ip);
    errdefer socket.close();

    // Parse and bind to local address (port 0 = OS assigns ephemeral port).
    // tinyproxy behavior: when bind address is explicitly requested, bind failure
    // aborts this connection attempt.
    const local_addr = try zio.net.IpAddress.parseIp(bind_ip, 0);
    try socket.bind(.{ .ip = local_addr });

    // Async connect via zio event loop — yields to other coroutines while waiting
    try socket.connect(.{ .ip = target_addr }, .{});

    return .{ .socket = socket };
}

/// Connect to target trying each bind address until one succeeds.
/// Returns an error if none can be used.
pub fn connectWithBindList(
    _: *zio.Runtime,
    target_addr: zio.net.IpAddress,
    bind_addrs: []const []const u8,
) !zio.net.Stream {
    if (bind_addrs.len == 0) return target_addr.connect(.{});

    var last_err: ?anyerror = null;
    for (bind_addrs) |bind_ip| {
        var socket = try zio.net.Socket.open(.stream, .fromPosix(target_addr.any.family), .ip);
        errdefer socket.close();

        const local_addr = zio.net.IpAddress.parseIp(bind_ip, 0) catch |err| {
            last_err = err;
            continue;
        };

        socket.bind(.{ .ip = local_addr }) catch |err| {
            last_err = err;
            continue;
        };

        socket.connect(.{ .ip = target_addr }, .{}) catch |err| {
            last_err = err;
            continue;
        };
        return .{ .socket = socket };
    }

    if (last_err) |err| {
        log.warn("Failed to bind/connect using configured bind addresses: {}", .{err});
        return err;
    }
    return error.AddressNotAvailable;
}

/// get peer (remote) address from the socket
/// Returns true if successful, false on error
pub fn get_peer_addr(sock: posix.socket_t, addr: *net.Address) bool {
    var addr_len: posix.socklen_t = @sizeOf(net.Address);
    return posix.getpeername(sock, &addr.any, &addr_len) == null;
}

/// get local address from the socket and format to string (IP only, no port)
/// Returns the formatted string, or null on error
pub fn get_local_addr_str(sock: posix.socket_t, buf: []u8) ?[]const u8 {
    var storage: posix.sockaddr.storage = undefined;
    var addr_len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    posix.getsockname(sock, @ptrCast(&storage), &addr_len) catch return null;

    // Validate minimum buffer size (IPv4 max 15 chars + null, IPv6 needs more)
    if (buf.len < 46) return null; // Max IPv6 string length

    // Get address family and format IP only (without port)
    const family = storage.family;
    if (family == posix.AF.INET) {
        const addr4: *const posix.sockaddr.in = @ptrCast(&storage);
        const bytes: *const [4]u8 = @ptrCast(&addr4.addr);
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ bytes[0], bytes[1], bytes[2], bytes[3] }) catch return null;
    } else if (family == posix.AF.INET6) {
        const addr6: *const posix.sockaddr.in6 = @ptrCast(&storage);
        // Format IPv6 address (RFC 5952: lowercase, no unnecessary leading zeros)
        return std.fmt.bufPrint(buf,
            "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}",
            .{
                addr6.addr[0], addr6.addr[1], addr6.addr[2], addr6.addr[3],
                addr6.addr[4], addr6.addr[5], addr6.addr[6], addr6.addr[7],
                addr6.addr[8], addr6.addr[9], addr6.addr[10], addr6.addr[11],
                addr6.addr[12], addr6.addr[13], addr6.addr[14], addr6.addr[15],
            },
        ) catch return null;
    }
    return null;
}

/// set the socket send and receive timeout
pub fn set_socket_timeout(sock: posix.socket_t, idle_timeout: u32) !void {
    var timespec: posix.timespec = .{
        .sec = idle_timeout,
        .nsec = 0,
    };
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.SNDTIMEO, mem.asBytes(&timespec));
    try posix.setsockopt(sock, posix.SOL.SOCKET, posix.SO.RCVTIMEO, mem.asBytes(&timespec));
}

/// set the socket to blocking
pub fn set_socket_blocking(sock: posix.socket_t) !void {
    const flags = try posix.fcntl(sock, posix.F.GETFL, 0);

    // reinterpret the flags into posix.O, clear NONBLOCK, and cast back to usize
    var oflags: posix.O = @bitCast(@as(u32, @intCast(flags)));
    oflags.NONBLOCK = false;
    const new_flags: usize = @intCast(@as(u32, @bitCast(oflags)));

    _ = try posix.fcntl(sock, posix.F.SETFL, new_flags);
}
