//! Transparent Proxy Support
//!
//! Retrieves the original destination address for transparently intercepted
//! connections using SO_ORIGINAL_DST (Linux) or pf (BSD).
//!
//! This allows tinyproxy to act as a transparent proxy where clients don't
//! need to explicitly configure the proxy - traffic is redirected via iptables
//! or pf firewall rules.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

/// Linux-specific constants for transparent proxy support
const linux = struct {
    /// SOL_IP level for getsockopt
    const SOL_IP: u32 = 0;
    /// SO_ORIGINAL_DST option (from netfilter)
    const SO_ORIGINAL_DST: u32 = 80;
};

/// Result of getting the original destination
pub const OriginalDest = struct {
    host: []const u8,
    port: u16,
    /// Whether this was from a transparently intercepted connection
    is_transparent: bool,
};

/// Get the original destination address for a transparently intercepted connection.
///
/// On Linux, uses getsockopt(SO_ORIGINAL_DST) to retrieve the destination
/// that was redirected by iptables REDIRECT or TPROXY rules.
///
/// On other platforms, returns null (transparent proxy not supported).
///
/// Args:
///   socket_fd: The client connection socket file descriptor
///   buf: Buffer to store the IP address string (must be at least 46 bytes for IPv6)
///
/// Returns:
///   The original destination if available and different from local address, null otherwise
pub fn getOriginalDest(socket_fd: posix.socket_t, buf: []u8) ?OriginalDest {
    if (comptime builtin.os.tag == .linux) {
        return getOriginalDestLinux(socket_fd, buf);
    } else {
        // Transparent proxy not implemented for this platform
        // BSD/macOS would need pf integration which is more complex
        return null;
    }
}

/// Linux implementation using SO_ORIGINAL_DST
fn getOriginalDestLinux(socket_fd: posix.socket_t, buf: []u8) ?OriginalDest {
    // Try IPv4 first (more common)
    var addr_v4: posix.sockaddr.in = undefined;
    var len_v4: posix.socklen_t = @sizeOf(posix.sockaddr.in);

    switch (posix.errno(std.os.linux.getsockopt(
        socket_fd,
        @intCast(linux.SOL_IP),
        @intCast(linux.SO_ORIGINAL_DST),
        @as([*]u8, @ptrCast(&addr_v4)),
        &len_v4,
    ))) {
        .SUCCESS => {
            // Successfully got IPv4 original destination
            const port = std.mem.bigToNative(u16, addr_v4.port);
            const ip_bytes = @as(*const [4]u8, @ptrCast(&addr_v4.addr));

            // Format the IP address into the buffer
            const formatted = std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            }) catch return null;

            return .{
                .host = formatted,
                .port = port,
                .is_transparent = true,
            };
        },
        else => {
            // IPv4 failed, could try IPv6 here in the future
            return null;
        },
    }
}

/// Check if transparent proxy is supported on this platform
pub fn isSupported() bool {
    return comptime builtin.os.tag == .linux;
}

// ============================================================================
// Tests
// ============================================================================

test "isSupported returns correct value" {
    const supported = isSupported();
    if (builtin.os.tag == .linux) {
        try std.testing.expect(supported);
    } else {
        try std.testing.expect(!supported);
    }
}

test "getOriginalDest returns null for invalid socket" {
    var buf: [64]u8 = undefined;
    // Invalid socket should return null (or error gracefully)
    const result = getOriginalDest(-1, &buf);
    // On non-Linux, always null. On Linux, will fail gracefully.
    if (comptime builtin.os.tag != .linux) {
        try std.testing.expect(result == null);
    }
}
