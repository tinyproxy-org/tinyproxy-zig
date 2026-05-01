//! Proxy Configuration Module
//!
//! Holds all runtime configuration for tinyproxy-zig.
//! Compatible with tinyproxy configuration format.

const std = @import("std");
const Acl = @import("acl.zig").Acl;
const BasicAuth = @import("auth.zig").BasicAuth;
const Filter = @import("filter.zig").Filter;
const ReverseProxy = @import("reverse.zig").ReverseProxy;
const UpstreamManager = @import("upstream.zig").UpstreamManager;

/// Logging level for proxy operations
pub const LogLevel = enum {
    critical,
    err,
    warning,
    notice,
    info,
    debug,
};

/// Port range for CONNECT restrictions
pub const PortRange = struct {
    min: u16,
    max: u16,

    pub fn contains(self: PortRange, port: u16) bool {
        return port >= self.min and port <= self.max;
    }

    pub fn single(port: u16) PortRange {
        return .{ .min = port, .max = port };
    }
};

/// Additional headers to append to outgoing requests.
pub const AddHeader = struct {
    name: []const u8,
    value: []const u8,
};

/// Main configuration structure
pub const Config = struct {
    allocator: std.mem.Allocator,

    // ========================================================================
    // Network Configuration
    // ========================================================================
    /// Incoming listen addresses (empty = wildcard listen)
    listen_addrs: std.ArrayList([]const u8) = undefined,
    listen_addrs_initialized: bool = false,
    port: u16 = 9999,
    /// Local addresses to bind outgoing connections to
    bind_addrs: std.ArrayList([]const u8) = undefined,
    bind_addrs_initialized: bool = false,
    /// Bind outgoing connections to same interface as incoming
    bind_same: bool = false,

    // ========================================================================
    // Connection Control
    // ========================================================================
    max_clients: usize = 100,
    idle_timeout: u32 = 600, // 10 minutes

    // ========================================================================
    // Via Header (Phase 2.2)
    // ========================================================================
    /// Custom proxy name for Via header (default: "tinyproxy")
    via_proxy_name: ?[]const u8 = null,
    via_proxy_name_owned: bool = false,
    /// Disable Via header entirely
    disable_via_header: bool = false,
    /// Add X-Tinyproxy header with client IP
    xtinyproxy: bool = false,

    // ========================================================================
    // Anonymous Mode (Phase 2.3)
    // ========================================================================
    /// Enable anonymous mode (filter client headers)
    anonymous_enabled: bool = false,
    /// Headers allowed in anonymous mode (lowercase)
    anonymous_headers: std.StringHashMap(void) = undefined,
    anonymous_headers_initialized: bool = false,

    // ========================================================================
    // CONNECT Port Restrictions (Phase 3.3)
    // ========================================================================
    /// Allowed ports for CONNECT method (empty = all allowed)
    connect_ports: std.ArrayList(PortRange) = undefined,
    connect_ports_initialized: bool = false,

    // ========================================================================
    // AddHeader (Phase 2.2.4)
    // ========================================================================
    add_headers: std.ArrayList(AddHeader) = undefined,
    add_headers_initialized: bool = false,

    // ========================================================================
    // Logging (Phase 1.2 - skeleton)
    // ========================================================================
    log_file: ?[]const u8 = null,
    log_file_owned: bool = false,
    log_level: LogLevel = .info,
    use_syslog: bool = false,

    // ========================================================================
    // Daemon Mode (Phase 5.3 - skeleton)
    // ========================================================================
    user: ?[]const u8 = null,
    user_owned: bool = false,
    group: ?[]const u8 = null,
    group_owned: bool = false,
    pid_file: ?[]const u8 = null,
    pid_file_owned: bool = false,

    // ========================================================================
    // ACL Access Control (Phase 3.1)
    // ========================================================================
    acl: Acl = undefined,
    acl_initialized: bool = false,

    // ========================================================================
    // Basic Auth (Phase 3.2)
    // ========================================================================
    auth: BasicAuth = undefined,
    auth_initialized: bool = false,

    // ========================================================================
    // Upstream Proxy (Phase 4.1)
    // ========================================================================
    upstream: UpstreamManager = undefined,
    upstream_initialized: bool = false,

    // ========================================================================
    // URL/Domain Filter (Phase 3.4)
    // ========================================================================
    filter: Filter = undefined,
    filter_initialized: bool = false,
    /// Path to filter file (stored for reload)
    filter_file: ?[]const u8 = null,
    filter_file_owned: bool = false,

    // ========================================================================
    // Statistics Page (Phase 5.1)
    // ========================================================================
    /// Host name for stats page (e.g., "tinyproxy.stats")
    stat_host: ?[]const u8 = null,
    stat_host_owned: bool = false,
    /// Custom stats page template file
    stat_file: ?[]const u8 = null,
    stat_file_owned: bool = false,

    // ========================================================================
    // Error Pages (Phase 5.4)
    // ========================================================================
    /// Default error page template file
    default_error_file: ?[]const u8 = null,
    default_error_file_owned: bool = false,
    /// Custom error files by HTTP status code (e.g., 404 => "/path/to/404.html")
    error_files: std.AutoHashMap(u16, []const u8) = undefined,
    error_files_initialized: bool = false,

    // ========================================================================
    // Reverse Proxy (Phase 4.2)
    // ========================================================================
    reverse: ReverseProxy = undefined,
    reverse_initialized: bool = false,

    // ========================================================================
    // Transparent Proxy (Phase 4.3)
    // ========================================================================
    /// Enable transparent proxy mode (use SO_ORIGINAL_DST)
    transparent: bool = false,

    const Self = @This();

    /// Initialize config with defaults
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .listen_addrs = std.ArrayList([]const u8).empty,
            .listen_addrs_initialized = true,
            .bind_addrs = std.ArrayList([]const u8).empty,
            .bind_addrs_initialized = true,
            .anonymous_headers = std.StringHashMap(void).init(allocator),
            .anonymous_headers_initialized = true,
            .connect_ports = std.ArrayList(PortRange).empty,
            .connect_ports_initialized = true,
            .add_headers = std.ArrayList(AddHeader).empty,
            .add_headers_initialized = true,
            .acl = Acl.init(allocator),
            .acl_initialized = true,
            .auth = BasicAuth.init(allocator),
            .auth_initialized = true,
            .upstream = UpstreamManager.init(allocator),
            .upstream_initialized = true,
            .filter = Filter.init(allocator),
            .filter_initialized = true,
            .error_files = std.AutoHashMap(u16, []const u8).init(allocator),
            .error_files_initialized = true,
            .reverse = ReverseProxy.init(allocator),
            .reverse_initialized = true,
        };
    }

    /// Deinitialize and free resources
    pub fn deinit(self: *Self) void {
        // Free listen/bind address lists.
        if (self.listen_addrs_initialized) {
            for (self.listen_addrs.items) |addr| {
                self.allocator.free(@constCast(addr));
            }
            self.listen_addrs.deinit(self.allocator);
        }
        if (self.bind_addrs_initialized) {
            for (self.bind_addrs.items) |addr| {
                self.allocator.free(@constCast(addr));
            }
            self.bind_addrs.deinit(self.allocator);
        }
        // Free owned strings
        if (self.via_proxy_name_owned) {
            if (self.via_proxy_name) |v| self.allocator.free(@constCast(v));
        }
        if (self.log_file_owned) {
            if (self.log_file) |v| self.allocator.free(@constCast(v));
        }
        if (self.user_owned) {
            if (self.user) |v| self.allocator.free(@constCast(v));
        }
        if (self.group_owned) {
            if (self.group) |v| self.allocator.free(@constCast(v));
        }
        if (self.pid_file_owned) {
            if (self.pid_file) |v| self.allocator.free(@constCast(v));
        }

        // Free anonymous headers
        if (self.anonymous_headers_initialized) {
            var it = self.anonymous_headers.keyIterator();
            while (it.next()) |key| {
                self.allocator.free(key.*);
            }
            self.anonymous_headers.deinit();
        }

        // Free connect ports
        if (self.connect_ports_initialized) {
            self.connect_ports.deinit(self.allocator);
        }

        // Free AddHeader entries
        if (self.add_headers_initialized) {
            for (self.add_headers.items) |entry| {
                self.allocator.free(@constCast(entry.name));
                self.allocator.free(@constCast(entry.value));
            }
            self.add_headers.deinit(self.allocator);
        }

        // Free ACL
        if (self.acl_initialized) {
            self.acl.deinit();
        }

        // Free BasicAuth
        if (self.auth_initialized) {
            self.auth.deinit();
        }

        // Free UpstreamManager
        if (self.upstream_initialized) {
            self.upstream.deinit();
        }

        // Free Filter
        if (self.filter_initialized) {
            self.filter.deinit();
        }
        if (self.filter_file_owned) {
            if (self.filter_file) |v| self.allocator.free(@constCast(v));
        }

        // Free stat_host and stat_file
        if (self.stat_host_owned) {
            if (self.stat_host) |v| self.allocator.free(@constCast(v));
        }
        if (self.stat_file_owned) {
            if (self.stat_file) |v| self.allocator.free(@constCast(v));
        }

        // Free error files
        if (self.default_error_file_owned) {
            if (self.default_error_file) |v| self.allocator.free(@constCast(v));
        }
        if (self.error_files_initialized) {
            var it = self.error_files.valueIterator();
            while (it.next()) |v| {
                self.allocator.free(@constCast(v.*));
            }
            self.error_files.deinit();
        }

        // Free reverse proxy
        if (self.reverse_initialized) {
            self.reverse.deinit();
        }
    }

    /// Add a listen address directive value.
    pub fn addListenAddress(self: *Self, addr: []const u8) !void {
        const duped = try self.allocator.dupe(u8, addr);
        errdefer self.allocator.free(duped);
        try self.listen_addrs.append(self.allocator, duped);
    }

    /// Add a bind address directive value.
    pub fn addBindAddress(self: *Self, addr: []const u8) !void {
        const duped = try self.allocator.dupe(u8, addr);
        errdefer self.allocator.free(duped);
        try self.bind_addrs.append(self.allocator, duped);
    }

    // ========================================================================
    // Anonymous Mode Helpers
    // ========================================================================

    /// Maximum number of anonymous headers allowed (DoS prevention)
    const MAX_ANONYMOUS_HEADERS: usize = 100;

    /// Add a header to the anonymous whitelist
    /// Uses lowercase for case-insensitive matching
    pub fn allowAnonymousHeader(self: *Self, header: []const u8) !void {
        // Check maximum number of headers to prevent DoS
        if (self.anonymous_headers.count() >= MAX_ANONYMOUS_HEADERS) {
            return error.TooManyHeaders;
        }

        // HTTP/1.1 spec limits header names to 8192 bytes (practical limit)
        // Use stack buffer for common cases, fall back to heap for long headers
        if (header.len <= 512) {
            var lower_buf: [512]u8 = undefined;
            for (header, 0..) |c, i| {
                lower_buf[i] = std.ascii.toLower(c);
            }

            // Check if already in whitelist
            if (self.anonymous_headers.contains(lower_buf[0..header.len])) {
                return; // Already exists, no need to allocate
            }

            // Allocate and store lowercase key
            const lower = try self.allocator.alloc(u8, header.len);
            @memcpy(lower, lower_buf[0..header.len]);
            try self.anonymous_headers.put(lower, {});
        } else {
            if (header.len > 8192) return error.HeaderTooLong;

            // Allocate and lowercase on heap
            const lower = try self.allocator.alloc(u8, header.len);
            for (header, 0..) |c, i| {
                lower[i] = std.ascii.toLower(c);
            }
            try self.anonymous_headers.put(lower, {});
        }
    }

    /// Check if a header is allowed in anonymous mode
    pub fn isAnonymousHeaderAllowed(self: *const Self, header: []const u8) bool {
        // Check case-insensitively
        // HTTP/1.1 spec limits header names to 8192 bytes
        if (header.len > 8192) return false;

        if (header.len <= 512) {
            var lower_buf: [512]u8 = undefined;
            for (header, 0..) |c, i| {
                lower_buf[i] = std.ascii.toLower(c);
            }
            return self.anonymous_headers.contains(lower_buf[0..header.len]);
        }

        // For long headers, allocate and check
        const lower = self.allocator.alloc(u8, header.len) catch return false;
        defer self.allocator.free(lower);
        for (header, 0..) |c, i| {
            lower[i] = std.ascii.toLower(c);
        }
        return self.anonymous_headers.contains(lower);
    }

    // ========================================================================
    // Connect Port Helpers
    // ========================================================================

    /// Add an allowed port for CONNECT
    pub fn allowConnectPort(self: *Self, port: u16) !void {
        try self.connect_ports.append(self.allocator, PortRange.single(port));
    }

    /// Add an allowed port range for CONNECT
    pub fn allowConnectPortRange(self: *Self, min: u16, max: u16) !void {
        try self.connect_ports.append(self.allocator, .{ .min = min, .max = max });
    }

    /// Check if a port is allowed for CONNECT
    /// Empty list means all ports allowed
    pub fn isConnectPortAllowed(self: *const Self, port: u16) bool {
        if (self.connect_ports.items.len == 0) return true;
        for (self.connect_ports.items) |range| {
            if (range.contains(port)) return true;
        }
        return false;
    }

    // ========================================================================
    // AddHeader Helpers
    // ========================================================================

    pub fn addHeader(self: *Self, name: []const u8, value: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);
        const value_copy = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(value_copy);
        try self.add_headers.append(self.allocator, .{ .name = name_copy, .value = value_copy });
    }

    // ========================================================================
    // Via Header Helpers
    // ========================================================================

    /// Get proxy name for Via header
    pub fn getProxyName(self: *const Self) []const u8 {
        return self.via_proxy_name orelse "tinyproxy";
    }

    // ========================================================================
    // Filter Helpers
    // ========================================================================

    /// Load filter patterns from file
    pub fn loadFilterFile(self: *Self, io: std.Io, path: []const u8) !void {
        try self.filter.loadFromFile(io, path);

        // Store path for potential reload
        const duped = try self.allocator.dupe(u8, path);
        if (self.filter_file_owned) {
            if (self.filter_file) |old| self.allocator.free(@constCast(old));
        }
        self.filter_file = duped;
        self.filter_file_owned = true;
    }

    /// Check if a URL/host should be filtered (blocked)
    pub fn isFiltered(self: *const Self, url: []const u8) bool {
        if (!self.filter.enabled) return false;

        const input = switch (self.filter.target) {
            .host => Filter.extractHost(url),
            .url => url,
        };

        return self.filter.isBlocked(input);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Config init and deinit" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 9999), config.port);
    try std.testing.expectEqual(@as(usize, 0), config.listen_addrs.items.len);
}

test "Config anonymous header whitelist" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try config.allowAnonymousHeader("Host");
    try config.allowAnonymousHeader("Accept");

    try std.testing.expect(config.isAnonymousHeaderAllowed("host"));
    try std.testing.expect(config.isAnonymousHeaderAllowed("HOST"));
    try std.testing.expect(config.isAnonymousHeaderAllowed("Accept"));
    try std.testing.expect(!config.isAnonymousHeaderAllowed("User-Agent"));
}

test "Config connect port restrictions" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    // Empty = all allowed
    try std.testing.expect(config.isConnectPortAllowed(80));
    try std.testing.expect(config.isConnectPortAllowed(443));
    try std.testing.expect(config.isConnectPortAllowed(8080));

    // Add restrictions
    try config.allowConnectPort(443);
    try config.allowConnectPort(563);
    try config.allowConnectPortRange(8000, 9000);

    try std.testing.expect(!config.isConnectPortAllowed(80));
    try std.testing.expect(config.isConnectPortAllowed(443));
    try std.testing.expect(config.isConnectPortAllowed(563));
    try std.testing.expect(config.isConnectPortAllowed(8080));
    try std.testing.expect(config.isConnectPortAllowed(8500));
    try std.testing.expect(!config.isConnectPortAllowed(9001));
}

test "Config via proxy name" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();

    try std.testing.expectEqualStrings("tinyproxy", config.getProxyName());

    config.via_proxy_name = "my-proxy";
    try std.testing.expectEqualStrings("my-proxy", config.getProxyName());
}
