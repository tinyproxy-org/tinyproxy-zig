//! Upstream Proxy Management
//!
//! Handles parsing and selection of upstream proxies (HTTP/SOCKS).
//! Support for NoUpstream exceptions.

const std = @import("std");
const acl = @import("acl.zig");
const HostSpec = acl.HostSpec;

pub const ProxyType = enum {
    http,
    socks4,
    socks5,
};

pub const UpstreamProxy = struct {
    proxy_type: ProxyType,
    host: []const u8,
    port: u16,
    user: ?[]const u8 = null,
    pass: ?[]const u8 = null,
    /// Pre-encoded "user:pass" for HTTP Proxy-Authorization, when configured.
    auth_basic: ?[]const u8 = null,
};

pub const UpstreamManager = struct {
    allocator: std.mem.Allocator,
    rules: std.ArrayList(Rule),

    const Self = @This();
    const RuleTarget = union(enum) {
        proxy: UpstreamProxy,
        none,
    };
    const Rule = struct {
        /// Null means default rule.
        match: ?HostSpec = null,
        target: RuleTarget,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .rules = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.rules.items) |rule| {
            if (rule.match) |spec| spec.deinit(self.allocator);
            switch (rule.target) {
                .none => {},
                .proxy => |p| {
                    self.allocator.free(p.host);
                    if (p.user) |u| self.allocator.free(u);
                    if (p.pass) |pw| self.allocator.free(pw);
                    if (p.auth_basic) |auth| self.allocator.free(auth);
                },
            }
        }
        self.rules.deinit(self.allocator);
    }

    /// Add a NoUpstream rule
    pub fn addNoUpstream(self: *Self, spec_str: []const u8) !void {
        // Strip quotes if present
        const trimmed = std.mem.trim(u8, spec_str, " \t\"'");
        const spec = try HostSpec.parse(self.allocator, trimmed);
        errdefer spec.deinit(self.allocator);

        try self.rules.append(self.allocator, .{
            .match = spec,
            .target = .none,
        });
    }

    /// Add an Upstream rule
    /// Format:
    ///   - type (user:pass@)?host:port [domain]
    ///   - none domain
    pub fn addUpstream(self: *Self, value: []const u8) !void {
        var iter = std.mem.tokenizeAny(u8, value, " \t");

        // 1. Type
        const type_str = iter.next() orelse return error.InvalidUpstreamFormat;
        if (std.ascii.eqlIgnoreCase(type_str, "none")) {
            const spec_str = iter.next() orelse return error.InvalidUpstreamFormat;
            if (iter.next() != null) return error.InvalidUpstreamFormat;
            return self.addNoUpstream(spec_str);
        }
        const proxy_type: ProxyType = if (std.ascii.eqlIgnoreCase(type_str, "http"))
            .http
        else if (std.ascii.eqlIgnoreCase(type_str, "socks4"))
            .socks4
        else if (std.ascii.eqlIgnoreCase(type_str, "socks5"))
            .socks5
        else
            return error.InvalidProxyType;

        // 2. Address (user:pass@host:port)
        const addr_str = iter.next() orelse return error.InvalidUpstreamFormat;

        var user: ?[]const u8 = null;
        var pass: ?[]const u8 = null;
        var host_port_str = addr_str;

        // Check for user:pass@
        if (std.mem.lastIndexOfScalar(u8, addr_str, '@')) |at_pos| {
            const auth_part = addr_str[0..at_pos];
            host_port_str = addr_str[at_pos + 1 ..];

            if (std.mem.indexOfScalar(u8, auth_part, ':')) |colon_pos| {
                user = try self.allocator.dupe(u8, auth_part[0..colon_pos]);
                pass = try self.allocator.dupe(u8, auth_part[colon_pos + 1 ..]);
            } else {
                return error.InvalidUpstreamAddress;
            }
        }

        // Parse host:port
        var host_part: []const u8 = undefined;
        var port_part: []const u8 = undefined;
        if (std.mem.startsWith(u8, host_port_str, "[")) {
            const right_bracket = std.mem.indexOfScalar(u8, host_port_str, ']') orelse {
                if (user) |u| self.allocator.free(u);
                if (pass) |p| self.allocator.free(p);
                return error.InvalidUpstreamAddress;
            };
            if (right_bracket + 1 >= host_port_str.len or host_port_str[right_bracket + 1] != ':') {
                if (user) |u| self.allocator.free(u);
                if (pass) |p| self.allocator.free(p);
                return error.InvalidUpstreamAddress;
            }
            host_part = host_port_str[1..right_bracket];
            port_part = host_port_str[right_bracket + 2 ..];
        } else {
            const colon_pos = std.mem.lastIndexOfScalar(u8, host_port_str, ':') orelse {
                if (user) |u| self.allocator.free(u);
                if (pass) |p| self.allocator.free(p);
                return error.InvalidUpstreamAddress;
            };
            if (colon_pos == 0) {
                if (user) |u| self.allocator.free(u);
                if (pass) |p| self.allocator.free(p);
                return error.InvalidUpstreamAddress;
            }
            host_part = host_port_str[0..colon_pos];
            port_part = host_port_str[colon_pos + 1 ..];
        }
        if (host_part.len == 0 or port_part.len == 0) {
            // Clean up user/pass on error
            if (user) |u| self.allocator.free(u);
            if (pass) |p| self.allocator.free(p);
            return error.InvalidUpstreamAddress;
        }

        const host = try self.allocator.dupe(u8, host_part);
        errdefer self.allocator.free(host);

        const port = std.fmt.parseInt(u16, port_part, 10) catch {
            // Clean up user/pass/host on error
            if (user) |u| self.allocator.free(u);
            if (pass) |p| self.allocator.free(p);
            self.allocator.free(host);
            return error.InvalidPort;
        };
        if (port == 0) {
            if (user) |u| self.allocator.free(u);
            if (pass) |p| self.allocator.free(p);
            self.allocator.free(host);
            return error.InvalidPort;
        }

        // 3. Optional Match Spec
        var match: ?HostSpec = null;
        if (iter.next()) |match_str| {
            // Strip quotes
            const trimmed_match = std.mem.trim(u8, match_str, "\"'");
            match = HostSpec.parse(self.allocator, trimmed_match) catch |err| {
                // Clean up on parse error
                if (user) |u| self.allocator.free(u);
                if (pass) |p| self.allocator.free(p);
                self.allocator.free(host);
                return err;
            };
        }
        if (iter.next() != null) {
            if (match) |spec| spec.deinit(self.allocator);
            if (user) |u| self.allocator.free(u);
            if (pass) |p| self.allocator.free(p);
            self.allocator.free(host);
            return error.InvalidUpstreamFormat;
        }

        // tinyproxy C keeps only the first default upstream rule.
        if (match == null and self.hasDefaultProxy()) {
            if (user) |u| self.allocator.free(u);
            if (pass) |p| self.allocator.free(p);
            self.allocator.free(host);
            return;
        }

        var auth_basic: ?[]const u8 = null;
        if (proxy_type == .http and user != null) {
            auth_basic = encodeBasicAuth(self.allocator, user.?, pass orelse "") catch |err| {
                if (match) |spec| spec.deinit(self.allocator);
                if (user) |u| self.allocator.free(u);
                if (pass) |p| self.allocator.free(p);
                self.allocator.free(host);
                return err;
            };
        }

        errdefer {
            if (match) |spec| spec.deinit(self.allocator);
            if (user) |u| self.allocator.free(u);
            if (pass) |p| self.allocator.free(p);
            self.allocator.free(host);
            if (auth_basic) |auth| self.allocator.free(auth);
        }

        try self.rules.append(self.allocator, .{
            .match = match,
            .target = .{ .proxy = .{
                .proxy_type = proxy_type,
                .host = host,
                .port = port,
                .user = user,
                .pass = pass,
                .auth_basic = auth_basic,
            } },
        });
    }

    /// Find the best upstream for a given host.
    /// tinyproxy semantics:
    /// - last matching domain/netmask rule wins
    /// - default upstream (no match spec) is only a fallback
    pub fn findUpstream(self: *const Self, host: []const u8) ?*const UpstreamProxy {
        var default_proxy: ?*const UpstreamProxy = null;
        var i = self.rules.items.len;
        while (i > 0) {
            i -= 1;
            const rule = &self.rules.items[i];
            if (rule.match == null) {
                switch (rule.target) {
                    .none => {},
                    .proxy => |*p| {
                        if (default_proxy == null) default_proxy = p;
                    },
                }
                continue;
            }
            if (rule.match) |spec| {
                if (!spec.matchesHost(host)) {
                    continue;
                }
            }
            switch (rule.target) {
                .none => return null,
                .proxy => |*p| return p,
            }
        }

        return default_proxy;
    }

    fn hasDefaultProxy(self: *const Self) bool {
        for (self.rules.items) |rule| {
            if (rule.match != null) continue;
            switch (rule.target) {
                .none => {},
                .proxy => return true,
            }
        }
        return false;
    }
};

fn encodeBasicAuth(allocator: std.mem.Allocator, user: []const u8, pass: []const u8) ![]u8 {
    const raw = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ user, pass });
    defer allocator.free(raw);

    const encoded_len = std.base64.standard.Encoder.calcSize(raw.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(encoded, raw);
    return encoded;
}

// ============================================================================
// Tests
// ============================================================================

test "UpstreamManager basic http" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    try mgr.addUpstream("http 127.0.0.1:8080");

    const p = mgr.findUpstream("example.com");
    try std.testing.expect(p != null);
    try std.testing.expectEqual(ProxyType.http, p.?.proxy_type);
    try std.testing.expectEqualStrings("127.0.0.1", p.?.host);
    try std.testing.expectEqual(8080, p.?.port);
}

test "UpstreamManager auth and matching" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    // Specific rule for .onion
    try mgr.addUpstream("socks5 user:pass@127.0.0.1:9050 .onion");

    // Default rule
    try mgr.addUpstream("http 10.0.0.1:3128");

    // Check .onion
    const p1 = mgr.findUpstream("secret.onion");
    try std.testing.expect(p1 != null);
    try std.testing.expectEqual(ProxyType.socks5, p1.?.proxy_type);
    try std.testing.expectEqualStrings("user", p1.?.user.?);
    try std.testing.expectEqualStrings("pass", p1.?.pass.?);

    // Check others
    const p2 = mgr.findUpstream("google.com");
    try std.testing.expect(p2 != null);
    try std.testing.expectEqual(ProxyType.http, p2.?.proxy_type);
    try std.testing.expectEqualStrings("10.0.0.1", p2.?.host);
}

test "UpstreamManager no upstream" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    try mgr.addNoUpstream(".local");
    try mgr.addUpstream("http 10.0.0.1:8080");

    const p1 = mgr.findUpstream("my.local");
    try std.testing.expect(p1 == null);

    const p2 = mgr.findUpstream("google.com");
    try std.testing.expect(p2 != null);
}

test "UpstreamManager supports upstream none syntax" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    try mgr.addUpstream("none .internal");
    try mgr.addUpstream("http 10.0.0.1:8080");

    try std.testing.expect(mgr.findUpstream("svc.internal") == null);
    try std.testing.expect(mgr.findUpstream("example.com") != null);
}

test "UpstreamManager last matching rule wins" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    try mgr.addUpstream("http 10.0.0.1:8080 .example.com");
    try mgr.addUpstream("none .example.com");
    try std.testing.expect(mgr.findUpstream("www.example.com") == null);

    try mgr.addUpstream("http 10.0.0.2:8080 .example.com");
    const p = mgr.findUpstream("www.example.com");
    try std.testing.expect(p != null);
    try std.testing.expectEqualStrings("10.0.0.2", p.?.host);
}

test "UpstreamManager keeps first default upstream" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    try mgr.addUpstream("http 1.1.1.1:8000");
    try mgr.addUpstream("http 2.2.2.2:9000");

    const p = mgr.findUpstream("example.com");
    try std.testing.expect(p != null);
    try std.testing.expectEqualStrings("1.1.1.1", p.?.host);
    try std.testing.expectEqual(@as(u16, 8000), p.?.port);
}

test "UpstreamManager pre-encodes http proxy auth" {
    var mgr = UpstreamManager.init(std.testing.allocator);
    defer mgr.deinit();

    try mgr.addUpstream("http user:pass@127.0.0.1:3128");
    const p = mgr.findUpstream("example.com");
    try std.testing.expect(p != null);
    try std.testing.expect(p.?.auth_basic != null);
    try std.testing.expectEqualStrings("dXNlcjpwYXNz", p.?.auth_basic.?);
}
