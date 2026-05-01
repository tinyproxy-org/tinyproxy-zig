//! ACL (Access Control List) Module for tinyproxy-zig
//!
//! Implements IP address/subnet-based Allow/Deny rules.
//! Rules are evaluated in order, last matching rule wins.
//! If no rules match, the default action is deny.
//!
//! Supported formats:
//!   - Single IP: 127.0.0.1, ::1
//!   - CIDR: 192.168.0.0/16, fe80::/10
//!   - Domain suffix: .example.com (requires DNS lookup)
//!
//! Usage:
//!   var acl = Acl.init(allocator);
//!   defer acl.deinit();
//!   try acl.addRule("127.0.0.1", .allow);
//!   try acl.addRule("192.168.0.0/16", .allow);
//!   try acl.addRule("0.0.0.0/0", .deny);
//!   const action = acl.check(client_addr);

const std = @import("std");
const zio = @import("zio");

/// ACL action
pub const AclAction = enum {
    allow,
    deny,
};

/// Host specification for ACL matching
pub const HostSpec = union(enum) {
    /// Single IPv4 address
    ip4: [4]u8,
    /// IPv4 with CIDR prefix
    ip4_cidr: struct {
        addr: [4]u8,
        prefix_len: u5,
    },
    /// Single IPv6 address
    ip6: [16]u8,
    /// IPv6 with CIDR prefix
    ip6_cidr: struct {
        addr: [16]u8,
        prefix_len: u7,
    },
    /// Domain suffix (.example.com matches *.example.com)
    domain: []const u8,

    /// Parse a host specification from string
    pub fn parse(allocator: std.mem.Allocator, spec: []const u8) !HostSpec {
        const trimmed = std.mem.trim(u8, spec, " \t");

        // Check for domain (starts with '.')
        if (trimmed.len > 0 and trimmed[0] == '.') {
            const duped = try allocator.dupe(u8, trimmed);
            return .{ .domain = duped };
        }

        // Check for CIDR notation
        if (std.mem.indexOfScalar(u8, trimmed, '/')) |slash_pos| {
            const addr_part = trimmed[0..slash_pos];
            const prefix_str = trimmed[slash_pos + 1 ..];
            const prefix_len = std.fmt.parseInt(u8, prefix_str, 10) catch return error.InvalidPrefix;

            // Try IPv4 first
            if (parseIp4(addr_part)) |ip4_bytes| {
                if (prefix_len > 32) return error.InvalidPrefix;
                return .{ .ip4_cidr = .{
                    .addr = ip4_bytes,
                    .prefix_len = @intCast(prefix_len),
                } };
            }

            // Try IPv6
            if (parseIp6(addr_part)) |ip6_bytes| {
                if (prefix_len > 128) return error.InvalidPrefix;
                return .{ .ip6_cidr = .{
                    .addr = ip6_bytes,
                    .prefix_len = @intCast(prefix_len),
                } };
            }

            return error.InvalidAddress;
        }

        // Single IP address
        if (parseIp4(trimmed)) |ip4_bytes| {
            return .{ .ip4 = ip4_bytes };
        }

        if (parseIp6(trimmed)) |ip6_bytes| {
            return .{ .ip6 = ip6_bytes };
        }

        // Treat as domain if it contains '.' and isn't an IP
        if (std.mem.indexOfScalar(u8, trimmed, '.') != null) {
            const domain_spec = try allocator.alloc(u8, trimmed.len + 1);
            domain_spec[0] = '.';
            @memcpy(domain_spec[1..], trimmed);
            return .{ .domain = domain_spec };
        }

        return error.InvalidHostSpec;
    }

    /// Check if this spec matches the given address
    /// Note: Domain matching (.domain suffix) always returns false for Address matching
    /// because it requires a hostname string, not an IP address. Use matchesHost()
    /// for domain-based matching against hostname strings.
    pub fn matches(self: HostSpec, addr: zio.net.IpAddress) bool {
        return switch (self) {
            .ip4 => |ip4| matchIp4Single(ip4, addr),
            .ip4_cidr => |cidr| matchIp4Cidr(cidr.addr, cidr.prefix_len, addr),
            .ip6 => |ip6| matchIp6Single(ip6, addr),
            .ip6_cidr => |cidr| matchIp6Cidr(cidr.addr, cidr.prefix_len, addr),
            .domain => false, // Domain matching requires hostname string - use matchesHost() instead
        };
    }

    /// Check if this spec matches the given host string (domain or IP)
    pub fn matchesHost(self: HostSpec, host: []const u8) bool {
        switch (self) {
            .domain => |d| {
                // If d starts with '.', match as suffix
                if (d.len > 0 and d[0] == '.') {
                    if (std.mem.endsWith(u8, host, d)) return true;
                    // match exact domain without dot too? e.g. ".com" matches "example.com"
                    // but also ".example.com" matches "example.com"?
                    // Usually ".example.com" matches "foo.example.com" and "example.com"
                    if (d.len - 1 == host.len and std.mem.eql(u8, host, d[1..])) return true;
                    return false;
                }
                return std.mem.eql(u8, host, d);
            },
            else => {
                // Try parsing host as IP. If fast parse fails, assume no match.
                // We do NOT perform DNS lookup here to avoid blocking.
                const addr = zio.net.IpAddress.parseIp(host, 0) catch return false;
                return self.matches(addr);
            },
        }
    }

    /// Free allocated memory
    pub fn deinit(self: HostSpec, allocator: std.mem.Allocator) void {
        switch (self) {
            .domain => |d| allocator.free(d),
            else => {},
        }
    }
};

/// Single ACL entry
pub const AclEntry = struct {
    action: AclAction,
    spec: HostSpec,
};

/// Access Control List
pub const Acl = struct {
    entries: std.ArrayList(AclEntry),
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize an empty ACL
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .entries = .empty,
            .allocator = allocator,
        };
    }

    /// Add a rule to the ACL
    pub fn addRule(self: *Self, rule: []const u8, action: AclAction) !void {
        const spec = try HostSpec.parse(self.allocator, rule);
        errdefer spec.deinit(self.allocator);
        try self.entries.append(self.allocator, .{ .action = action, .spec = spec });
    }

    /// Add an allow rule
    pub fn allow(self: *Self, rule: []const u8) !void {
        try self.addRule(rule, .allow);
    }

    /// Add a deny rule
    pub fn deny(self: *Self, rule: []const u8) !void {
        try self.addRule(rule, .deny);
    }

    /// Check if an address is allowed
    /// Returns the action from the last matching rule, or .deny if no rules match
    pub fn check(self: *const Self, addr: zio.net.IpAddress) AclAction {
        // No rules = deny by default (tinyproxy behavior)
        if (self.entries.items.len == 0) {
            return .deny;
        }

        // Last matching rule wins
        var result: ?AclAction = null;
        for (self.entries.items) |entry| {
            if (entry.spec.matches(addr)) {
                result = entry.action;
            }
        }

        return result orelse .deny;
    }

    /// Check if ACL has any rules
    pub fn hasRules(self: *const Self) bool {
        return self.entries.items.len > 0;
    }

    /// Free all resources
    pub fn deinit(self: *Self) void {
        for (self.entries.items) |entry| {
            entry.spec.deinit(self.allocator);
        }
        self.entries.deinit(self.allocator);
    }
};

// ============================================================================
// IPv4 Parsing and Matching
// ============================================================================

fn parseIp4(s: []const u8) ?[4]u8 {
    var result: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;

    while (parts.next()) |part| {
        if (i >= 4) return null;
        result[i] = std.fmt.parseInt(u8, part, 10) catch return null;
        i += 1;
    }

    if (i != 4) return null;
    return result;
}

fn matchIp4Single(spec: [4]u8, addr: zio.net.IpAddress) bool {
    switch (addr.getFamily()) {
        .ipv4 => return std.mem.eql(u8, &spec, std.mem.asBytes(&addr.in.addr)),
        .ipv6 => {
            // Check for IPv4-mapped IPv6 (::ffff:a.b.c.d)
            const ip6_bytes = &addr.in6.addr;
            if (isIp4MappedIp6(ip6_bytes)) {
                return std.mem.eql(u8, &spec, ip6_bytes[12..16]);
            }
            return false;
        },
    }
}

fn matchIp4Cidr(spec: [4]u8, prefix_len: u5, addr: zio.net.IpAddress) bool {
    const client_bytes: [4]u8 = switch (addr.getFamily()) {
        .ipv4 => std.mem.asBytes(&addr.in.addr)[0..4].*,
        .ipv6 => blk: {
            const ip6_bytes = &addr.in6.addr;
            if (isIp4MappedIp6(ip6_bytes)) {
                break :blk ip6_bytes[12..16].*;
            }
            return false;
        },
    };

    return matchCidr(u32, spec, client_bytes, prefix_len);
}

// ============================================================================
// IPv6 Parsing and Matching
// ============================================================================

fn parseIp6(s: []const u8) ?[16]u8 {
    // Simple IPv6 parsing - handles :: compression
    var result: [16]u8 = std.mem.zeroes([16]u8);

    // Find :: position
    const double_colon = std.mem.indexOf(u8, s, "::");

    if (double_colon) |dc_pos| {
        // Parse before ::
        const before = s[0..dc_pos];
        const after = if (dc_pos + 2 < s.len) s[dc_pos + 2 ..] else "";

        var before_idx: usize = 0;
        if (before.len > 0) {
            var parts = std.mem.splitScalar(u8, before, ':');
            while (parts.next()) |part| {
                if (before_idx >= 8) return null;
                const val = std.fmt.parseInt(u16, part, 16) catch return null;
                result[before_idx * 2] = @intCast(val >> 8);
                result[before_idx * 2 + 1] = @intCast(val & 0xFF);
                before_idx += 1;
            }
        }

        // Parse after :: from the end
        var after_parts: [8]u16 = undefined;
        var after_count: usize = 0;
        if (after.len > 0) {
            var parts = std.mem.splitScalar(u8, after, ':');
            while (parts.next()) |part| {
                if (after_count >= 8) return null;
                after_parts[after_count] = std.fmt.parseInt(u16, part, 16) catch return null;
                after_count += 1;
            }
        }

        // Copy after parts from end
        const after_start = 8 - after_count;
        for (0..after_count) |i| {
            result[(after_start + i) * 2] = @intCast(after_parts[i] >> 8);
            result[(after_start + i) * 2 + 1] = @intCast(after_parts[i] & 0xFF);
        }
    } else {
        // No :: - must have 8 parts
        var parts = std.mem.splitScalar(u8, s, ':');
        var idx: usize = 0;
        while (parts.next()) |part| {
            if (idx >= 8) return null;
            const val = std.fmt.parseInt(u16, part, 16) catch return null;
            result[idx * 2] = @intCast(val >> 8);
            result[idx * 2 + 1] = @intCast(val & 0xFF);
            idx += 1;
        }
        if (idx != 8) return null;
    }

    return result;
}

fn matchIp6Single(spec: [16]u8, addr: zio.net.IpAddress) bool {
    switch (addr.getFamily()) {
        .ipv6 => return std.mem.eql(u8, &spec, &addr.in6.addr),
        .ipv4 => {
            // Check if spec is IPv4-mapped and client is IPv4
            if (isIp4MappedIp6(&spec)) {
                return std.mem.eql(u8, spec[12..16], std.mem.asBytes(&addr.in.addr));
            }
            return false;
        },
    }
}

fn matchIp6Cidr(spec: [16]u8, prefix_len: u7, addr: zio.net.IpAddress) bool {
    const client_bytes: [16]u8 = switch (addr.getFamily()) {
        .ipv6 => addr.in6.addr,
        .ipv4 => blk: {
            // Convert IPv4 to IPv4-mapped IPv6
            if (isIp4MappedIp6(&spec)) {
                var mapped: [16]u8 = std.mem.zeroes([16]u8);
                mapped[10] = 0xFF;
                mapped[11] = 0xFF;
                @memcpy(mapped[12..16], std.mem.asBytes(&addr.in.addr));
                break :blk mapped;
            }
            return false;
        },
    };

    return matchCidr(u128, spec, client_bytes, prefix_len);
}

fn isIp4MappedIp6(addr: *const [16]u8) bool {
    // ::ffff:a.b.c.d
    return std.mem.eql(u8, addr[0..10], &[_]u8{0} ** 10) and
        addr[10] == 0xFF and addr[11] == 0xFF;
}

// ============================================================================
// Generic CIDR Matching
// ============================================================================

fn matchCidr(comptime T: type, spec: anytype, client: anytype, prefix_len: anytype) bool {
    const bits: u8 = @bitSizeOf(T);

    // Convert to native endian integers for comparison
    const spec_int = std.mem.readInt(T, &spec, .big);
    const client_int = std.mem.readInt(T, &client, .big);

    if (prefix_len == 0) return true;
    if (prefix_len >= bits) return spec_int == client_int;

    const shift_amount = bits - prefix_len;
    const shift: std.math.Log2Int(T) = @intCast(shift_amount);
    const mask = ~(@as(T, 0)) << shift;

    return (spec_int & mask) == (client_int & mask);
}

// ============================================================================
// Tests
// ============================================================================

test "parseIp4 basic" {
    const result = parseIp4("192.168.1.100");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 100 }, result.?);
}

test "parseIp4 localhost" {
    const result = parseIp4("127.0.0.1");
    try std.testing.expect(result != null);
    try std.testing.expectEqual([4]u8{ 127, 0, 0, 1 }, result.?);
}

test "parseIp4 invalid" {
    try std.testing.expect(parseIp4("256.0.0.1") == null);
    try std.testing.expect(parseIp4("192.168.1") == null);
    try std.testing.expect(parseIp4("not.an.ip.addr") == null);
}

test "parseIp6 full" {
    const result = parseIp6("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(u8, 0x20), result.?[0]);
    try std.testing.expectEqual(@as(u8, 0x01), result.?[1]);
}

test "parseIp6 compressed" {
    const result = parseIp6("::1");
    try std.testing.expect(result != null);
    // ::1 should be all zeros except the last byte
    for (result.?[0..15]) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
    try std.testing.expectEqual(@as(u8, 1), result.?[15]);
}

test "parseIp6 ipv4-mapped" {
    const result = parseIp6("::ffff:192.168.1.1");
    // This format isn't fully supported yet - just ensure no crash
    _ = result;
}

test "HostSpec parse IPv4" {
    const spec = try HostSpec.parse(std.testing.allocator, "192.168.1.1");
    defer spec.deinit(std.testing.allocator);
    try std.testing.expect(spec == .ip4);
}

test "HostSpec parse IPv4 CIDR" {
    const spec = try HostSpec.parse(std.testing.allocator, "192.168.0.0/16");
    defer spec.deinit(std.testing.allocator);
    try std.testing.expect(spec == .ip4_cidr);
    try std.testing.expectEqual(@as(u5, 16), spec.ip4_cidr.prefix_len);
}

test "HostSpec parse domain" {
    const spec = try HostSpec.parse(std.testing.allocator, ".example.com");
    defer spec.deinit(std.testing.allocator);
    try std.testing.expect(spec == .domain);
    try std.testing.expectEqualStrings(".example.com", spec.domain);
}

test "CIDR matching IPv4" {
    const spec = [4]u8{ 192, 168, 0, 0 };
    const client1 = [4]u8{ 192, 168, 1, 100 }; // Should match /16
    const client2 = [4]u8{ 192, 169, 0, 1 }; // Should not match /16

    try std.testing.expect(matchCidr(u32, spec, client1, 16));
    try std.testing.expect(!matchCidr(u32, spec, client2, 16));
}

test "CIDR matching exact" {
    const spec = [4]u8{ 192, 168, 1, 100 };
    const client = [4]u8{ 192, 168, 1, 100 };

    try std.testing.expect(matchCidr(u32, spec, client, 32));
}

test "Acl basic allow/deny" {
    var acl = Acl.init(std.testing.allocator);
    defer acl.deinit();

    // Order matters: last matching rule wins
    // So deny all first, then allow localhost
    try acl.deny("0.0.0.0/0");
    try acl.allow("127.0.0.1");

    // Create test addresses
    const localhost = zio.net.IpAddress.initIp4(.{ 127, 0, 0, 1 }, 0);
    const other = zio.net.IpAddress.initIp4(.{ 10, 0, 0, 1 }, 0);

    try std.testing.expectEqual(AclAction.allow, acl.check(localhost));
    try std.testing.expectEqual(AclAction.deny, acl.check(other));
}

test "Acl empty denies by default" {
    var acl = Acl.init(std.testing.allocator);
    defer acl.deinit();

    const addr = zio.net.IpAddress.initIp4(.{ 127, 0, 0, 1 }, 0);
    try std.testing.expectEqual(AclAction.deny, acl.check(addr));
}

test "Acl last rule wins" {
    var acl = Acl.init(std.testing.allocator);
    defer acl.deinit();

    try acl.deny("192.168.0.0/16");
    try acl.allow("192.168.1.0/24");

    const addr1 = zio.net.IpAddress.initIp4(.{ 192, 168, 1, 100 }, 0);
    const addr2 = zio.net.IpAddress.initIp4(.{ 192, 168, 2, 100 }, 0);

    // 192.168.1.100 matches both rules, last (allow) wins
    try std.testing.expectEqual(AclAction.allow, acl.check(addr1));
    // 192.168.2.100 only matches first rule (deny)
    try std.testing.expectEqual(AclAction.deny, acl.check(addr2));
}
