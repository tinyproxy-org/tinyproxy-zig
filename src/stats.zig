//! Statistics Module for tinyproxy-zig
//!
//! Provides atomic counters for proxy statistics and HTML rendering.
//!
//! Usage:
//!   const stats = @import("stats.zig");
//!   stats.global.recordOpen();
//!   stats.global.addBytesSent(1024);
//!   const html = try stats.global.renderHtml(allocator);

const std = @import("std");
const time_compat = @import("time_compat.zig");

/// Global statistics instance
pub var global: Stats = .{};

/// Statistics counters using atomic operations for thread safety
pub const Stats = struct {
    /// Total connections opened
    connections_opened: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Total connections closed
    connections_closed: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Connections refused (ACL denied)
    connections_refused: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Connections denied (auth failed)
    connections_denied: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Total bytes sent to clients
    bytes_sent: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Total bytes received from clients
    bytes_received: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Total requests processed
    requests_total: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Bad requests (malformed)
    requests_bad: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),
    /// Start timestamp (Unix epoch) - initialized at runtime
    start_time: std.atomic.Value(i64) = std.atomic.Value(i64).init(0),

    const Self = @This();

    /// Initialize start time (call once at startup)
    pub fn initStartTime(self: *Self) void {
        const expected: i64 = 0;
        _ = self.start_time.cmpxchgStrong(expected, time_compat.timestamp(), .monotonic, .monotonic);
    }

    pub fn init() Self {
        var s = Self{};
        s.start_time.store(time_compat.timestamp(), .monotonic);
        return s;
    }

    /// Record a new connection opened
    pub fn recordOpen(self: *Self) void {
        _ = self.connections_opened.fetchAdd(1, .monotonic);
    }

    /// Record a connection closed
    pub fn recordClose(self: *Self) void {
        _ = self.connections_closed.fetchAdd(1, .monotonic);
    }

    /// Record a refused connection (ACL)
    pub fn recordRefused(self: *Self) void {
        _ = self.connections_refused.fetchAdd(1, .monotonic);
    }

    /// Record a denied connection (auth)
    pub fn recordDenied(self: *Self) void {
        _ = self.connections_denied.fetchAdd(1, .monotonic);
    }

    /// Record a request
    pub fn recordRequest(self: *Self) void {
        _ = self.requests_total.fetchAdd(1, .monotonic);
    }

    /// Record a bad request
    pub fn recordBadRequest(self: *Self) void {
        _ = self.requests_bad.fetchAdd(1, .monotonic);
    }

    /// Add bytes sent
    pub fn addBytesSent(self: *Self, bytes: u64) void {
        _ = self.bytes_sent.fetchAdd(bytes, .monotonic);
    }

    /// Add bytes received
    pub fn addBytesReceived(self: *Self, bytes: u64) void {
        _ = self.bytes_received.fetchAdd(bytes, .monotonic);
    }

    /// Get current number of active connections
    pub fn getActiveConnections(self: *const Self) u64 {
        const opened = self.connections_opened.load(.monotonic);
        const closed = self.connections_closed.load(.monotonic);
        return if (opened > closed) opened - closed else 0;
    }

    /// Get uptime in seconds
    pub fn getUptime(self: *const Self) u64 {
        const now = time_compat.timestamp();
        const start = self.start_time.load(.monotonic);
        const diff = now - start;
        return if (diff > 0) @intCast(diff) else 0;
    }

    /// Format uptime as human-readable string
    fn formatUptime(self: *const Self, buf: []u8) []const u8 {
        const uptime = self.getUptime();
        const days = uptime / 86400;
        const hours = (uptime % 86400) / 3600;
        const minutes = (uptime % 3600) / 60;
        const seconds = uptime % 60;

        if (days > 0) {
            return std.fmt.bufPrint(buf, "{d}d {d}h {d}m {d}s", .{ days, hours, minutes, seconds }) catch "?";
        } else if (hours > 0) {
            return std.fmt.bufPrint(buf, "{d}h {d}m {d}s", .{ hours, minutes, seconds }) catch "?";
        } else if (minutes > 0) {
            return std.fmt.bufPrint(buf, "{d}m {d}s", .{ minutes, seconds }) catch "?";
        } else {
            return std.fmt.bufPrint(buf, "{d}s", .{seconds}) catch "?";
        }
    }

    /// Format bytes as human-readable string
    fn formatBytes(bytes: u64, buf: []u8) []const u8 {
        if (bytes >= 1024 * 1024 * 1024) {
            const gb: f64 = @as(f64, @floatFromInt(bytes)) / (1024 * 1024 * 1024);
            return std.fmt.bufPrint(buf, "{d:.2} GB", .{gb}) catch "?";
        } else if (bytes >= 1024 * 1024) {
            const mb: f64 = @as(f64, @floatFromInt(bytes)) / (1024 * 1024);
            return std.fmt.bufPrint(buf, "{d:.2} MB", .{mb}) catch "?";
        } else if (bytes >= 1024) {
            const kb: f64 = @as(f64, @floatFromInt(bytes)) / 1024;
            return std.fmt.bufPrint(buf, "{d:.2} KB", .{kb}) catch "?";
        } else {
            return std.fmt.bufPrint(buf, "{d} bytes", .{bytes}) catch "?";
        }
    }

    /// Render statistics as HTML page
    pub fn renderHtml(self: *const Self, allocator: std.mem.Allocator) ![]const u8 {
        var uptime_buf: [64]u8 = undefined;
        var sent_buf: [32]u8 = undefined;
        var recv_buf: [32]u8 = undefined;

        const uptime_str = self.formatUptime(&uptime_buf);
        const sent_str = formatBytes(self.bytes_sent.load(.monotonic), &sent_buf);
        const recv_str = formatBytes(self.bytes_received.load(.monotonic), &recv_buf);

        return std.fmt.allocPrint(allocator, html_template, .{
            // Uptime
            uptime_str,
            // Connections
            self.connections_opened.load(.monotonic),
            self.getActiveConnections(),
            self.connections_refused.load(.monotonic),
            self.connections_denied.load(.monotonic),
            // Requests
            self.requests_total.load(.monotonic),
            self.requests_bad.load(.monotonic),
            // Bytes
            sent_str,
            recv_str,
        });
    }

    /// Render statistics using a custom template file
    /// Template variables supported:
    ///   {version} - proxy version
    ///   {runtime} - uptime string
    ///   {clientsopen} - active connections
    ///   {totalconnections} - total connections opened
    ///   {badconnections} - (deprecated, same as deniedconnections)
    ///   {deniedconnections} - connections denied by auth
    ///   {refusedconnections} - connections refused by ACL
    ///   {totalrequests} - total requests processed
    ///   {badrequests} - malformed requests
    pub fn renderFromTemplate(self: *const Self, io: std.Io, allocator: std.mem.Allocator, template_path: []const u8) ![]const u8 {
        // Read template file
        const template = std.Io.Dir.cwd().readFileAlloc(io, template_path, allocator, .limited(1024 * 1024)) catch {
            // Fall back to default template if file not found
            return self.renderHtml(allocator);
        };
        defer allocator.free(template);

        // Prepare all replacement values first (stack buffers for efficiency)
        var uptime_buf: [64]u8 = undefined;
        const uptime_str = self.formatUptime(&uptime_buf);

        var active_buf: [32]u8 = undefined;
        const active_str = std.fmt.bufPrint(&active_buf, "{d}", .{self.getActiveConnections()}) catch return error.BufferTooSmall;

        var total_conn_buf: [32]u8 = undefined;
        const total_conn_str = std.fmt.bufPrint(&total_conn_buf, "{d}", .{self.connections_opened.load(.monotonic)}) catch return error.BufferTooSmall;

        var denied_buf: [32]u8 = undefined;
        const denied_str = std.fmt.bufPrint(&denied_buf, "{d}", .{self.connections_denied.load(.monotonic)}) catch return error.BufferTooSmall;

        var refused_buf: [32]u8 = undefined;
        const refused_str = std.fmt.bufPrint(&refused_buf, "{d}", .{self.connections_refused.load(.monotonic)}) catch return error.BufferTooSmall;

        var total_req_buf: [32]u8 = undefined;
        const total_req_str = std.fmt.bufPrint(&total_req_buf, "{d}", .{self.requests_total.load(.monotonic)}) catch return error.BufferTooSmall;

        var bad_req_buf: [32]u8 = undefined;
        const bad_req_str = std.fmt.bufPrint(&bad_req_buf, "{d}", .{self.requests_bad.load(.monotonic)}) catch return error.BufferTooSmall;

        // Replace variables in template
        const replacements = [_]struct { pattern: []const u8, value: []const u8 }{
            .{ .pattern = "{version}", .value = "tinyproxy-zig" },
            .{ .pattern = "{runtime}", .value = uptime_str },
            .{ .pattern = "{clientsopen}", .value = active_str },
            .{ .pattern = "{totalconnections}", .value = total_conn_str },
            .{ .pattern = "{badconnections}", .value = denied_str },
            .{ .pattern = "{deniedconnections}", .value = denied_str },
            .{ .pattern = "{refusedconnections}", .value = refused_str },
            .{ .pattern = "{totalrequests}", .value = total_req_str },
            .{ .pattern = "{badrequests}", .value = bad_req_str },
        };

        var result = try allocator.dupe(u8, template);
        errdefer allocator.free(result);

        for (replacements) |r| {
            // Skip if pattern not found
            if (std.mem.indexOf(u8, result, r.pattern) == null) continue;
            result = try replaceAll(allocator, result, r.pattern, r.value);
        }

        return result;
    }
};

/// Replace all occurrences of pattern with value
fn replaceAll(allocator: std.mem.Allocator, input: []const u8, pattern: []const u8, value: []const u8) ![]u8 {
    // Count occurrences
    var count: usize = 0;
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, input, pos, pattern)) |idx| {
        count += 1;
        pos = idx + pattern.len;
    }

    if (count == 0) {
        return try allocator.dupe(u8, input);
    }

    // Calculate new size
    const new_len = input.len - (count * pattern.len) + (count * value.len);
    const result = try allocator.alloc(u8, new_len);
    errdefer allocator.free(result);

    // Perform replacements
    var src_pos: usize = 0;
    var dst_pos: usize = 0;

    while (std.mem.indexOfPos(u8, input, src_pos, pattern)) |idx| {
        // Copy text before pattern
        const before_len = idx - src_pos;
        @memcpy(result[dst_pos..][0..before_len], input[src_pos..idx]);
        dst_pos += before_len;

        // Copy replacement value
        @memcpy(result[dst_pos..][0..value.len], value);
        dst_pos += value.len;

        src_pos = idx + pattern.len;
    }

    // Copy remaining text
    const remaining = input.len - src_pos;
    @memcpy(result[dst_pos..][0..remaining], input[src_pos..]);

    return result;
}

const html_template =
    \\<!DOCTYPE html>
    \\<html>
    \\<head>
    \\<title>tinyproxy Statistics</title>
    \\<style>
    \\body {{ font-family: sans-serif; margin: 40px; background: #f5f5f5; }}
    \\h1 {{ color: #333; }}
    \\table {{ border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
    \\th, td {{ padding: 12px 20px; text-align: left; border-bottom: 1px solid #eee; }}
    \\th {{ background: #f8f8f8; color: #666; font-weight: 600; }}
    \\tr:hover {{ background: #fafafa; }}
    \\.value {{ font-family: monospace; font-size: 1.1em; }}
    \\</style>
    \\</head>
    \\<body>
    \\<h1>tinyproxy Statistics</h1>
    \\<table>
    \\<tr><th>Metric</th><th>Value</th></tr>
    \\<tr><td>Uptime</td><td class="value">{s}</td></tr>
    \\<tr><td>Total Connections</td><td class="value">{d}</td></tr>
    \\<tr><td>Active Connections</td><td class="value">{d}</td></tr>
    \\<tr><td>Connections Refused (ACL)</td><td class="value">{d}</td></tr>
    \\<tr><td>Connections Denied (Auth)</td><td class="value">{d}</td></tr>
    \\<tr><td>Total Requests</td><td class="value">{d}</td></tr>
    \\<tr><td>Bad Requests</td><td class="value">{d}</td></tr>
    \\<tr><td>Bytes Sent</td><td class="value">{s}</td></tr>
    \\<tr><td>Bytes Received</td><td class="value">{s}</td></tr>
    \\</table>
    \\<p><small>tinyproxy-zig</small></p>
    \\</body>
    \\</html>
;

/// Send stats page HTTP response
pub fn sendStatsPage(allocator: std.mem.Allocator, writer: anytype) !void {
    const body = try global.renderHtml(allocator);
    defer allocator.free(body);

    try writer.print(
        "HTTP/1.1 200 OK\r\n" ++
            "Content-Type: text/html; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "{s}",
        .{ body.len, body },
    );
}

// ============================================================================
// Tests
// ============================================================================

test "Stats atomic operations" {
    var stats = Stats.init();

    stats.recordOpen();
    stats.recordOpen();
    stats.recordClose();

    try std.testing.expectEqual(@as(u64, 2), stats.connections_opened.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), stats.connections_closed.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 1), stats.getActiveConnections());
}

test "Stats bytes tracking" {
    var stats = Stats.init();

    stats.addBytesSent(1000);
    stats.addBytesSent(500);
    stats.addBytesReceived(2000);

    try std.testing.expectEqual(@as(u64, 1500), stats.bytes_sent.load(.monotonic));
    try std.testing.expectEqual(@as(u64, 2000), stats.bytes_received.load(.monotonic));
}

test "Stats formatBytes" {
    var buf: [32]u8 = undefined;

    try std.testing.expectEqualStrings("500 bytes", Stats.formatBytes(500, &buf));
    try std.testing.expectEqualStrings("1.50 KB", Stats.formatBytes(1536, &buf));
    try std.testing.expectEqualStrings("1.00 MB", Stats.formatBytes(1024 * 1024, &buf));
    try std.testing.expectEqualStrings("2.50 GB", Stats.formatBytes(2684354560, &buf));
}

test "Stats renderHtml" {
    const allocator = std.testing.allocator;
    var stats = Stats.init();

    stats.recordOpen();
    stats.recordRequest();
    stats.addBytesSent(1024);

    const html = try stats.renderHtml(allocator);
    defer allocator.free(html);

    try std.testing.expect(std.mem.indexOf(u8, html, "tinyproxy Statistics") != null);
    try std.testing.expect(std.mem.indexOf(u8, html, "Total Connections") != null);
}
