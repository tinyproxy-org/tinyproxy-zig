const std = @import("std");
const zio = @import("zio");
const buffer = @import("buffer.zig");

/// Maximum number of headers allowed per request (DoS protection)
pub const MAX_HEADERS: usize = 100;

/// Maximum chunk size allowed (16MB - prevents DoS)
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

pub const HttpError = error{
    BadRequest,
    InvalidHeader,
    InvalidContentLength,
    InvalidChunk,
    TooManyHeaders,
    InvalidMethod,
};

pub const HttpVersion = enum {
    http09,
    http10,
    http11,
};

pub const RequestLine = struct {
    method: []const u8,
    uri: []const u8,
    version: HttpVersion,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const HttpMessage = struct {
    allocator: std.mem.Allocator,
    headers: std.StringHashMap([]const u8),
    header_list: std.ArrayList(Header),
    content_length: ?usize = null,
    is_chunked: bool = false,

    pub fn init(allocator: std.mem.Allocator) HttpMessage {
        return .{
            .allocator = allocator,
            .headers = std.StringHashMap([]const u8).init(allocator),
            .header_list = std.ArrayList(Header).empty,
        };
    }

    pub fn body_reader(self: *const HttpMessage) BodyReader {
        if (self.is_chunked) {
            return .{ .mode = .chunked, .remaining = 0 };
        }
        if (self.content_length) |len| {
            if (len == 0) return .{ .mode = .none, .remaining = 0 };
            return .{ .mode = .length, .remaining = len };
        }
        return .{ .mode = .none, .remaining = 0 };
    }

    pub fn deinit(self: *HttpMessage) void {
        for (self.header_list.items) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.headers.deinit();
        self.header_list.deinit(self.allocator);
    }
};

pub const BodyMode = enum {
    none,
    length,
    chunked,
};

pub const BodyReader = struct {
    mode: BodyMode,
    remaining: usize,

    pub fn copy_raw_to(
        self: *BodyReader,
        reader: *buffer.LineReader,
        rt: *zio.Runtime,
        stream: *zio.net.Stream,
        writer: anytype,
    ) !void {
        switch (self.mode) {
            .none => return,
            .length => {
                var remaining = self.remaining;
                var buf: [buffer.IO_BUFFER_SIZE]u8 = undefined;
                while (remaining > 0) {
                    const to_read = @min(remaining, buf.len);
                    const n = try reader.read(rt, stream, buf[0..to_read]);
                    if (n == 0) return error.EndOfStream;
                    try writer.writeAll(buf[0..n], .none);
                    remaining -= n;
                }
                self.remaining = 0;
            },
            .chunked => {
                var buf: [buffer.IO_BUFFER_SIZE]u8 = undefined;
                while (true) {
                    const size_line = try reader.readLine(rt, stream);
                    defer reader.allocator.free(size_line);
                    try writer.writeAll(size_line, .none);

                    const size_trim = std.mem.trimEnd(u8, size_line, "\r\n");
                    const semi = std.mem.indexOfScalar(u8, size_trim, ';') orelse size_trim.len;
                    const size_str = std.mem.trim(u8, size_trim[0..semi], " \t");
                    if (size_str.len == 0) return error.InvalidChunk;
                    const chunk_size = std.fmt.parseInt(usize, size_str, 16) catch return error.InvalidChunk;

                    // Prevent DoS via extremely large chunks
                    if (chunk_size > MAX_CHUNK_SIZE) return error.InvalidChunk;

                    if (chunk_size == 0) {
                        while (true) {
                            const trailer = try reader.readLine(rt, stream);
                            defer reader.allocator.free(trailer);
                            try writer.writeAll(trailer, .none);
                            const trailer_trim = std.mem.trimEnd(u8, trailer, "\r\n");
                            if (trailer_trim.len == 0) break;
                        }
                        break;
                    }

                    var remaining = chunk_size;
                    while (remaining > 0) {
                        const to_read = @min(remaining, buf.len);
                        try reader.read_exact(rt, stream, buf[0..to_read]);
                        try writer.writeAll(buf[0..to_read], .none);
                        remaining -= to_read;
                    }

                    var crlf: [2]u8 = undefined;
                    try reader.read_exact(rt, stream, &crlf);
                    if (!std.mem.eql(u8, &crlf, "\r\n")) return error.InvalidChunk;
                    try writer.writeAll(&crlf, .none);
                }
            },
        }
    }
};

pub fn parse_request_line(line: []const u8) HttpError!RequestLine {
    const trimmed = std.mem.trimEnd(u8, line, "\r\n");
    var parts = std.mem.splitScalar(u8, trimmed, ' ');
    const method = parts.next() orelse return error.BadRequest;

    // Validate method length (RFC 2616: 1-20 chars, RFC 7231: token up to 255)
    if (method.len == 0 or method.len > 255) return error.InvalidMethod;

    const uri = parts.next() orelse return error.BadRequest;
    const version_opt = parts.next();
    if (version_opt == null) {
        if (!std.ascii.eqlIgnoreCase(method, "GET")) return error.BadRequest;
        return .{ .method = method, .uri = uri, .version = .http09 };
    }

    const version = version_opt.?;
    if (!std.ascii.startsWithIgnoreCase(version, "HTTP/")) return error.BadRequest;
    if (std.ascii.eqlIgnoreCase(version, "HTTP/1.0")) {
        return .{ .method = method, .uri = uri, .version = .http10 };
    }
    if (std.ascii.eqlIgnoreCase(version, "HTTP/1.1")) {
        return .{ .method = method, .uri = uri, .version = .http11 };
    }
    return error.BadRequest;
}

pub fn read_headers(
    allocator: std.mem.Allocator,
    reader: *buffer.LineReader,
    rt: *zio.Runtime,
    stream: *zio.net.Stream,
) !HttpMessage {
    var message = HttpMessage.init(allocator);
    errdefer message.deinit();
    var last_header_index: ?usize = null;
    var seen_content_length: ?usize = null;

    while (true) {
        const line = try reader.readLine(rt, stream);
        defer allocator.free(line);
        const trimmed = std.mem.trimEnd(u8, line, "\r\n");
        if (trimmed.len == 0) break;

        // RFC 7230 obsolete line folding support (C tinyproxy-compatible).
        if (trimmed[0] == ' ' or trimmed[0] == '\t') {
            if (last_header_index) |idx| {
                const old_value = message.header_list.items[idx].value;
                const combined = try std.fmt.allocPrint(allocator, "{s}\r\n{s}", .{ old_value, trimmed });
                allocator.free(old_value);
                message.header_list.items[idx].value = combined;
                const header_name = message.header_list.items[idx].name;
                try message.headers.put(header_name, combined);
            }
            continue;
        }

        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse {
            // tinyproxy C behavior: skip malformed header lines without ':'.
            last_header_index = null;
            continue;
        };
        const name_raw = std.mem.trim(u8, trimmed[0..colon], " \t");
        const value_raw = std.mem.trim(u8, trimmed[colon + 1 ..], " \t");
        if (name_raw.len == 0) {
            last_header_index = null;
            continue;
        }

        const name = try allocator.dupe(u8, name_raw);
        errdefer allocator.free(name);
        for (name) |*c| c.* = std.ascii.toLower(c.*);
        const value = try allocator.dupe(u8, value_raw);
        errdefer allocator.free(value);

        // Check header limit BEFORE appending to prevent bypass
        if (message.header_list.items.len >= MAX_HEADERS) {
            return error.TooManyHeaders;
        }

        if (std.mem.eql(u8, name, "content-length")) {
            if (message.is_chunked) return error.InvalidHeader;
            const parsed_len = std.fmt.parseInt(usize, value_raw, 10) catch return error.InvalidContentLength;
            if (seen_content_length) |previous_len| {
                if (previous_len != parsed_len) return error.InvalidContentLength;
            } else {
                seen_content_length = parsed_len;
                message.content_length = parsed_len;
            }
        } else if (std.mem.eql(u8, name, "transfer-encoding")) {
            var it = std.mem.splitScalar(u8, value_raw, ',');
            while (it.next()) |token| {
                const part = std.mem.trim(u8, token, " \t");
                if (std.ascii.eqlIgnoreCase(part, "chunked")) {
                    if (seen_content_length != null) return error.InvalidHeader;
                    message.is_chunked = true;
                    break;
                }
            }
        }

        try message.header_list.append(allocator, .{ .name = name, .value = value });
        errdefer _ = message.header_list.pop();
        try message.headers.put(name, value);
        last_header_index = message.header_list.items.len - 1;
    }

    return message;
}

test "parse request line http11" {
    const line = "GET /path HTTP/1.1\r\n";
    const req = try parse_request_line(line);
    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/path", req.uri);
    try std.testing.expect(req.version == .http11);
}

fn malformed_header_server(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept(.{});
    defer stream.close();

    var reader = buffer.LineReader.init(rt.allocator, buffer.MAX_LINE_LENGTH);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);
    _ = try parse_request_line(line);

    var message = try read_headers(rt.allocator, &reader, rt, &stream);
    defer message.deinit();

    try std.testing.expectEqualStrings("example.com", message.headers.get("host").?);
    try std.testing.expect(message.headers.get("bad-header-without-colon") == null);
    try std.testing.expectEqualStrings("one\r\n continuation", message.headers.get("x-test").?);
}

test "read headers skips malformed lines and supports folded continuation" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.close();

    var server_task = try rt.spawn(malformed_header_server, .{ rt, &server });

    var client = try server.socket.address.ip.connect(.{});
    defer client.close();

    try client.writeAll(
        "GET / HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Bad Header Without Colon\r\n" ++
            "X-Test: one\r\n" ++
            " continuation\r\n" ++
            "\r\n",
        .none,
    );

    try server_task.join();
}

const TestWriter = struct {
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,

    pub fn writeAll(self: *TestWriter, data: []const u8, _: anytype) !void {
        try self.list.appendSlice(self.allocator, data);
    }
};

fn content_length_server(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept(.{});
    defer stream.close();

    var reader = buffer.LineReader.init(rt.allocator, buffer.MAX_LINE_LENGTH);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);
    _ = try parse_request_line(line);

    var message = try read_headers(rt.allocator, &reader, rt, &stream);
    defer message.deinit();

    try std.testing.expectEqual(@as(?usize, 5), message.content_length);

    var body = std.ArrayList(u8).empty;
    defer body.deinit(rt.allocator);
    var writer = TestWriter{ .list = &body, .allocator = rt.allocator };
    var body_reader = message.body_reader();
    try body_reader.copy_raw_to(&reader, rt, &stream, &writer);

    try std.testing.expectEqualStrings("hello", body.items);
}

test "read content-length body" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.close();

    var server_task = try rt.spawn(content_length_server, .{ rt, &server });

    var client = try server.socket.address.ip.connect(.{});
    defer client.close();

    try client.writeAll(
        "POST /submit HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Length: 5\r\n" ++
            "\r\n" ++
            "hello",
        .none,
    );

    try server_task.join();
}

fn chunked_server(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept(.{});
    defer stream.close();

    var reader = buffer.LineReader.init(rt.allocator, buffer.MAX_LINE_LENGTH);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);
    _ = try parse_request_line(line);

    var message = try read_headers(rt.allocator, &reader, rt, &stream);
    defer message.deinit();

    try std.testing.expect(message.is_chunked);

    var body = std.ArrayList(u8).empty;
    defer body.deinit(rt.allocator);
    var writer = TestWriter{ .list = &body, .allocator = rt.allocator };
    var body_reader = message.body_reader();
    try body_reader.copy_raw_to(&reader, rt, &stream, &writer);

    try std.testing.expectEqualStrings(
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        body.items,
    );
}

test "read chunked body" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.close();

    var server_task = try rt.spawn(chunked_server, .{ rt, &server });

    var client = try server.socket.address.ip.connect(.{});
    defer client.close();

    try client.writeAll(
        "POST /chunked HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n",
        .none,
    );

    try server_task.join();
}

fn conflicting_content_length_server(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept(.{});
    defer stream.close();

    var reader = buffer.LineReader.init(rt.allocator, buffer.MAX_LINE_LENGTH);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);
    _ = try parse_request_line(line);

    try std.testing.expectError(error.InvalidContentLength, read_headers(rt.allocator, &reader, rt, &stream));
}

test "read headers rejects conflicting content-length" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.close();

    var server_task = try rt.spawn(conflicting_content_length_server, .{ rt, &server });

    var client = try server.socket.address.ip.connect(.{});
    defer client.close();

    try client.writeAll(
        "POST /submit HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Length: 5\r\n" ++
            "Content-Length: 6\r\n" ++
            "\r\n" ++
            "hello!",
        .none,
    );

    try server_task.join();
}

fn transfer_encoding_with_content_length_server(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept(.{});
    defer stream.close();

    var reader = buffer.LineReader.init(rt.allocator, buffer.MAX_LINE_LENGTH);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);
    _ = try parse_request_line(line);

    try std.testing.expectError(error.InvalidHeader, read_headers(rt.allocator, &reader, rt, &stream));
}

test "read headers rejects transfer-encoding with content-length" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.close();

    var server_task = try rt.spawn(transfer_encoding_with_content_length_server, .{ rt, &server });

    var client = try server.socket.address.ip.connect(.{});
    defer client.close();

    try client.writeAll(
        "POST /submit HTTP/1.1\r\n" ++
            "Host: example.com\r\n" ++
            "Content-Length: 5\r\n" ++
            "Transfer-Encoding: chunked\r\n" ++
            "\r\n" ++
            "0\r\n\r\n",
        .none,
    );

    try server_task.join();
}
