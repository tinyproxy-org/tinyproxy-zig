const std = @import("std");
const zio = @import("zio");

/// Default buffer size for line reading (4KB)
pub const DEFAULT_BUFFER_SIZE: usize = 4096;

/// Maximum line length for HTTP headers (prevents DoS via large headers)
pub const MAX_LINE_LENGTH: usize = 8192;

/// Buffer size for I/O operations (8KB)
pub const IO_BUFFER_SIZE: usize = 8192;

pub const LineReader = struct {
    allocator: std.mem.Allocator,
    max_len: usize,
    buf: [4096]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    pub fn init(allocator: std.mem.Allocator, max_len: usize) LineReader {
        return .{ .allocator = allocator, .max_len = max_len };
    }

    pub fn deinit(self: *LineReader) void {
        _ = self;
    }

    pub fn readLine(self: *LineReader, _: *zio.Runtime, stream: *zio.net.Stream) ![]u8 {
        var out = std.ArrayList(u8).empty;
        errdefer out.deinit(self.allocator);

        while (true) {
            if (self.start == self.end) {
                self.start = 0;
                self.end = try stream.read(&self.buf, .none);
                if (self.end == 0) return error.EndOfStream;
            }

            const slice = self.buf[self.start..self.end];
            if (std.mem.indexOfScalar(u8, slice, '\n')) |pos| {
                const chunk = slice[0 .. pos + 1];
                // Check max length before appending to prevent overflow
                if (out.items.len + chunk.len > self.max_len) return error.LineTooLong;
                try out.appendSlice(self.allocator, chunk);
                self.start += pos + 1;
                break;
            }

            // Check max length before appending to prevent overflow
            if (out.items.len + slice.len > self.max_len) return error.LineTooLong;
            try out.appendSlice(self.allocator, slice);
            self.start = self.end;
        }

        return try out.toOwnedSlice(self.allocator);
    }

    pub fn read(self: *LineReader, _: *zio.Runtime, stream: *zio.net.Stream, out: []u8) !usize {
        if (out.len == 0) return 0;
        if (self.start < self.end) {
            const available = self.end - self.start;
            const n = @min(available, out.len);
            std.mem.copyForwards(u8, out[0..n], self.buf[self.start .. self.start + n]);
            self.start += n;
            return n;
        }
        return stream.read(out, .none);
    }

    pub fn read_exact(self: *LineReader, rt: *zio.Runtime, stream: *zio.net.Stream, out: []u8) !void {
        var offset: usize = 0;
        while (offset < out.len) {
            const n = try self.read(rt, stream, out[offset..]);
            if (n == 0) return error.EndOfStream;
            offset += n;
        }
    }

    /// Flush any buffered data to the given writer stream.
    /// Returns the number of bytes flushed.
    pub fn flush_to(self: *LineReader, _: *zio.Runtime, writer: *zio.net.Stream) !usize {
        if (self.start >= self.end) return 0;
        const buffered = self.buf[self.start..self.end];
        try writer.writeAll(buffered, .none);
        const flushed = buffered.len;
        self.start = self.end;
        return flushed;
    }
};

fn server_task(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept(.{});
    defer stream.close();

    var reader = LineReader.init(rt.allocator, 1024);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);

    try std.testing.expectEqualStrings("GET / HTTP/1.1\r\n", line);
}

test "line reader reads one line" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var listener = try addr.listen(.{ .reuse_address = true });
    defer listener.close();
    var server = try rt.spawn(server_task, .{ rt, &listener });

    var client = try listener.socket.address.ip.connect(.{});
    defer client.close();

    try client.writeAll("GET / HTTP/1.1\r\n", .none);
    try server.join();
}

fn server_read_buffered(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept(.{});
    defer stream.close();

    var reader = LineReader.init(rt.allocator, 1024);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);

    var buf: [4]u8 = undefined;
    const n = try reader.read(rt, &stream, &buf);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqualStrings("BODY", &buf);
}

test "line reader reads buffered bytes" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var listener = try addr.listen(.{ .reuse_address = true });
    defer listener.close();
    var server = try rt.spawn(server_read_buffered, .{ rt, &listener });

    var client = try listener.socket.address.ip.connect(.{});
    defer client.close();

    try client.writeAll("GET / HTTP/1.1\r\nBODY", .none);
    try server.join();
}

fn server_read_exact(rt: *zio.Runtime, server: *zio.net.Server) !void {
    var stream = try server.accept(.{});
    defer stream.close();

    var reader = LineReader.init(rt.allocator, 1024);
    defer reader.deinit();

    const line = try reader.readLine(rt, &stream);
    defer rt.allocator.free(line);

    var buf: [5]u8 = undefined;
    try reader.read_exact(rt, &stream, &buf);
    try std.testing.expectEqualStrings("HELLO", &buf);
}

test "line reader read_exact fills buffer" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var listener = try addr.listen(.{ .reuse_address = true });
    defer listener.close();
    var server = try rt.spawn(server_read_exact, .{ rt, &listener });

    var client = try listener.socket.address.ip.connect(.{});
    defer client.close();

    try client.writeAll("GET / HTTP/1.1\r\nHELLO", .none);
    try server.join();
}
