const std = @import("std");
const zio = @import("zio");
const buffer = @import("buffer.zig");

test "relay copies both directions" {
    var gpa = std.heap.DebugAllocator(.{}).init;
    defer _ = gpa.deinit();
    const rt = try zio.Runtime.init(gpa.allocator(), .{ .executors = .exact(1) });
    defer rt.deinit();

    const addr = try zio.net.IpAddress.parseIp4("127.0.0.1", 0);
    var server = try addr.listen(.{ .reuse_address = true });
    defer server.close();

    var ready = zio.ResetEvent.init;

    var relay_task = try rt.spawn(struct {
        fn run(rt2: *zio.Runtime, srv: *zio.net.Server, ready2: *zio.ResetEvent) !void {
            ready2.set();
            var a = try srv.accept(.{});
            defer a.close();
            var b = try srv.accept(.{});
            defer b.close();
            try copy_bidi(rt2, a, b);
        }
    }.run, .{ rt, &server, &ready });

    try ready.wait();
    var client_a = try server.socket.address.ip.connect(.{});
    var client_b = try server.socket.address.ip.connect(.{});

    try client_a.writeAll("PING", .none);
    var out_a: [4]u8 = undefined;
    _ = try client_b.read(&out_a, .none);
    try std.testing.expectEqualStrings("PING", &out_a);

    try client_b.writeAll("PONG", .none);
    var out_b: [4]u8 = undefined;
    _ = try client_a.read(&out_b, .none);
    try std.testing.expectEqualStrings("PONG", &out_b);

    client_a.close();
    client_b.close();
    try relay_task.join();
}

pub fn copy_one(_: *zio.Runtime, src: zio.net.Stream, dst: zio.net.Stream) !void {
    var from = src;
    var to = dst;
    var buf: [buffer.IO_BUFFER_SIZE]u8 = undefined;
    while (true) {
        const n = try from.read(&buf, .none);
        if (n == 0) break;
        try to.writeAll(buf[0..n], .none);
    }
}

pub fn copy_bidi(rt: *zio.Runtime, a: zio.net.Stream, b: zio.net.Stream) !void {
    // Spawn both directions to run concurrently
    var a_to_b = try rt.spawn(copy_one, .{ rt, a, b });
    var b_to_a = try rt.spawn(copy_one, .{ rt, b, a });

    var a_err: ?anyerror = null;
    var b_err: ?anyerror = null;

    // Wait for a→b: when done, half-close b's write side so the remote
    // peer receives EOF and the b→a direction can drain and finish.
    a_to_b.join() catch |err| {
        a_err = err;
    };
    b.shutdown(.send) catch {};

    // Wait for b→a: when done, half-close a's write side.
    b_to_a.join() catch |err| {
        b_err = err;
    };
    a.shutdown(.send) catch {};

    // Return first non-EndOfStream error if any
    // EndOfStream is expected when one side closes connection normally
    if (a_err) |err| {
        if (err != error.EndOfStream) return err;
    }
    if (b_err) |err| {
        if (err != error.EndOfStream) return err;
    }
}
