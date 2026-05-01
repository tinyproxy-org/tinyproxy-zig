const std = @import("std");
const zio = @import("zio");

const upstream = @import("upstream.zig");

pub const SocksError = error{
    SocksDomainTooLong,
    BufferTooSmall,
    SocksProtocolError,
    SocksMethodRejected,
    SocksAuthFailed,
    SocksConnectFailed,
};

fn build_socks4a_request(buf: []u8, host: []const u8, port: u16) SocksError![]const u8 {
    if (host.len > 255) return SocksError.SocksDomainTooLong;
    const needed = 9 + host.len + 1;
    if (buf.len < needed) return SocksError.BufferTooSmall;

    buf[0] = 4;
    buf[1] = 1;
    std.mem.writeInt(u16, buf[2..4], port, .big);
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 1;
    buf[8] = 0;
    std.mem.copyForwards(u8, buf[9 .. 9 + host.len], host);
    buf[9 + host.len] = 0;
    return buf[0..needed];
}

fn build_socks5_methods(buf: []u8, has_auth: bool) []const u8 {
    buf[0] = 5;
    if (has_auth) {
        buf[1] = 2;
        buf[2] = 0;
        buf[3] = 2;
        return buf[0..4];
    }
    buf[1] = 1;
    buf[2] = 0;
    return buf[0..3];
}

fn build_socks5_auth(buf: []u8, user: []const u8, pass: []const u8) SocksError![]const u8 {
    if (user.len > 255 or pass.len > 255) return SocksError.SocksProtocolError;
    const needed = 3 + user.len + pass.len;
    if (buf.len < needed) return SocksError.BufferTooSmall;

    buf[0] = 1;
    buf[1] = @intCast(user.len);
    std.mem.copyForwards(u8, buf[2 .. 2 + user.len], user);
    buf[2 + user.len] = @intCast(pass.len);
    std.mem.copyForwards(u8, buf[3 + user.len .. needed], pass);
    return buf[0..needed];
}

fn build_socks5_connect(buf: []u8, host: []const u8, port: u16) SocksError![]const u8 {
    if (host.len > 255) return SocksError.SocksDomainTooLong;
    const needed = 7 + host.len;
    if (buf.len < needed) return SocksError.BufferTooSmall;

    buf[0] = 5;
    buf[1] = 1;
    buf[2] = 0;
    buf[3] = 3;
    buf[4] = @intCast(host.len);
    std.mem.copyForwards(u8, buf[5 .. 5 + host.len], host);
    const port_bytes = buf[5 + host.len .. 7 + host.len];
    const port_ptr: *[2]u8 = @ptrCast(port_bytes.ptr);
    std.mem.writeInt(u16, port_ptr, port, .big);
    return buf[0..needed];
}

fn read_exact(_: *zio.Runtime, stream: anytype, out: []u8) SocksError!void {
    var filled: usize = 0;
    while (filled < out.len) {
        const n = stream.read(out[filled..], .none) catch return SocksError.SocksProtocolError;
        if (n == 0) return SocksError.SocksProtocolError;
        filled += n;
    }
}

fn connect_socks4a(rt: *zio.Runtime, stream: anytype, host: []const u8, port: u16) SocksError!void {
    var buf: [512]u8 = undefined;
    const req = try build_socks4a_request(&buf, host, port);
    stream.writeAll(req, .none) catch return SocksError.SocksProtocolError;

    var resp: [8]u8 = undefined;
    try read_exact(rt, stream, &resp);
    if (resp[0] != 0 or resp[1] != 90) return SocksError.SocksConnectFailed;
}

fn connect_socks5(
    rt: *zio.Runtime,
    stream: anytype,
    user: ?[]const u8,
    pass: ?[]const u8,
    host: []const u8,
    port: u16,
) SocksError!void {
    var buf: [512]u8 = undefined;
    const has_auth = user != null;
    const auth_user = user orelse "";
    const auth_pass = pass orelse "";

    const methods = build_socks5_methods(&buf, has_auth);
    stream.writeAll(methods, .none) catch return SocksError.SocksProtocolError;

    var method_resp: [2]u8 = undefined;
    try read_exact(rt, stream, &method_resp);
    if (method_resp[0] != 5) return SocksError.SocksProtocolError;
    if (method_resp[1] != 0 and method_resp[1] != 2) return SocksError.SocksMethodRejected;
    if (method_resp[1] == 2) {
        if (!has_auth) return SocksError.SocksMethodRejected;
        const auth_req = try build_socks5_auth(&buf, auth_user, auth_pass);
        stream.writeAll(auth_req, .none) catch return SocksError.SocksProtocolError;

        var auth_resp: [2]u8 = undefined;
        try read_exact(rt, stream, &auth_resp);
        if (auth_resp[1] != 0 or (auth_resp[0] != 1 and auth_resp[0] != 5)) {
            return SocksError.SocksAuthFailed;
        }
    }

    const connect_req = try build_socks5_connect(&buf, host, port);
    stream.writeAll(connect_req, .none) catch return SocksError.SocksProtocolError;

    var resp_hdr: [4]u8 = undefined;
    try read_exact(rt, stream, &resp_hdr);
    if (resp_hdr[0] != 5) return SocksError.SocksProtocolError;
    if (resp_hdr[1] != 0) return SocksError.SocksConnectFailed;

    var addr_len: usize = 0;
    switch (resp_hdr[3]) {
        1 => addr_len = 4,
        4 => addr_len = 16,
        3 => {
            var len_buf: [1]u8 = undefined;
            try read_exact(rt, stream, &len_buf);
            addr_len = len_buf[0];
        },
        else => return SocksError.SocksProtocolError,
    }

    if (addr_len > 0) {
        try read_exact(rt, stream, buf[0..addr_len]);
    }

    var port_buf: [2]u8 = undefined;
    try read_exact(rt, stream, &port_buf);
}

pub fn connect(
    rt: *zio.Runtime,
    stream: anytype,
    proxy_type: upstream.ProxyType,
    user: ?[]const u8,
    pass: ?[]const u8,
    host: []const u8,
    port: u16,
) SocksError!void {
    switch (proxy_type) {
        .socks4 => try connect_socks4a(rt, stream, host, port),
        .socks5 => try connect_socks5(rt, stream, user, pass, host, port),
        else => return SocksError.SocksProtocolError,
    }
}

const testing = std.testing;

test "socks4a_request_encoding" {
    var buf: [512]u8 = undefined;
    const req = try build_socks4a_request(&buf, "example.com", 443);

    try testing.expectEqual(@as(u8, 4), req[0]);
    try testing.expectEqual(@as(u8, 1), req[1]);
    try testing.expectEqual(@as(u8, 0x01), req[2]);
    try testing.expectEqual(@as(u8, 0xBB), req[3]);
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 1 }, req[4..8]);
    try testing.expectEqual(@as(u8, 0), req[8]);
}

test "socks5_method_negotiation_encoding" {
    var buf: [8]u8 = undefined;
    const req = build_socks5_methods(&buf, true);

    try testing.expectEqual(@as(usize, 4), req.len);
    try testing.expectEqual(@as(u8, 5), req[0]);
    try testing.expectEqual(@as(u8, 2), req[1]);
    try testing.expectEqual(@as(u8, 0), req[2]);
    try testing.expectEqual(@as(u8, 2), req[3]);
}

test "socks5_auth_request_encoding" {
    var buf: [512]u8 = undefined;
    const req = try build_socks5_auth(&buf, "user", "pass");

    try testing.expectEqual(@as(u8, 1), req[0]);
    try testing.expectEqual(@as(u8, 4), req[1]);
    try testing.expectEqualStrings("user", req[2..6]);
}

const FakeStream = struct {
    read_buf: []const u8,
    read_pos: usize = 0,
    write_buf: []u8,
    write_pos: usize = 0,

    pub fn writeAll(self: *FakeStream, data: []const u8, _: anytype) !void {
        if (self.write_pos + data.len > self.write_buf.len) return error.OutOfMemory;
        std.mem.copyForwards(u8, self.write_buf[self.write_pos .. self.write_pos + data.len], data);
        self.write_pos += data.len;
    }

    pub fn read(self: *FakeStream, out: []u8, _: anytype) !usize {
        if (self.read_pos >= self.read_buf.len) return 0;
        const remaining = self.read_buf.len - self.read_pos;
        const to_copy = @min(out.len, remaining);
        std.mem.copyForwards(u8, out[0..to_copy], self.read_buf[self.read_pos .. self.read_pos + to_copy]);
        self.read_pos += to_copy;
        return to_copy;
    }
};

test "socks4a_handshake_writes_request" {
    const resp = [_]u8{ 0, 90, 0, 0, 0, 0, 0, 0 };
    var write_buf: [512]u8 = undefined;
    var stream = FakeStream{
        .read_buf = &resp,
        .write_buf = &write_buf,
    };
    var dummy_rt: zio.Runtime = undefined;
    try connect(&dummy_rt, &stream, upstream.ProxyType.socks4, null, null, "example.com", 443);
    const written = stream.write_buf[0..stream.write_pos];

    try testing.expectEqual(@as(u8, 4), written[0]);
    try testing.expectEqual(@as(u8, 1), written[1]);
}

test "socks5_no_auth_handshake_writes_methods_and_connect" {
    const resp = [_]u8{
        5, 0, // method selection: no-auth
        5, 0, 0, 1, // connect response: ok, IPv4
        127, 0, 0, 1, // bind addr
        0x1F, 0x90, // bind port 8080
    };
    var write_buf: [512]u8 = undefined;
    var stream = FakeStream{
        .read_buf = &resp,
        .write_buf = &write_buf,
    };
    var dummy_rt: zio.Runtime = undefined;
    try connect(&dummy_rt, &stream, upstream.ProxyType.socks5, null, null, "example.com", 443);
    const written = stream.write_buf[0..stream.write_pos];

    try testing.expectEqual(@as(u8, 5), written[0]);
    try testing.expectEqual(@as(u8, 5), written[3]); // connect request version
}

test "socks5_auth_handshake_writes_auth" {
    const resp = [_]u8{
        5, 2, // method selection: user/pass
        1, 0, // auth success
        5,    0,    0, 1, // connect response: ok, IPv4
        127,  0,    0, 1,
        0x1F, 0x90,
    };
    var write_buf: [512]u8 = undefined;
    var stream = FakeStream{
        .read_buf = &resp,
        .write_buf = &write_buf,
    };
    var dummy_rt: zio.Runtime = undefined;
    try connect(&dummy_rt, &stream, upstream.ProxyType.socks5, "user", "pass", "example.com", 443);
    const written = stream.write_buf[0..stream.write_pos];

    try testing.expect(std.mem.indexOf(u8, written, "user") != null);
}
