const std = @import("std");

pub fn timestamp() i64 {
    var ts: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(.REALTIME, &ts))) {
        .SUCCESS => return @intCast(ts.sec),
        else => return 0,
    }
}
