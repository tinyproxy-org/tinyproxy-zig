//! Daemon Mode Support for tinyproxy-zig
//!
//! Provides daemonization, PID file management, and privilege dropping.
//!
//! Usage:
//!   const daemon = @import("daemon.zig");
//!   try daemon.daemonize();
//!   try daemon.writePidFile("/var/run/tinyproxy.pid");
//!   try daemon.dropPrivileges("nobody", "nogroup");

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const libc = std.c;

pub const DaemonError = error{
    ForkFailed,
    SetsidFailed,
    ChdirFailed,
    UserNotFound,
    GroupNotFound,
    SetgidFailed,
    SetuidFailed,
    PidFileCreateFailed,
    PidFileWriteFailed,
};

/// Daemonize the process (fork, setsid, close standard file descriptors)
pub fn daemonize() DaemonError!void {
    if (builtin.os.tag == .windows) {
        // Windows doesn't support Unix daemonization
        return;
    }

    // First fork
    const pid1 = fork() catch return error.ForkFailed;
    if (pid1 > 0) {
        // Parent exits
        libc.exit(0);
    }

    // Create new session (become session leader)
    if (libc.setsid() < 0) return error.SetsidFailed;

    // Second fork to prevent acquiring a controlling terminal
    const pid2 = fork() catch return error.ForkFailed;
    if (pid2 > 0) {
        // First child exits
        libc.exit(0);
    }

    // Change working directory to root to avoid blocking unmount
    if (libc.chdir("/") != 0) return error.ChdirFailed;

    // Close standard file descriptors and redirect to /dev/null
    redirectToDevNull();
}

fn fork() !posix.pid_t {
    const rc = libc.fork();
    return switch (posix.errno(rc)) {
        .SUCCESS => @intCast(rc),
        else => error.ForkFailed,
    };
}

fn redirectToDevNull() void {
    const null_fd = posix.openatZ(posix.AT.FDCWD, "/dev/null", .{ .ACCMODE = .RDWR }, 0) catch return;
    defer _ = libc.close(null_fd);

    // Redirect stdin, stdout, stderr to /dev/null
    _ = libc.dup2(null_fd, posix.STDIN_FILENO);
    _ = libc.dup2(null_fd, posix.STDOUT_FILENO);
    _ = libc.dup2(null_fd, posix.STDERR_FILENO);
}

/// Write PID file
pub fn writePidFile(io: std.Io, path: []const u8) !void {
    const file = std.Io.Dir.cwd().createFile(io, path, .{
        .permissions = .default_file,
    }) catch return error.PidFileCreateFailed;
    defer file.close(io);

    const pid = if (builtin.os.tag != .windows) std.os.linux.getpid() else 0;
    var buf: [32]u8 = undefined;
    const pid_str = std.fmt.bufPrint(&buf, "{d}\n", .{pid}) catch return error.PidFileWriteFailed;

    file.writeStreamingAll(io, pid_str) catch return error.PidFileWriteFailed;
}

/// Remove PID file
pub fn removePidFile(io: std.Io, path: []const u8) void {
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

/// Drop privileges by switching to specified user and group
pub fn dropPrivileges(user: ?[]const u8, group: ?[]const u8) DaemonError!void {
    if (builtin.os.tag == .windows) {
        return;
    }

    // Drop group first (must do before dropping user privileges)
    if (group) |g| {
        const gid = getGroupId(g) catch return error.GroupNotFound;
        if (libc.setgid(gid) != 0) return error.SetgidFailed;
        // Also set supplementary groups
        setgroups(gid) catch {};
    }

    // Drop user privileges
    if (user) |u| {
        const uid = getUserId(u) catch return error.UserNotFound;
        if (libc.setuid(uid) != 0) return error.SetuidFailed;
    }
}

fn getUserId(name: []const u8) !posix.uid_t {
    // Use libc getpwnam for user lookup
    const c = @cImport({
        @cInclude("pwd.h");
    });

    // Create null-terminated string
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) return error.UserNotFound;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;

    const pw = c.getpwnam(&name_buf);
    if (pw == null) return error.UserNotFound;
    return pw.*.pw_uid;
}

fn getGroupId(name: []const u8) !posix.gid_t {
    // Use libc getgrnam for group lookup
    const c = @cImport({
        @cInclude("grp.h");
    });

    // Create null-terminated string
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) return error.GroupNotFound;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;

    const gr = c.getgrnam(&name_buf);
    if (gr == null) return error.GroupNotFound;
    return gr.*.gr_gid;
}

fn setgroups(gid: posix.gid_t) !void {
    // Use libc setgroups to clear supplementary groups
    const c = @cImport({
        @cInclude("grp.h");
        @cInclude("unistd.h");
    });

    const groups = [_]posix.gid_t{gid};
    const rc = c.setgroups(1, &groups);
    if (rc != 0) {
        // EPERM can happen when already dropped privileges - ignore
        // Also silently ignore EINVAL (on some systems when gid == current gid)
        const errno: std.c.E = @enumFromInt(std.c._errno().*);
        if (errno == .PERM or errno == .INVAL) return;
        return error.SetgidFailed;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "daemon module compiles" {
    // Basic compile test - actual daemon functionality requires root privileges
    if (builtin.os.tag == .windows) return;

    // Test that functions exist and compile
    _ = daemonize;
    _ = writePidFile;
    _ = removePidFile;
    _ = dropPrivileges;
}
