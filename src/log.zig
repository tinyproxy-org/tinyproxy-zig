//! Unified Logging System for tinyproxy-zig
//!
//! Provides logging to file, stderr, or syslog with configurable log levels.
//! Thread-safe logging using mutex.
//!
//! Usage:
//!   const log = @import("log.zig");
//!   try log.init(io, &config);
//!   defer log.deinit();
//!
//!   log.info("Connection from {s}", .{client_ip});
//!   log.err("Failed to connect: {}", .{err});

const std = @import("std");
const builtin = @import("builtin");
const Config = @import("config.zig").Config;
const ConfigLogLevel = @import("config.zig").LogLevel;
const time_compat = @import("time_compat.zig");

// ============================================================================
// Syslog bindings (POSIX)
// ============================================================================

const syslog = if (builtin.os.tag != .windows) struct {
    const c = @cImport({
        @cInclude("syslog.h");
    });

    // Syslog priorities
    const LOG_EMERG = c.LOG_EMERG;
    const LOG_ALERT = c.LOG_ALERT;
    const LOG_CRIT = c.LOG_CRIT;
    const LOG_ERR = c.LOG_ERR;
    const LOG_WARNING = c.LOG_WARNING;
    const LOG_NOTICE = c.LOG_NOTICE;
    const LOG_INFO = c.LOG_INFO;
    const LOG_DEBUG = c.LOG_DEBUG;

    // Syslog options
    const LOG_PID = c.LOG_PID;
    const LOG_CONS = c.LOG_CONS;
    const LOG_NDELAY = c.LOG_NDELAY;

    // Syslog facilities
    const LOG_DAEMON = c.LOG_DAEMON;

    fn openlog(ident: [*:0]const u8, option: c_int, facility: c_int) void {
        c.openlog(ident, option, facility);
    }

    fn syslogWrite(priority: c_int, message: [*:0]const u8) void {
        c.syslog(priority, "%s", message);
    }

    fn closelog() void {
        c.closelog();
    }

    fn levelToPriority(level: LogLevel) c_int {
        return switch (level) {
            .critical => LOG_CRIT,
            .err => LOG_ERR,
            .warning => LOG_WARNING,
            .notice => LOG_NOTICE,
            .info => LOG_INFO,
            .debug => LOG_DEBUG,
        };
    }
} else struct {
    // Windows stub - syslog not supported
    fn openlog(_: [*:0]const u8, _: c_int, _: c_int) void {}
    fn syslogWrite(_: c_int, _: [*:0]const u8) void {}
    fn closelog() void {}
    fn levelToPriority(_: LogLevel) c_int {
        return 0;
    }

    const LOG_PID: c_int = 0;
    const LOG_CONS: c_int = 0;
    const LOG_NDELAY: c_int = 0;
    const LOG_DAEMON: c_int = 0;
};

/// Log levels matching tinyproxy
pub const LogLevel = enum(u8) {
    critical = 0,
    err = 1,
    warning = 2,
    notice = 3,
    info = 4,
    debug = 5,

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .critical => "CRITICAL",
            .err => "ERROR",
            .warning => "WARNING",
            .notice => "NOTICE",
            .info => "INFO",
            .debug => "DEBUG",
        };
    }

    pub fn fromConfig(level: ConfigLogLevel) LogLevel {
        return switch (level) {
            .critical => .critical,
            .err => .err,
            .warning => .warning,
            .notice => .notice,
            .info => .info,
            .debug => .debug,
        };
    }
};

/// Global logger state
const LogState = struct {
    io: ?std.Io = null,
    file: ?std.Io.File = null,
    min_level: LogLevel = .info,
    use_syslog: bool = false,
    initialized: bool = false,
    mutex: std.Io.Mutex = .init,
};

var state: LogState = .{};

// Shared buffer for formatting
var format_buf: [4096]u8 = undefined;

/// Initialize the logging system
pub fn init(io: std.Io, config: *const Config) !void {
    state.mutex.lockUncancelable(io);
    defer state.mutex.unlock(io);

    state.io = io;
    if (state.initialized) {
        // Already initialized, just update settings
        state.min_level = LogLevel.fromConfig(config.log_level);
        return;
    }

    state.min_level = LogLevel.fromConfig(config.log_level);
    state.use_syslog = config.use_syslog;

    // Initialize syslog if enabled
    if (state.use_syslog) {
        syslog.openlog("tinyproxy", syslog.LOG_PID | syslog.LOG_CONS | syslog.LOG_NDELAY, syslog.LOG_DAEMON);
        state.initialized = true;
        return;
    }

    // Open log file if specified
    if (config.log_file) |path| {
        state.file = std.Io.Dir.cwd().createFile(io, path, .{
            .truncate = false,
        }) catch |e| {
            // Fall back to stderr
            std.debug.print("Failed to open log file '{s}': {}\n", .{ path, e });
            state.file = null;
            return e;
        };

        // Seek to end for append mode
        if (state.file) |f| {
            const len = f.length(io) catch 0;
            io.vtable.fileSeekTo(io.userdata, f, len) catch {};
        }
    }

    state.initialized = true;
}

/// Deinitialize the logging system
pub fn deinit() void {
    const io = state.io orelse return;
    state.mutex.lockUncancelable(io);
    defer state.mutex.unlock(io);

    if (state.use_syslog) {
        syslog.closelog();
    }

    if (state.file) |f| {
        f.close(io);
        state.file = null;
    }
    state.io = null;
    state.initialized = false;
}

/// Reopen log file (for log rotation via SIGUSR1)
pub fn reopen(io: std.Io, path: []const u8) !void {
    state.mutex.lockUncancelable(io);
    defer state.mutex.unlock(io);

    state.io = io;

    // Close existing file
    if (state.file) |f| {
        f.close(io);
    }

    // Open new file
    state.file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = false,
    });

    if (state.file) |f| {
        const len = f.length(io) catch 0;
        io.vtable.fileSeekTo(io.userdata, f, len) catch {};
    }
}

/// Check if a log level is enabled
pub fn isEnabled(level: LogLevel) bool {
    return @intFromEnum(level) <= @intFromEnum(state.min_level);
}

/// Core logging function
pub fn logFn(level: LogLevel, comptime fmt: []const u8, args: anytype) void {
    if (!isEnabled(level)) return;

    const io = state.io orelse return;
    state.mutex.lockUncancelable(io);
    defer state.mutex.unlock(io);

    // Use syslog if enabled
    if (state.use_syslog) {
        // Format message without timestamp (syslog adds its own)
        const msg = std.fmt.bufPrint(format_buf[0 .. format_buf.len - 1], fmt, args) catch return;
        // Null-terminate for C syslog
        format_buf[msg.len] = 0;
        syslog.syslogWrite(syslog.levelToPriority(level), @ptrCast(format_buf[0 .. msg.len + 1].ptr));
        return;
    }

    // Get current timestamp
    const timestamp = getTimestamp();

    // Format the message into buffer
    const msg = std.fmt.bufPrint(&format_buf, "[{s}] {s}: " ++ fmt ++ "\n", .{timestamp} ++ .{level.toString()} ++ args) catch return;

    // Write to file or stderr
    if (state.file) |f| {
        f.writeStreamingAll(io, msg) catch {};
    } else {
        std.debug.print("{s}", .{msg});
    }
}

fn getTimestamp() [19]u8 {
    const epoch_seconds: i64 = time_compat.timestamp();

    // Handle negative timestamps (before 1970) - just use a default
    if (epoch_seconds < 0) {
        return "1970-01-01 00:00:00".*;
    }

    const secs: u64 = @intCast(epoch_seconds);
    const day_count = secs / std.time.s_per_day;
    const day_seconds = secs % std.time.s_per_day;

    // Calculate year/month/day from epoch days
    var year: u32 = 1970;
    var remaining_days: u64 = day_count;

    while (remaining_days >= daysInYear(year)) {
        remaining_days -= daysInYear(year);
        year += 1;
    }

    const is_leap = isLeapYear(@intCast(year));
    const days_in_months: [12]u8 = if (is_leap)
        .{ 31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
    else
        .{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };

    var month: u8 = 1;
    for (days_in_months) |days| {
        if (remaining_days < days) break;
        remaining_days -= days;
        month += 1;
    }
    const day: u8 = @intCast(remaining_days + 1);

    // Calculate hours/minutes/seconds
    const hours: u8 = @intCast(day_seconds / 3600);
    const minutes: u8 = @intCast((day_seconds % 3600) / 60);
    const seconds: u8 = @intCast(day_seconds % 60);

    var buf: [19]u8 = undefined;
    _ = std.fmt.bufPrint(&buf, "{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}", .{
        year,
        month,
        day,
        hours,
        minutes,
        seconds,
    }) catch {
        return "0000-00-00 00:00:00".*;
    };

    return buf;
}

fn daysInYear(year: u32) u64 {
    return if (isLeapYear(@intCast(year))) 366 else 365;
}

fn isLeapYear(year: i32) bool {
    if (@mod(year, 400) == 0) return true;
    if (@mod(year, 100) == 0) return false;
    if (@mod(year, 4) == 0) return true;
    return false;
}

// ============================================================================
// Convenience logging functions
// ============================================================================

pub fn critical(comptime fmt: []const u8, args: anytype) void {
    logFn(.critical, fmt, args);
}

pub fn err(comptime fmt: []const u8, args: anytype) void {
    logFn(.err, fmt, args);
}

pub fn warning(comptime fmt: []const u8, args: anytype) void {
    logFn(.warning, fmt, args);
}

pub fn notice(comptime fmt: []const u8, args: anytype) void {
    logFn(.notice, fmt, args);
}

pub fn info(comptime fmt: []const u8, args: anytype) void {
    logFn(.info, fmt, args);
}

pub fn debug(comptime fmt: []const u8, args: anytype) void {
    logFn(.debug, fmt, args);
}

// ============================================================================
// Access Log (separate from debug log)
// ============================================================================

pub const AccessEvent = struct {
    client: []const u8,
    method: []const u8,
    host: []const u8,
    path: []const u8 = "/",
    status: u16,
    bytes: usize,
};

/// Log an access event (connection info)
pub fn access(event: AccessEvent) void {
    if (!isEnabled(.notice)) return;

    const io = state.io orelse return;
    state.mutex.lockUncancelable(io);
    defer state.mutex.unlock(io);

    const timestamp = getTimestamp();

    // Apache-like access log format
    const msg = std.fmt.bufPrint(&format_buf, "[{s}] {s} \"{s} {s}{s}\" {} {}\n", .{
        timestamp,
        event.client,
        event.method,
        event.host,
        event.path,
        event.status,
        event.bytes,
    }) catch return;

    if (state.file) |f| {
        f.writeStreamingAll(io, msg) catch {};
    } else {
        std.debug.print("{s}", .{msg});
    }
}

// ============================================================================
// Tests
// ============================================================================

test "log level ordering" {
    try std.testing.expect(@intFromEnum(LogLevel.critical) < @intFromEnum(LogLevel.err));
    try std.testing.expect(@intFromEnum(LogLevel.err) < @intFromEnum(LogLevel.warning));
    try std.testing.expect(@intFromEnum(LogLevel.warning) < @intFromEnum(LogLevel.notice));
    try std.testing.expect(@intFromEnum(LogLevel.notice) < @intFromEnum(LogLevel.info));
    try std.testing.expect(@intFromEnum(LogLevel.info) < @intFromEnum(LogLevel.debug));
}

test "log level toString" {
    try std.testing.expectEqualStrings("CRITICAL", LogLevel.critical.toString());
    try std.testing.expectEqualStrings("ERROR", LogLevel.err.toString());
    try std.testing.expectEqualStrings("INFO", LogLevel.info.toString());
}

test "timestamp format" {
    const ts = getTimestamp();
    // Check format: YYYY-MM-DD HH:MM:SS (19 chars)
    try std.testing.expect(ts[4] == '-');
    try std.testing.expect(ts[7] == '-');
    try std.testing.expect(ts[10] == ' ');
    try std.testing.expect(ts[13] == ':');
    try std.testing.expect(ts[16] == ':');
}

test "isEnabled respects log level" {
    // Save and restore state
    const saved_level = state.min_level;
    defer state.min_level = saved_level;

    state.min_level = .warning;

    try std.testing.expect(isEnabled(.critical));
    try std.testing.expect(isEnabled(.err));
    try std.testing.expect(isEnabled(.warning));
    try std.testing.expect(!isEnabled(.notice));
    try std.testing.expect(!isEnabled(.info));
    try std.testing.expect(!isEnabled(.debug));
}

test "leap year calculation" {
    try std.testing.expect(isLeapYear(2000)); // divisible by 400
    try std.testing.expect(!isLeapYear(1900)); // divisible by 100 but not 400
    try std.testing.expect(isLeapYear(2024)); // divisible by 4
    try std.testing.expect(!isLeapYear(2023)); // not divisible by 4
}
