const std = @import("std");

const build_options = @import("build_options");
const zio = @import("zio");

const child = @import("child.zig");
const conf_parser = @import("conf.zig");
const Config = @import("config.zig").Config;
const daemon = @import("daemon.zig");
const logger = @import("log.zig");
const signals = @import("signals.zig");
const stats = @import("stats.zig");

const log = std.log.scoped(.main);

const DefaultConfigPath = "";
const ExitUsage: u8 = 64;

const ArgsError = error{InvalidArgs};
const ArgsErrorDetail = union(enum) {
    illegal_option: u8,
    missing_argument: u8,
};

const CliOptions = struct {
    config_path: []const u8,
    foreground: bool,
    show_help: bool,
    show_version: bool,
};

const UsageText =
    \\Usage: tinyproxy [options]
    \\
    \\Options are:
    \\  -d        Do not daemonize (run in foreground).
    \\  -c FILE   Use an alternate configuration file.
    \\  -h        Display this usage information.
    \\  -v        Display version information.
    \\
;

const VersionText = "tinyproxy " ++ build_options.version ++ "\n";

fn parseArgsDetailed(args: []const []const u8, err_detail: ?*ArgsErrorDetail) ArgsError!CliOptions {
    var config_path: ?[]const u8 = null;
    var foreground: bool = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-c")) {
            if (i + 1 >= args.len) {
                if (err_detail) |detail| detail.* = .{ .missing_argument = 'c' };
                return error.InvalidArgs;
            }
            config_path = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "-d")) {
            foreground = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "-h")) {
            return .{
                .config_path = config_path orelse DefaultConfigPath,
                .foreground = foreground,
                .show_help = true,
                .show_version = false,
            };
        }
        if (std.mem.eql(u8, arg, "-v")) {
            return .{
                .config_path = config_path orelse DefaultConfigPath,
                .foreground = foreground,
                .show_help = false,
                .show_version = true,
            };
        }
        if (arg.len >= 2 and arg[0] == '-') {
            if (err_detail) |detail| detail.* = .{ .illegal_option = arg[1] };
            return error.InvalidArgs;
        }
        return error.InvalidArgs;
    }
    return .{
        .config_path = config_path orelse DefaultConfigPath,
        .foreground = foreground,
        .show_help = false,
        .show_version = false,
    };
}

fn parseArgs(args: []const []const u8) ArgsError!CliOptions {
    return parseArgsDetailed(args, null);
}

fn printUsage() void {
    std.debug.print("{s}", .{UsageText});
}

fn printArgsError(detail: ArgsErrorDetail) void {
    switch (detail) {
        .illegal_option => |option| std.debug.print("tinyproxy: illegal option -- {c}\n", .{option}),
        .missing_argument => |option| std.debug.print("tinyproxy: option requires an argument -- {c}\n", .{option}),
    }
    printUsage();
}

fn exitCodeForArgsError(err: ArgsError) u8 {
    return switch (err) {
        error.InvalidArgs => ExitUsage,
    };
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    // Use DebugAllocator in development builds for leak detection
    var gpa = std.heap.DebugAllocator(.{
        .safety = true,
    }).init;
    defer {
        const leaked = gpa.deinit();
        if (leaked == .leak) {
            std.log.err("Memory leaks detected!", .{});
        }
    }
    const allocator = gpa.allocator();

    var args_arena = std.heap.ArenaAllocator.init(allocator);
    defer args_arena.deinit();
    const args = try init.minimal.args.toSlice(args_arena.allocator());

    var args_error_detail: ArgsErrorDetail = .{ .illegal_option = '?' };
    const cli = parseArgsDetailed(args, &args_error_detail) catch |err| {
        printArgsError(args_error_detail);
        std.process.exit(exitCodeForArgsError(err));
    };

    if (cli.show_help) {
        try std.Io.File.writeStreamingAll(.stdout(), io, UsageText);
        return;
    }

    if (cli.show_version) {
        try std.Io.File.writeStreamingAll(.stdout(), io, VersionText);
        return;
    }

    if (cli.config_path.len == 0) {
        log.info("using built-in default configuration", .{});
    } else {
        log.info("loading configuration from '{s}'", .{cli.config_path});
    }

    var conf = if (cli.config_path.len == 0)
        Config.init(allocator)
    else
        conf_parser.parseFile(io, allocator, cli.config_path) catch |err| {
            log.err("failed to load config '{s}': {}", .{ cli.config_path, err });
            return err;
        };
    defer conf.deinit();

    // Daemonize if not running in foreground mode
    if (!cli.foreground) {
        daemon.daemonize() catch |err| {
            log.err("failed to daemonize: {}", .{err});
            return err;
        };
    }

    // Write PID file if configured
    if (conf.pid_file) |pid_path| {
        daemon.writePidFile(io, pid_path) catch |err| {
            log.err("failed to write PID file '{s}': {}", .{ pid_path, err });
            return err;
        };
        log.info("wrote PID file '{s}'", .{pid_path});
    }

    try logger.init(io, &conf);
    defer logger.deinit();
    const log_backend = if (conf.use_syslog) "syslog" else if (conf.log_file != null) "file" else "stderr";
    log.info("logging initialized backend={s} level={s}", .{ log_backend, @tagName(conf.log_level) });

    // Initialize statistics start time
    stats.global.initStartTime();

    const zrt = try zio.Runtime.init(allocator, .{ .executors = .exact(1) });
    defer zrt.deinit();

    // Setup signal handlers
    try signals.setup();
    defer signals.cleanup();

    // Clean up PID file on exit
    defer {
        if (conf.pid_file) |pid_path| {
            daemon.removePidFile(io, pid_path);
        }
    }

    var handle = try zrt.spawn(main_task, .{ zrt, io, &conf, cli.config_path });
    try handle.join();
}

fn main_task(rt: *zio.Runtime, io: std.Io, conf: *Config, config_path: []const u8) !void {
    try child.listen_socket(rt, conf);
    defer child.close_listen_sockets();
    try child.main_loop(rt, io, conf, config_path);
}

const ExpectedCliOptions = struct {
    config_path: []const u8 = DefaultConfigPath,
    foreground: bool = false,
    show_help: bool = false,
    show_version: bool = false,
};

fn expectParseArgs(args: []const []const u8, expected: ExpectedCliOptions) !void {
    const cli = try parseArgs(args);
    try std.testing.expectEqualStrings(expected.config_path, cli.config_path);
    try std.testing.expectEqual(expected.foreground, cli.foreground);
    try std.testing.expectEqual(expected.show_help, cli.show_help);
    try std.testing.expectEqual(expected.show_version, cli.show_version);
}

fn expectInvalidArgs(args: []const []const u8) !void {
    try std.testing.expectError(error.InvalidArgs, parseArgs(args));
}

test "parseArgs accepts upstream short options" {
    try expectParseArgs(&.{"tinyproxy"}, .{});
    try expectParseArgs(&.{ "tinyproxy", "-d", "-c", "test.conf" }, .{
        .config_path = "test.conf",
        .foreground = true,
    });
    try expectParseArgs(&.{ "tinyproxy", "-h" }, .{
        .show_help = true,
    });
    try expectParseArgs(&.{ "tinyproxy", "-v" }, .{
        .show_version = true,
    });
}

test "VersionText uses build package version" {
    try std.testing.expectEqualStrings("tinyproxy " ++ build_options.version ++ "\n", VersionText);
}

test "parseArgs rejects non-upstream argument forms" {
    const invalid_args = [_][]const []const u8{
        &.{ "tinyproxy", "-c" },
        &.{ "tinyproxy", "--config", "conf/tinyproxy.conf" },
        &.{ "tinyproxy", "--foreground" },
        &.{ "tinyproxy", "--help" },
        &.{ "tinyproxy", "--version" },
        &.{ "tinyproxy", "unexpected.conf" },
    };

    for (invalid_args) |args| {
        try expectInvalidArgs(args);
    }
}

test "parseArgsDetailed records diagnostics for usage failures" {
    var detail: ArgsErrorDetail = .{ .illegal_option = '?' };
    try std.testing.expectError(error.InvalidArgs, parseArgsDetailed(&.{ "tinyproxy", "-c" }, &detail));
    try std.testing.expectEqual(ArgsErrorDetail{ .missing_argument = 'c' }, detail);

    detail = .{ .illegal_option = '?' };
    try std.testing.expectError(error.InvalidArgs, parseArgsDetailed(&.{ "tinyproxy", "-x" }, &detail));
    try std.testing.expectEqual(ArgsErrorDetail{ .illegal_option = 'x' }, detail);
    try std.testing.expectEqual(ExitUsage, exitCodeForArgsError(error.InvalidArgs));
}
