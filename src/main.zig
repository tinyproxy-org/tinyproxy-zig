const std = @import("std");

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

const ArgsError = error{InvalidArgs};

const CliOptions = struct {
    config_path: []const u8,
    foreground: bool,
};

fn parseArgs(args: []const []const u8) ArgsError!CliOptions {
    var config_path: ?[]const u8 = null;
    var foreground: bool = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--config")) {
            if (i + 1 >= args.len) return error.InvalidArgs;
            config_path = args[i + 1];
            i += 1;
            continue;
        }
        if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--foreground")) {
            foreground = true;
            continue;
        }
        return error.InvalidArgs;
    }
    return .{
        .config_path = config_path orelse DefaultConfigPath,
        .foreground = foreground,
    };
}

fn printUsage() void {
    std.debug.print(
        \\Usage: tinyproxy-zig [OPTIONS]
        \\
        \\Options:
        \\  -c, --config <path>   Path to configuration file
        \\  -d, --foreground      Run in foreground (don't daemonize)
        \\
    , .{});
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

    const cli = parseArgs(args) catch |err| {
        printUsage();
        return err;
    };

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
        log.info("daemonized process", .{});
    } else {
        log.info("running in foreground", .{});
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
    log.info("starting", .{});
    try child.listen_socket(rt, conf);
    defer child.close_listen_sockets();
    log.debug("listeners initialized, entering main loop", .{});
    try child.main_loop(rt, io, conf, config_path);
    log.info("main loop returned", .{});
}

test "parseArgs default path" {
    const args = [_][]const u8{"tinyproxy-zig"};
    const cli = try parseArgs(&args);
    try std.testing.expectEqualStrings("", cli.config_path);
    try std.testing.expect(!cli.foreground);
}

test "parseArgs -c" {
    const args = [_][]const u8{ "tinyproxy-zig", "-c", "./cfg.conf" };
    const cli = try parseArgs(&args);
    try std.testing.expectEqualStrings("./cfg.conf", cli.config_path);
}

test "parseArgs --config" {
    const args = [_][]const u8{ "tinyproxy-zig", "--config", "conf/tinyproxy.conf" };
    const cli = try parseArgs(&args);
    try std.testing.expectEqualStrings("conf/tinyproxy.conf", cli.config_path);
}

test "parseArgs -d foreground" {
    const args = [_][]const u8{ "tinyproxy-zig", "-d" };
    const cli = try parseArgs(&args);
    try std.testing.expect(cli.foreground);
}

test "parseArgs combined options" {
    const args = [_][]const u8{ "tinyproxy-zig", "-d", "-c", "test.conf" };
    const cli = try parseArgs(&args);
    try std.testing.expect(cli.foreground);
    try std.testing.expectEqualStrings("test.conf", cli.config_path);
}

test "parseArgs invalid args" {
    const args_missing = [_][]const u8{ "tinyproxy-zig", "-c" };
    try std.testing.expectError(error.InvalidArgs, parseArgs(&args_missing));

    const args_unknown = [_][]const u8{ "tinyproxy-zig", "--unknown" };
    try std.testing.expectError(error.InvalidArgs, parseArgs(&args_unknown));
}
