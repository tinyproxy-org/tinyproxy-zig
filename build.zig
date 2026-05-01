const std = @import("std");

const TestSpec = struct {
    name: []const u8,
    path: []const u8,
    needs_zio: bool = false,
    serial: bool = false,
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // zio: coroutine and async io
    const zio_mod = b.dependency("zio", .{}).module("zio");

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    exe_mod.addImport("zio", zio_mod);

    const exe = b.addExecutable(.{
        .name = "tinyproxy",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");

    const test_specs = [_]TestSpec{
        .{ .name = "acl-tests", .path = "src/acl.zig", .needs_zio = true },
        .{ .name = "anonymous-tests", .path = "src/anonymous.zig", .needs_zio = true },
        .{ .name = "auth-tests", .path = "src/auth.zig" },
        .{ .name = "buffer-tests", .path = "src/buffer.zig", .needs_zio = true },
        .{ .name = "child-tests", .path = "src/child.zig", .needs_zio = true, .serial = true },
        .{ .name = "conf-tests", .path = "src/conf.zig", .needs_zio = true },
        .{ .name = "config-tests", .path = "src/config.zig", .needs_zio = true },
        .{ .name = "connect-ports-tests", .path = "src/connect_ports.zig", .needs_zio = true },
        .{ .name = "daemon-tests", .path = "src/daemon.zig" },
        .{ .name = "filter-tests", .path = "src/filter.zig" },
        .{ .name = "headers-tests", .path = "src/headers.zig", .needs_zio = true },
        .{ .name = "html-error-tests", .path = "src/html_error.zig" },
        .{ .name = "http-tests", .path = "src/http.zig", .needs_zio = true, .serial = true },
        .{ .name = "log-tests", .path = "src/log.zig" },
        .{ .name = "pool-tests", .path = "src/pool.zig" },
        .{ .name = "proxy-tests", .path = "src/proxy.zig", .needs_zio = true },
        .{ .name = "relay-tests", .path = "src/relay.zig", .needs_zio = true, .serial = true },
        .{ .name = "main-tests", .path = "src/main.zig", .needs_zio = true, .serial = true },
        .{ .name = "request-tests", .path = "src/request.zig", .needs_zio = true },
        .{ .name = "reverse-tests", .path = "src/reverse.zig", .needs_zio = true },
        .{ .name = "signals-tests", .path = "src/signals.zig" },
        .{ .name = "socks-tests", .path = "src/socks.zig", .needs_zio = true },
        .{ .name = "stats-tests", .path = "src/stats.zig" },
        .{ .name = "text-tests", .path = "src/text.zig" },
        .{ .name = "transparent-tests", .path = "src/transparent.zig" },
        .{ .name = "upstream-tests", .path = "src/upstream.zig", .needs_zio = true },
    };

    var previous_serial_run: ?*std.Build.Step.Run = null;

    inline for (test_specs) |spec| {
        const test_mod = b.createModule(.{
            .root_source_file = b.path(spec.path),
            .target = target,
            .optimize = optimize,
        });

        if (spec.needs_zio) {
            test_mod.addImport("zio", zio_mod);
        }

        const tests = b.addTest(.{
            .name = spec.name,
            .root_module = test_mod,
        });
        const run = b.addRunArtifact(tests);

        if (spec.serial) {
            if (previous_serial_run) |previous_run| {
                run.step.dependOn(&previous_run.step);
            }
            previous_serial_run = run;
        }

        test_step.dependOn(&run.step);
    }
}
