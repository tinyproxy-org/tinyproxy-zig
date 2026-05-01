//! Tinyproxy Configuration File Parser
//!
//! Parses tinyproxy-compatible configuration files.
//! Format: Each line contains a keyword followed by value(s).
//! - Lines starting with # are comments
//! - Keywords are case-insensitive
//! - Values containing spaces should be quoted with double-quotes
//!
//! Example:
//!   Port 8888
//!   Listen 127.0.0.1
//!   Anonymous "Host"
//!   ConnectPort 443
//!   ConnectPort 8000-9000

const std = @import("std");
const zio = @import("zio");
const Config = @import("config.zig").Config;
const PortRange = @import("config.zig").PortRange;
const LogLevel = @import("config.zig").LogLevel;
const FilterMode = @import("filter.zig").FilterMode;
const FilterTarget = @import("filter.zig").FilterTarget;
const FilterType = @import("filter.zig").FilterType;

/// Configuration parsing errors
pub const ParseError = error{
    InvalidPort,
    InvalidNumber,
    MissingValue,
    InvalidSyntax,
    UnterminatedQuote,
    InvalidPortRange,
    InvalidLogLevel,
    InvalidBoolean,
    UnknownDirective,
    OutOfMemory,
    ConfigFileTooLarge,
};

/// Known configuration directives
pub const Directive = enum {
    // Network
    port,
    listen,
    bind,
    bind_same,
    timeout,
    max_clients,

    // Logging
    log_file,
    syslog,
    log_level,

    // Daemon
    user,
    group,
    pid_file,

    // Via header
    via_proxy_name,
    disable_via_header,
    xtinyproxy,

    // Anonymous mode
    anonymous,

    // Connect ports
    connect_port,

    // Access control
    allow,
    deny,

    // Basic auth
    basic_auth,
    basic_auth_realm,

    // Filter
    filter,
    filter_type,
    filter_url_over_host,
    filter_urls, // Alias for filter_url_over_host
    filter_casesensitive,
    filter_default_deny,
    filter_extended, // bre/ere flag (we only support fnmatch, so ignored)

    // Reverse proxy
    reverse_path,
    reverse_only,
    reverse_magic,
    reverse_baseurl,

    // Upstream
    upstream,
    no_upstream,

    // Error pages
    error_file,
    default_error_file,
    stat_host,
    stat_file,

    // Add header
    add_header,

    // Transparent proxy
    transparent,

    // Prefork directives (not supported in single-threaded model, ignored with warning)
    max_spare_servers,
    min_spare_servers,
    start_servers,
    max_requests_per_child,

    // Unknown directive (ignored with warning)
    unknown,

    /// Parse directive from string (case-insensitive)
    pub fn fromString(s: []const u8) Directive {
        const directives = .{
            .{ "port", .port },
            .{ "listen", .listen },
            .{ "bind", .bind },
            .{ "bindsame", .bind_same },
            .{ "timeout", .timeout },
            .{ "maxclients", .max_clients },
            .{ "logfile", .log_file },
            .{ "syslog", .syslog },
            .{ "loglevel", .log_level },
            .{ "user", .user },
            .{ "group", .group },
            .{ "pidfile", .pid_file },
            .{ "viaproxyname", .via_proxy_name },
            .{ "disableviaheader", .disable_via_header },
            .{ "xtinyproxy", .xtinyproxy },
            .{ "anonymous", .anonymous },
            .{ "connectport", .connect_port },
            .{ "allow", .allow },
            .{ "deny", .deny },
            .{ "basicauth", .basic_auth },
            .{ "basicauthrealm", .basic_auth_realm },
            .{ "filter", .filter },
            .{ "filtertype", .filter_type },
            .{ "filterurloverhost", .filter_url_over_host },
            .{ "filterurls", .filter_urls }, // Alias
            .{ "filtercasesensitive", .filter_casesensitive },
            .{ "filterdefaultdeny", .filter_default_deny },
            .{ "filterextended", .filter_extended },
            .{ "reversepath", .reverse_path },
            .{ "reverseonly", .reverse_only },
            .{ "reversemagic", .reverse_magic },
            .{ "reversebaseurl", .reverse_baseurl },
            .{ "upstream", .upstream },
            .{ "noupstream", .no_upstream },
            .{ "errorfile", .error_file },
            .{ "defaulterrorfile", .default_error_file },
            .{ "stathost", .stat_host },
            .{ "statfile", .stat_file },
            .{ "addheader", .add_header },
            .{ "transparent", .transparent },
            // Prefork directives (ignored in single-threaded model)
            .{ "maxspareservers", .max_spare_servers },
            .{ "minspareservers", .min_spare_servers },
            .{ "startservers", .start_servers },
            .{ "maxrequestsperchild", .max_requests_per_child },
        };

        // Case-insensitive comparison
        inline for (directives) |entry| {
            if (asciiEqlIgnoreCase(s, entry[0])) {
                return entry[1];
            }
        }
        return .unknown;
    }
};

/// Parse a configuration file from disk
pub fn parseFile(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !Config {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    const stat = file.stat(io) catch |err| {
        std.debug.print("Failed to stat config '{s}': {}\n", .{ path, err });
        return err;
    };
    const max_size = 1024 * 1024; // 1MB max
    if (stat.size > max_size) {
        std.debug.print("Config file '{s}' too large ({d} > {d} bytes). Consider splitting into multiple files.\n", .{ path, stat.size, max_size });
        return error.ConfigFileTooLarge;
    }

    var reader = file.reader(io, &.{});
    const content = try reader.interface.allocRemaining(allocator, .limited(max_size));
    defer allocator.free(content);

    return parseTextWithIo(io, allocator, content);
}

/// Reload an existing config from disk, replacing it on success.
pub fn reloadConfig(io: std.Io, config: *Config, path: []const u8) !void {
    if (path.len == 0) return error.MissingConfigPath;

    var new_config = try parseFile(io, config.allocator, path);
    errdefer new_config.deinit();

    config.deinit();
    config.* = new_config;
}

/// Parse configuration from text.
///
/// Directives that load external files, such as `Filter`, require an explicit
/// I/O backend. Use `parseTextWithIo` for those configs.
pub fn parseText(allocator: std.mem.Allocator, text: []const u8) !Config {
    var config = Config.init(allocator);
    errdefer config.deinit();

    var line_num: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');

    while (lines.next()) |line_raw| {
        line_num += 1;
        const line = std.mem.trim(u8, line_raw, " \t\r");

        // Skip empty lines and comments
        if (line.len == 0 or line[0] == '#') continue;

        if (lineDirective(line)) |directive| {
            if (directive == .filter) return error.MissingIoBackend;
        }

        // Parse the line with a failing I/O backend. The pre-scan above keeps
        // the public API usable for in-memory configs while rejecting external
        // file directives with an explicit error.
        try parseLine(std.Io.failing, allocator, &config, line);
    }

    return config;
}

/// Parse configuration from text with an explicit I/O backend for directives
/// that load external files.
pub fn parseTextWithIo(io: std.Io, allocator: std.mem.Allocator, text: []const u8) !Config {
    var config = Config.init(allocator);
    errdefer config.deinit();

    var line_num: usize = 0;
    var lines = std.mem.splitScalar(u8, text, '\n');

    while (lines.next()) |line_raw| {
        line_num += 1;
        const line = std.mem.trim(u8, line_raw, " \t\r");

        // Skip empty lines and comments
        if (line.len == 0 or line[0] == '#') continue;

        // Parse the line
        try parseLine(io, allocator, &config, line);
    }

    return config;
}

/// Parse a single configuration line
fn parseLine(io: std.Io, allocator: std.mem.Allocator, config: *Config, line: []const u8) !void {
    // Split into keyword and rest
    var iter = std.mem.tokenizeAny(u8, line, " \t");
    const keyword = iter.next() orelse return;
    const rest = iter.rest();

    const directive = Directive.fromString(keyword);

    switch (directive) {
        .port => {
            const value = try parseValue(rest, false);
            config.port = std.fmt.parseInt(u16, value, 10) catch return error.InvalidPort;
        },
        .listen => {
            const value = try parseValue(rest, false);
            try validateIpLiteral(value);
            config.addListenAddress(value) catch return error.OutOfMemory;
        },
        .timeout => {
            const value = try parseValue(rest, false);
            config.idle_timeout = std.fmt.parseInt(u32, value, 10) catch return error.InvalidNumber;
        },
        .max_clients => {
            const value = try parseValue(rest, false);
            config.max_clients = std.fmt.parseInt(usize, value, 10) catch return error.InvalidNumber;
        },
        .log_file => {
            const value = try parseValue(rest, true);
            const duped = try allocator.dupe(u8, value);
            if (config.log_file) |old| {
                if (config.log_file_owned) allocator.free(@constCast(old));
            }
            config.log_file = duped;
            config.log_file_owned = true;
        },
        .log_level => {
            const value = try parseValue(rest, false);
            config.log_level = parseLogLevel(value) orelse return error.InvalidLogLevel;
        },
        .user => {
            const value = try parseValue(rest, false);
            const duped = try allocator.dupe(u8, value);
            if (config.user) |old| {
                if (config.user_owned) allocator.free(@constCast(old));
            }
            config.user = duped;
            config.user_owned = true;
        },
        .group => {
            const value = try parseValue(rest, false);
            const duped = try allocator.dupe(u8, value);
            if (config.group) |old| {
                if (config.group_owned) allocator.free(@constCast(old));
            }
            config.group = duped;
            config.group_owned = true;
        },
        .pid_file => {
            const value = try parseValue(rest, true);
            const duped = try allocator.dupe(u8, value);
            if (config.pid_file) |old| {
                if (config.pid_file_owned) allocator.free(@constCast(old));
            }
            config.pid_file = duped;
            config.pid_file_owned = true;
        },
        .via_proxy_name => {
            const value = try parseValue(rest, true);
            const duped = try allocator.dupe(u8, value);
            if (config.via_proxy_name) |old| {
                if (config.via_proxy_name_owned) allocator.free(@constCast(old));
            }
            config.via_proxy_name = duped;
            config.via_proxy_name_owned = true;
        },
        .disable_via_header => {
            const value = try parseValue(rest, false);
            config.disable_via_header = parseBoolean(value) orelse return error.InvalidBoolean;
        },
        .anonymous => {
            const value = try parseValue(rest, true);
            try config.allowAnonymousHeader(value);
            config.anonymous_enabled = true;
        },
        .connect_port => {
            const value = try parseValue(rest, false);
            try parseConnectPort(config, value);
        },
        .syslog => {
            const value = try parseValue(rest, false);
            config.use_syslog = parseBoolean(value) orelse return error.InvalidBoolean;
        },
        .allow => {
            const value = try parseValue(rest, false);
            config.acl.allow(value) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    std.log.warn("Ignoring invalid Allow rule: {s}", .{value});
                },
            };
        },
        .deny => {
            const value = try parseValue(rest, false);
            config.acl.deny(value) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => {
                    std.log.warn("Ignoring invalid Deny rule: {s}", .{value});
                },
            };
        },
        .basic_auth => {
            // Format: BasicAuth user password
            var auth_iter = std.mem.tokenizeAny(u8, rest, " \t");
            const user = auth_iter.next() orelse return error.MissingValue;
            const pass = auth_iter.next() orelse return error.MissingValue;
            config.auth.addUser(user, pass) catch return error.OutOfMemory;
        },

        // Directives that need future phases (store raw for now)
        .upstream => {
            config.upstream.addUpstream(rest) catch |err| {
                return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.InvalidPort,
                };
            };
        },
        .no_upstream => {
            config.upstream.addNoUpstream(rest) catch return error.OutOfMemory;
        },

        // Filter configuration
        .filter => {
            const value = try parseValue(rest, true);
            config.loadFilterFile(io, value) catch |err| {
                return switch (err) {
                    error.OutOfMemory => error.OutOfMemory,
                    else => error.MissingValue, // File not found or read error
                };
            };
        },
        .filter_type => {
            const value = try parseValue(rest, false);
            // tinyproxy supports: bre, ere, fnmatch
            if (asciiEqlIgnoreCase(value, "fnmatch")) {
                config.filter.filter_type = .fnmatch;
            } else if (asciiEqlIgnoreCase(value, "bre")) {
                config.filter.filter_type = .bre;
            } else if (asciiEqlIgnoreCase(value, "ere")) {
                config.filter.filter_type = .ere;
            }
            // Unknown types default to fnmatch (tinyproxy C behavior)
        },
        .filter_url_over_host => {
            const value = try parseValue(rest, false);
            const enabled = parseBoolean(value) orelse return error.InvalidBoolean;
            config.filter.target = if (enabled) FilterTarget.url else FilterTarget.host;
        },
        .filter_casesensitive => {
            const value = try parseValue(rest, false);
            config.filter.case_sensitive = parseBoolean(value) orelse return error.InvalidBoolean;
        },
        .filter_default_deny => {
            const value = try parseValue(rest, false);
            const enabled = parseBoolean(value) orelse return error.InvalidBoolean;
            config.filter.mode = if (enabled) FilterMode.default_deny else FilterMode.default_allow;
        },

        // Reverse proxy
        .reverse_path => {
            // tinyproxy syntax: ReversePath "path" "url" OR ReversePath "url"
            // Single-argument form maps "/" to the provided URL.
            const parsed = try parseReversePath(rest);
            const path = parsed.path orelse "/";
            config.reverse.addPath(path, parsed.url) catch return error.OutOfMemory;
        },

        .add_header => {
            const parts = try parseTwoValues(rest);
            try config.addHeader(parts.first, parts.second);
        },

        .stat_host => {
            const value = try parseValue(rest, true);
            const duped = try allocator.dupe(u8, value);
            if (config.stat_host) |old| {
                if (config.stat_host_owned) allocator.free(@constCast(old));
            }
            config.stat_host = duped;
            config.stat_host_owned = true;
        },

        .default_error_file => {
            const value = try parseValue(rest, true);
            const duped = try allocator.dupe(u8, value);
            if (config.default_error_file) |old| {
                if (config.default_error_file_owned) allocator.free(@constCast(old));
            }
            config.default_error_file = duped;
            config.default_error_file_owned = true;
        },
        .error_file => {
            // Format: ErrorFile 404 "/path/to/404.html"
            const parts = try parseTwoValues(rest);
            const status = std.fmt.parseInt(u16, parts.first, 10) catch return error.InvalidNumber;
            const duped = try allocator.dupe(u8, parts.second);
            // Remove old entry if exists
            if (config.error_files.fetchRemove(status)) |entry| {
                allocator.free(@constCast(entry.value));
            }
            try config.error_files.put(status, duped);
        },

        .reverse_only => {
            const value = try parseValue(rest, false);
            config.reverse.reverse_only = parseBoolean(value) orelse return error.InvalidBoolean;
        },
        .reverse_baseurl => {
            const value = try parseValue(rest, true);
            config.reverse.setBaseUrl(value) catch return error.OutOfMemory;
        },

        .xtinyproxy => {
            const value = try parseValue(rest, false);
            config.xtinyproxy = parseBoolean(value) orelse return error.InvalidBoolean;
        },

        .bind => {
            const value = try parseValue(rest, false);
            try validateIpLiteral(value);
            config.addBindAddress(value) catch return error.OutOfMemory;
        },

        .bind_same => {
            const value = try parseValue(rest, false);
            config.bind_same = parseBoolean(value) orelse return error.InvalidBoolean;
        },

        .stat_file => {
            const value = try parseValue(rest, true);
            const duped = try allocator.dupe(u8, value);
            if (config.stat_file_owned) {
                if (config.stat_file) |old| allocator.free(@constCast(old));
            }
            config.stat_file = duped;
            config.stat_file_owned = true;
        },

        .reverse_magic => {
            const value = try parseValue(rest, false);
            config.reverse.reverse_magic = parseBoolean(value) orelse return error.InvalidBoolean;
        },

        .transparent => {
            const value = try parseValue(rest, false);
            config.transparent = parseBoolean(value) orelse return error.InvalidBoolean;
        },

        .basic_auth_realm => {
            const value = try parseValue(rest, true);
            const duped = try allocator.dupe(u8, value);
            if (config.auth.realm_owned) {
                allocator.free(@constCast(config.auth.realm));
            }
            config.auth.realm = duped;
            config.auth.realm_owned = true;
        },

        .filter_urls => {
            // Alias for filter_url_over_host
            const value = try parseValue(rest, false);
            const enabled = parseBoolean(value) orelse return error.InvalidBoolean;
            config.filter.target = if (enabled) FilterTarget.url else FilterTarget.host;
        },

        .filter_extended => {
            // tinyproxy C uses FilterExtended Yes to enable ERE
            const value = try parseValue(rest, false);
            const enabled = parseBoolean(value) orelse return error.InvalidBoolean;
            if (enabled) {
                config.filter.filter_type = .ere;
            }
        },

        // Prefork directives - not supported in single-threaded coroutine model
        // These are ignored but should log a warning in production
        .max_spare_servers, .min_spare_servers, .start_servers, .max_requests_per_child => {
            // Prefork directives not applicable to single-threaded coroutine model
            std.log.warn("Ignoring obsolete/prefork directive in single-threaded mode", .{});
        },

        .unknown => {
            // tinyproxy C rejects unknown directives with a syntax error.
            return error.UnknownDirective;
        },
    }
}

fn lineDirective(line: []const u8) ?Directive {
    var iter = std.mem.tokenizeAny(u8, line, " \t");
    const keyword = iter.next() orelse return null;
    return Directive.fromString(keyword);
}

/// Parse a value from the rest of the line
/// Handles quoted strings if allow_quoted is true
fn parseValue(rest: []const u8, allow_quoted: bool) ![]const u8 {
    const trimmed = std.mem.trim(u8, rest, " \t");
    if (trimmed.len == 0) return error.MissingValue;

    if (allow_quoted and trimmed[0] == '"') {
        // Find closing quote
        const end = std.mem.indexOfScalarPos(u8, trimmed, 1, '"') orelse return error.UnterminatedQuote;
        return trimmed[1..end];
    }

    // Return first token (up to space)
    var iter = std.mem.tokenizeAny(u8, trimmed, " \t");
    return iter.next() orelse error.MissingValue;
}

fn parseToken(input: *[]const u8) ![]const u8 {
    var trimmed = std.mem.trimStart(u8, input.*, " \t");
    if (trimmed.len == 0) return error.MissingValue;

    if (trimmed[0] == '"') {
        const end = std.mem.indexOfScalarPos(u8, trimmed, 1, '"') orelse return error.UnterminatedQuote;
        const token = trimmed[1..end];
        trimmed = trimmed[end + 1 ..];
        input.* = trimmed;
        return token;
    }

    const end = std.mem.indexOfAny(u8, trimmed, " \t") orelse {
        input.* = trimmed[trimmed.len..];
        return trimmed;
    };
    const token = trimmed[0..end];
    trimmed = trimmed[end..];
    input.* = trimmed;
    return token;
}

fn parseTwoValues(rest: []const u8) !struct { first: []const u8, second: []const u8 } {
    var input = std.mem.trim(u8, rest, " \t");
    if (input.len == 0) return error.MissingValue;

    const first = try parseToken(&input);
    const second = try parseToken(&input);
    _ = parseToken(&input) catch |err| switch (err) {
        error.MissingValue => return .{ .first = first, .second = second },
        else => return err,
    };
    return error.InvalidSyntax;
}

fn parseReversePath(rest: []const u8) !struct { path: ?[]const u8, url: []const u8 } {
    var input = std.mem.trim(u8, rest, " \t");
    if (input.len == 0) return error.MissingValue;

    const first = try parseToken(&input);
    const second = parseToken(&input) catch |err| switch (err) {
        error.MissingValue => null,
        else => return err,
    };

    // Reject extra tokens so behavior matches strict config parsing.
    _ = parseToken(&input) catch |err| switch (err) {
        error.MissingValue => return if (second) |url|
            .{ .path = first, .url = url }
        else
            .{ .path = null, .url = first },
        else => return err,
    };
    return error.InvalidSyntax;
}

/// Parse log level string to enum
fn parseLogLevel(s: []const u8) ?LogLevel {
    const levels = .{
        .{ "critical", LogLevel.critical },
        .{ "error", LogLevel.err },
        .{ "warning", LogLevel.warning },
        .{ "notice", LogLevel.notice },
        .{ "connect", LogLevel.notice }, // Connect maps to notice
        .{ "info", LogLevel.info },
    };

    inline for (levels) |entry| {
        if (asciiEqlIgnoreCase(s, entry[0])) {
            return entry[1];
        }
    }
    return null;
}

/// Parse boolean value (Yes/No, On/Off, True/False, 1/0)
fn parseBoolean(s: []const u8) ?bool {
    const true_values = [_][]const u8{ "yes", "on", "true", "1" };
    const false_values = [_][]const u8{ "no", "off", "false", "0" };

    for (true_values) |v| {
        if (asciiEqlIgnoreCase(s, v)) return true;
    }
    for (false_values) |v| {
        if (asciiEqlIgnoreCase(s, v)) return false;
    }
    return null;
}

/// Parse connect port specification (e.g., "443" or "8000-9000")
fn parseConnectPort(config: *Config, value: []const u8) !void {
    // Validate input length to prevent overflow
    if (value.len == 0 or value.len > 11) return error.InvalidPort; // Max "65535-65535"

    // Check for range (contains '-')
    if (std.mem.indexOfScalar(u8, value, '-')) |dash_pos| {
        if (dash_pos == 0 or dash_pos == value.len - 1) return error.InvalidPortRange;

        const min_str = value[0..dash_pos];
        const max_str = value[dash_pos + 1 ..];

        // Validate lengths to prevent overflow (max 5 digits per port)
        if (min_str.len == 0 or min_str.len > 5) return error.InvalidPortRange;
        if (max_str.len == 0 or max_str.len > 5) return error.InvalidPortRange;

        const min = std.fmt.parseInt(u16, min_str, 10) catch return error.InvalidPortRange;
        const max = std.fmt.parseInt(u16, max_str, 10) catch return error.InvalidPortRange;

        if (min > max) return error.InvalidPortRange;

        try config.allowConnectPortRange(min, max);
    } else {
        // Single port
        const port = std.fmt.parseInt(u16, value, 10) catch return error.InvalidPort;
        try config.allowConnectPort(port);
    }
}

/// Case-insensitive ASCII string comparison
/// Uses std.ascii.eqlIgnoreCase for better performance
inline fn asciiEqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn validateIpLiteral(value: []const u8) !void {
    _ = zio.net.IpAddress.parseIp(value, 0) catch return error.InvalidSyntax;
}

// ============================================================================
// Tests
// ============================================================================

test "parse basic config" {
    const allocator = std.testing.allocator;
    const text =
        \\# Tinyproxy config
        \\Port 8888
        \\Listen 0.0.0.0
        \\Timeout 120
        \\MaxClients 50
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 8888), config.port);
    try std.testing.expectEqual(@as(usize, 1), config.listen_addrs.items.len);
    try std.testing.expectEqualStrings("0.0.0.0", config.listen_addrs.items[0]);
    try std.testing.expectEqual(@as(u32, 120), config.idle_timeout);
    try std.testing.expectEqual(@as(usize, 50), config.max_clients);
}

test "parse case insensitive directives" {
    const allocator = std.testing.allocator;
    const text =
        \\PORT 9000
        \\port 9001
        \\PoRt 9002
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    // Last value wins
    try std.testing.expectEqual(@as(u16, 9002), config.port);
}

test "parse multiple listen directives preserves order" {
    const allocator = std.testing.allocator;
    const text =
        \\Listen 127.0.0.1
        \\Listen ::1
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expectEqual(@as(usize, 2), config.listen_addrs.items.len);
    try std.testing.expectEqualStrings("127.0.0.1", config.listen_addrs.items[0]);
    try std.testing.expectEqualStrings("::1", config.listen_addrs.items[1]);
}

test "parse invalid listen address fails" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.InvalidSyntax, parseText(allocator, "Listen not-an-ip"));
}

test "parse multiple bind directives preserves order" {
    const allocator = std.testing.allocator;
    const text =
        \\Bind 127.0.0.1
        \\Bind ::1
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expectEqual(@as(usize, 2), config.bind_addrs.items.len);
    try std.testing.expectEqualStrings("127.0.0.1", config.bind_addrs.items[0]);
    try std.testing.expectEqualStrings("::1", config.bind_addrs.items[1]);
}

test "parse quoted values" {
    const allocator = std.testing.allocator;
    const text =
        \\LogFile "/var/log/tinyproxy.log"
        \\ViaProxyName "My Proxy Server"
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expectEqualStrings("/var/log/tinyproxy.log", config.log_file.?);
    try std.testing.expectEqualStrings("My Proxy Server", config.via_proxy_name.?);
}

test "parseText rejects file-backed directives without I/O backend" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.MissingIoBackend, parseText(allocator, "Filter /tmp/filter\n"));
}

test "parse anonymous headers" {
    const allocator = std.testing.allocator;
    const text =
        \\Anonymous "Host"
        \\Anonymous "Accept"
        \\Anonymous "Cookie"
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expect(config.anonymous_enabled);
    try std.testing.expect(config.isAnonymousHeaderAllowed("Host"));
    try std.testing.expect(config.isAnonymousHeaderAllowed("Accept"));
    try std.testing.expect(config.isAnonymousHeaderAllowed("Cookie"));
    try std.testing.expect(!config.isAnonymousHeaderAllowed("User-Agent"));
}

test "parse connect ports" {
    const allocator = std.testing.allocator;
    const text =
        \\ConnectPort 443
        \\ConnectPort 563
        \\ConnectPort 8000-9000
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expect(config.isConnectPortAllowed(443));
    try std.testing.expect(config.isConnectPortAllowed(563));
    try std.testing.expect(config.isConnectPortAllowed(8500));
    try std.testing.expect(!config.isConnectPortAllowed(80));
    try std.testing.expect(!config.isConnectPortAllowed(9001));
}

test "parse log level" {
    const allocator = std.testing.allocator;

    {
        const text = "LogLevel Critical";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expectEqual(LogLevel.critical, config.log_level);
    }

    {
        const text = "LogLevel Info";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expectEqual(LogLevel.info, config.log_level);
    }
}

test "parse boolean values" {
    const allocator = std.testing.allocator;

    {
        const text = "DisableViaHeader Yes";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expect(config.disable_via_header);
    }

    {
        const text = "Syslog On";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expect(config.use_syslog);
    }
}

test "parse daemon settings" {
    const allocator = std.testing.allocator;
    const text =
        \\User nobody
        \\Group nogroup
        \\PidFile "/var/run/tinyproxy.pid"
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expectEqualStrings("nobody", config.user.?);
    try std.testing.expectEqualStrings("nogroup", config.group.?);
    try std.testing.expectEqualStrings("/var/run/tinyproxy.pid", config.pid_file.?);
}

test "parse addheader directive" {
    const allocator = std.testing.allocator;
    const text =
        \\AddHeader X-Test 123
        \\AddHeader X-Note "hello world"
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expectEqual(@as(usize, 2), config.add_headers.items.len);
    try std.testing.expectEqualStrings("X-Test", config.add_headers.items[0].name);
    try std.testing.expectEqualStrings("123", config.add_headers.items[0].value);
    try std.testing.expectEqualStrings("X-Note", config.add_headers.items[1].name);
    try std.testing.expectEqualStrings("hello world", config.add_headers.items[1].value);
}

test "parse addheader rejects extra tokens" {
    const allocator = std.testing.allocator;
    const text = "AddHeader X-Test 123 extra";
    try std.testing.expectError(error.InvalidSyntax, parseText(allocator, text));
}

test "unknown directives fail parsing" {
    const allocator = std.testing.allocator;
    const text =
        \\Port 8888
        \\UnknownDirective value
    ;

    try std.testing.expectError(error.UnknownDirective, parseText(allocator, text));
}

test "skip comments and empty lines" {
    const allocator = std.testing.allocator;
    const text =
        \\# This is a comment
        \\
        \\Port 8888
        \\# Another comment
        \\
        \\Timeout 60
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 8888), config.port);
    try std.testing.expectEqual(@as(u32, 60), config.idle_timeout);
}

test "parse acl rules" {
    const allocator = std.testing.allocator;
    const text =
        \\Deny 0.0.0.0/0
        \\Allow 127.0.0.1
        \\Allow 192.168.0.0/16
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    const localhost = zio.net.IpAddress.initIp4(.{ 127, 0, 0, 1 }, 0);
    const internal = zio.net.IpAddress.initIp4(.{ 192, 168, 1, 100 }, 0);
    const external = zio.net.IpAddress.initIp4(.{ 8, 8, 8, 8 }, 0);

    const AclAction = @import("acl.zig").AclAction;
    try std.testing.expectEqual(AclAction.allow, config.acl.check(localhost));
    try std.testing.expectEqual(AclAction.allow, config.acl.check(internal));
    try std.testing.expectEqual(AclAction.deny, config.acl.check(external));
}

test "invalid acl rules are ignored (tinyproxy-compatible)" {
    const allocator = std.testing.allocator;
    const original_log_level = std.testing.log_level;
    std.testing.log_level = .err;
    defer std.testing.log_level = original_log_level;

    const text =
        \\Deny 0.0.0.0/0
        \\Allow not-an-address
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    const localhost = zio.net.IpAddress.initIp4(.{ 127, 0, 0, 1 }, 0);
    const AclAction = @import("acl.zig").AclAction;
    try std.testing.expectEqual(AclAction.deny, config.acl.check(localhost));
}

test "parse basic auth" {
    const allocator = std.testing.allocator;
    const text =
        \\BasicAuth admin secret123
        \\BasicAuth user password
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expect(config.auth.hasCredentials());

    // Test valid credentials (base64 of "admin:secret123")
    try std.testing.expect(config.auth.verify("Basic YWRtaW46c2VjcmV0MTIz"));

    // Test valid credentials for second user (base64 of "user:password")
    try std.testing.expect(config.auth.verify("Basic dXNlcjpwYXNzd29yZA=="));

    // Test wrong password
    try std.testing.expect(!config.auth.verify("Basic YWRtaW46d3JvbmcxMjM="));

    // Test no auth header
    try std.testing.expect(!config.auth.verify(null));
}

test "parse upstream none and auth upstream" {
    const allocator = std.testing.allocator;
    const text =
        \\Upstream socks5 user:pass@127.0.0.1:9050 ".onion"
        \\Upstream none ".internal.example.com"
        \\Upstream http 10.0.0.1:3128
    ;

    var config = try parseText(allocator, text);
    defer config.deinit();

    const onion = config.upstream.findUpstream("hidden.onion");
    try std.testing.expect(onion != null);
    try std.testing.expectEqualStrings("127.0.0.1", onion.?.host);
    try std.testing.expectEqualStrings("user", onion.?.user.?);
    try std.testing.expectEqualStrings("pass", onion.?.pass.?);

    const internal = config.upstream.findUpstream("svc.internal.example.com");
    try std.testing.expect(internal == null);

    const internet = config.upstream.findUpstream("example.org");
    try std.testing.expect(internet != null);
    try std.testing.expectEqualStrings("10.0.0.1", internet.?.host);
}

test "reload config applies new values" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const filename = "tinyproxy.conf";
    {
        var file = try tmp.dir.createFile(std.testing.io, filename, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "Port 8888\nListen 0.0.0.0\n");
    }

    const path = try tmp.dir.realPathFileAlloc(std.testing.io, filename, allocator);
    defer allocator.free(path);

    var config = Config.init(allocator);
    defer config.deinit();

    try std.testing.expectEqual(@as(u16, 9999), config.port);
    try reloadConfig(std.testing.io, &config, path);
    try std.testing.expectEqual(@as(u16, 8888), config.port);
    try std.testing.expectEqual(@as(usize, 1), config.listen_addrs.items.len);
    try std.testing.expectEqualStrings("0.0.0.0", config.listen_addrs.items[0]);
}

test "reload config keeps previous values on error" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const filename = "tinyproxy.conf";
    {
        var file = try tmp.dir.createFile(std.testing.io, filename, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, "Port not-a-number\n");
    }

    const path = try tmp.dir.realPathFileAlloc(std.testing.io, filename, allocator);
    defer allocator.free(path);

    var config = Config.init(allocator);
    defer config.deinit();

    const original_port = config.port;
    try std.testing.expectError(error.InvalidPort, reloadConfig(std.testing.io, &config, path));
    try std.testing.expectEqual(original_port, config.port);
}

test "parse transparent directive" {
    const allocator = std.testing.allocator;

    {
        const text = "Transparent Yes";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expect(config.transparent);
    }

    {
        const text = "Transparent No";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expect(!config.transparent);
    }

    {
        const text = "Transparent On";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expect(config.transparent);
    }
}

test "parse reverse magic directive" {
    const allocator = std.testing.allocator;

    {
        const text = "ReverseMagic Yes";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expect(config.reverse.reverse_magic);
    }

    {
        const text = "ReverseMagic No";
        var config = try parseText(allocator, text);
        defer config.deinit();
        try std.testing.expect(!config.reverse.reverse_magic);
    }
}

test "parse reversepath single-argument form" {
    const allocator = std.testing.allocator;
    const text = "ReversePath \"http://backend:8080/\"";

    var config = try parseText(allocator, text);
    defer config.deinit();

    try std.testing.expectEqual(@as(usize, 1), config.reverse.paths.items.len);
    try std.testing.expectEqualStrings("/", config.reverse.paths.items[0].path);
    try std.testing.expectEqualStrings("http://backend:8080/", config.reverse.paths.items[0].url);
}
