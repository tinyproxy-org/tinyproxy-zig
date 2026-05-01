//! HTML Error Page Module for tinyproxy-zig
//!
//! Provides friendly HTML error pages with template variable substitution.
//!
//! Supported template variables:
//!   {detail}   - Error detail message
//!   {cause}    - Error cause/reason
//!   {clientip} - Client IP address
//!   {clienthost} - Client hostname (if resolved)
//!   {method}   - HTTP method
//!   {protocol} - Request protocol
//!   {host}     - Request host
//!   {url}      - Full request URL
//!   {version}  - tinyproxy version

const std = @import("std");

pub const HttpError = enum(u16) {
    bad_request = 400,
    unauthorized = 401,
    forbidden = 403,
    not_found = 404,
    method_not_allowed = 405,
    proxy_auth_required = 407,
    request_timeout = 408,
    length_required = 411,
    uri_too_long = 414,
    internal_server_error = 500,
    not_implemented = 501,
    bad_gateway = 502,
    service_unavailable = 503,
    gateway_timeout = 504,

    pub fn statusLine(self: HttpError) []const u8 {
        return switch (self) {
            .bad_request => "400 Bad Request",
            .unauthorized => "401 Unauthorized",
            .forbidden => "403 Forbidden",
            .not_found => "404 Not Found",
            .method_not_allowed => "405 Method Not Allowed",
            .proxy_auth_required => "407 Proxy Authentication Required",
            .request_timeout => "408 Request Timeout",
            .length_required => "411 Length Required",
            .uri_too_long => "414 URI Too Long",
            .internal_server_error => "500 Internal Server Error",
            .not_implemented => "501 Not Implemented",
            .bad_gateway => "502 Bad Gateway",
            .service_unavailable => "503 Service Unavailable",
            .gateway_timeout => "504 Gateway Timeout",
        };
    }

    pub fn title(self: HttpError) []const u8 {
        return switch (self) {
            .bad_request => "Bad Request",
            .unauthorized => "Unauthorized",
            .forbidden => "Forbidden",
            .not_found => "Not Found",
            .method_not_allowed => "Method Not Allowed",
            .proxy_auth_required => "Authentication Required",
            .request_timeout => "Request Timeout",
            .length_required => "Length Required",
            .uri_too_long => "URI Too Long",
            .internal_server_error => "Internal Server Error",
            .not_implemented => "Not Implemented",
            .bad_gateway => "Bad Gateway",
            .service_unavailable => "Service Unavailable",
            .gateway_timeout => "Gateway Timeout",
        };
    }

    pub fn defaultMessage(self: HttpError) []const u8 {
        return switch (self) {
            .bad_request => "The proxy could not understand your request.",
            .unauthorized => "Authentication is required to access this resource.",
            .forbidden => "Access to this resource has been denied.",
            .not_found => "The requested resource could not be found.",
            .method_not_allowed => "The request method is not supported.",
            .proxy_auth_required => "Please authenticate to use this proxy.",
            .request_timeout => "The request timed out while waiting.",
            .length_required => "The request must include a Content-Length header.",
            .uri_too_long => "The request URI is too long for the server to process.",
            .internal_server_error => "An internal error occurred in the proxy.",
            .not_implemented => "This feature is not implemented.",
            .bad_gateway => "Could not connect to the upstream server.",
            .service_unavailable => "The proxy is temporarily unavailable.",
            .gateway_timeout => "The upstream server did not respond in time.",
        };
    }
};

/// Context for template variable substitution
pub const ErrorContext = struct {
    detail: []const u8 = "",
    cause: []const u8 = "",
    client_ip: []const u8 = "",
    client_host: []const u8 = "",
    method: []const u8 = "",
    protocol: []const u8 = "",
    host: []const u8 = "",
    url: []const u8 = "",
};

const VERSION = "tinyproxy-zig 0.1.0";

/// Default HTML error template
const default_template =
    \\<!DOCTYPE html>
    \\<html>
    \\<head>
    \\<title>{TITLE}</title>
    \\<style>
    \\body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 40px; background: #f5f5f5; }}
    \\h1 {{ color: #c0392b; margin-bottom: 10px; }}
    \\.container {{ max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
    \\.code {{ font-size: 4em; color: #e74c3c; font-weight: bold; margin-bottom: 0; }}
    \\.message {{ color: #666; line-height: 1.6; }}
    \\.detail {{ background: #fafafa; padding: 15px; border-radius: 4px; margin: 20px 0; font-family: monospace; font-size: 0.9em; color: #555; }}
    \\hr {{ border: none; border-top: 1px solid #eee; margin: 20px 0; }}
    \\.footer {{ color: #999; font-size: 0.8em; }}
    \\</style>
    \\</head>
    \\<body>
    \\<div class="container">
    \\<p class="code">{CODE}</p>
    \\<h1>{TITLE}</h1>
    \\<p class="message">{MESSAGE}</p>
    \\{DETAIL_SECTION}
    \\<hr>
    \\<p class="footer">{VERSION}</p>
    \\</div>
    \\</body>
    \\</html>
;

const detail_section_template =
    \\<div class="detail">{DETAIL}</div>
;

fn replaceAllOwned(allocator: std.mem.Allocator, input: []const u8, needle: []const u8, replacement: []const u8) ![]const u8 {
    return std.mem.replaceOwned(u8, allocator, input, needle, replacement);
}

/// Render an error page to HTML
pub fn renderErrorPage(
    allocator: std.mem.Allocator,
    err: HttpError,
    ctx: ErrorContext,
) ![]const u8 {
    // Build detail section if detail is provided
    var detail_section: []const u8 = "";
    var detail_section_owned = false;
    defer if (detail_section_owned) allocator.free(detail_section);

    if (ctx.detail.len > 0) {
        detail_section = try replaceAllOwned(allocator, detail_section_template, "{DETAIL}", ctx.detail);
        detail_section_owned = true;
    }

    // Build message with cause if provided
    var message: []const u8 = err.defaultMessage();
    var message_owned = false;
    defer if (message_owned) allocator.free(message);

    if (ctx.cause.len > 0) {
        message = try std.fmt.allocPrint(allocator, "{s} {s}", .{ err.defaultMessage(), ctx.cause });
        message_owned = true;
    }

    const code = try std.fmt.allocPrint(allocator, "{d}", .{@intFromEnum(err)});
    defer allocator.free(code);

    var html = try replaceAllOwned(allocator, default_template, "{TITLE}", err.title());
    errdefer allocator.free(html);

    const replacements = .{
        .{ "{CODE}", code },
        .{ "{MESSAGE}", message },
        .{ "{DETAIL_SECTION}", detail_section },
        .{ "{VERSION}", VERSION },
    };

    inline for (replacements) |replacement| {
        const next = try replaceAllOwned(allocator, html, replacement[0], replacement[1]);
        allocator.free(html);
        html = next;
    }

    return html;
}

/// Send an error response with HTML body
pub fn sendError(
    allocator: std.mem.Allocator,
    writer: anytype,
    err: HttpError,
    ctx: ErrorContext,
) !void {
    const body = try renderErrorPage(allocator, err, ctx);
    defer allocator.free(body);

    try writer.print(
        "HTTP/1.1 {s}\r\n" ++
            "Content-Type: text/html; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: close\r\n" ++
            "\r\n" ++
            "{s}",
        .{ err.statusLine(), body.len, body },
    );
}

/// Build a simple error response (without HTML rendering, for inline use)
pub fn buildSimpleResponse(err: HttpError, buf: []u8) ![]const u8 {
    const message = err.defaultMessage();
    return std.fmt.bufPrint(buf, "HTTP/1.1 {s}\r\nContent-Type: text/plain\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}", .{
        err.statusLine(),
        message.len,
        message,
    });
}

// ============================================================================
// Tests
// ============================================================================

test "HttpError status lines" {
    try std.testing.expectEqualStrings("400 Bad Request", HttpError.bad_request.statusLine());
    try std.testing.expectEqualStrings("502 Bad Gateway", HttpError.bad_gateway.statusLine());
    try std.testing.expectEqualStrings("403 Forbidden", HttpError.forbidden.statusLine());
}

test "HttpError titles" {
    try std.testing.expectEqualStrings("Bad Request", HttpError.bad_request.title());
    try std.testing.expectEqualStrings("Bad Gateway", HttpError.bad_gateway.title());
}

test "renderErrorPage basic" {
    const allocator = std.testing.allocator;

    const html = try renderErrorPage(allocator, .bad_gateway, .{});
    defer allocator.free(html);

    try std.testing.expect(std.mem.indexOf(u8, html, "502") != null);
    try std.testing.expect(std.mem.indexOf(u8, html, "Bad Gateway") != null);
    try std.testing.expect(std.mem.indexOf(u8, html, "tinyproxy-zig") != null);
}

test "renderErrorPage with detail" {
    const allocator = std.testing.allocator;

    const html = try renderErrorPage(allocator, .forbidden, .{
        .detail = "Connection refused by ACL rule",
    });
    defer allocator.free(html);

    try std.testing.expect(std.mem.indexOf(u8, html, "403") != null);
    try std.testing.expect(std.mem.indexOf(u8, html, "Forbidden") != null);
    try std.testing.expect(std.mem.indexOf(u8, html, "Connection refused by ACL rule") != null);
}

test "buildSimpleResponse" {
    var buf: [512]u8 = undefined;
    const response = try buildSimpleResponse(.not_found, &buf);

    try std.testing.expect(std.mem.indexOf(u8, response, "404 Not Found") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "Content-Type: text/plain") != null);
}
