//! URL/Domain Filtering Module
//!
//! Provides URL/domain-based access control using pattern matching.
//! Supports fnmatch (shell-style wildcards) and basic/extended regex patterns.
//!
//! Compatible with tinyproxy filter configuration:
//! - Filter: path to filter file (one pattern per line)
//! - FilterType: fnmatch (default), bre (basic regex), ere (extended regex)
//! - FilterURLOverHost/FilterURLs: match full URL instead of just host (default: No)
//! - FilterCaseSensitive: case-sensitive matching for bre/ere only (default: No)
//!   Note: fnmatch is ALWAYS case-sensitive per tinyproxy C behavior
//! - FilterExtended: alias for FilterType ere (tinyproxy C compatibility)
//! - FilterDefaultDeny: block by default, whitelist mode (default: No)

const std = @import("std");

/// Filter matching mode
pub const FilterMode = enum {
    /// Patterns specify what to block (blacklist)
    default_allow,
    /// Patterns specify what to allow (whitelist)
    default_deny,
};

/// Filter target - what to match against
pub const FilterTarget = enum {
    /// Match against host only
    host,
    /// Match against full URL
    url,
};

/// Filter pattern type - matches tinyproxy C FilterType directive
///
/// NOTE: BRE and ERE modes use simple substring matching, not full POSIX regex.
/// This covers most common use cases but does not support regex metacharacters
/// like ., ^, $, [], etc. Use fnmatch mode for glob-style wildcards (* and ?).
pub const FilterType = enum {
    /// Shell-style wildcards (* and ?) - always case-sensitive
    fnmatch,
    /// Basic POSIX regex (BRE) - respects FilterCaseSensitive
    /// Note: Currently implements substring matching only
    bre,
    /// Extended POSIX regex (ERE) - respects FilterCaseSensitive
    /// Note: Currently implements substring matching only
    ere,
};

/// Compiled pattern entry
const Pattern = struct {
    /// The pattern string (owned)
    pattern: []const u8,
};

/// URL/Domain Filter
pub const Filter = struct {
    allocator: std.mem.Allocator,
    /// Loaded patterns
    patterns: std.ArrayList(Pattern),
    /// Default behavior: allow or deny
    mode: FilterMode,
    /// Match host or full URL
    target: FilterTarget,
    /// Pattern matching type (fnmatch, bre, ere)
    filter_type: FilterType,
    /// Case-sensitive matching for bre/ere only (fnmatch is always case-sensitive)
    case_sensitive: bool,
    /// Whether filter is enabled (patterns loaded)
    enabled: bool,

    const Self = @This();

    /// Initialize filter with default settings
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .patterns = std.ArrayList(Pattern).empty,
            .mode = .default_allow,
            .target = .host,
            .filter_type = .fnmatch,
            .case_sensitive = false, // Only applies to bre/ere
            .enabled = false,
        };
    }

    /// Deinitialize and free all resources
    pub fn deinit(self: *Self) void {
        for (self.patterns.items) |entry| {
            self.allocator.free(entry.pattern);
        }
        self.patterns.deinit(self.allocator);
    }

    /// Load patterns from a file (one pattern per line)
    /// Lines starting with # are comments
    /// Empty lines are ignored
    pub fn loadFromFile(self: *Self, io: std.Io, path: []const u8) !void {
        const content = try std.Io.Dir.cwd().readFileAlloc(io, path, self.allocator, .limited(10 * 1024 * 1024));
        defer self.allocator.free(content);

        try self.loadFromText(content);
    }

    /// Load patterns from text content (for testing)
    pub fn loadFromText(self: *Self, content: []const u8) !void {
        var lines = std.mem.splitScalar(u8, content, '\n');

        while (lines.next()) |line_raw| {
            const line = std.mem.trim(u8, line_raw, " \t\r");

            // Skip empty lines and comments
            if (line.len == 0 or line[0] == '#') continue;

            try self.addPattern(line);
        }

        self.enabled = self.patterns.items.len > 0;
    }

    /// Add a single pattern
    pub fn addPattern(self: *Self, pattern: []const u8) !void {
        const duped = try self.allocator.dupe(u8, pattern);
        errdefer self.allocator.free(duped);

        try self.patterns.append(self.allocator, .{ .pattern = duped });
    }

    /// Check if a URL/host should be blocked
    /// Returns true if access should be blocked
    pub fn isBlocked(self: *const Self, input: []const u8) bool {
        if (!self.enabled) return false;

        const matched = self.matchesAnyPattern(input);

        return switch (self.mode) {
            .default_allow => matched, // Block if matched
            .default_deny => !matched, // Block if NOT matched
        };
    }

    /// Check if input matches any loaded pattern
    fn matchesAnyPattern(self: *const Self, input: []const u8) bool {
        switch (self.filter_type) {
            .fnmatch => {
                // fnmatch is ALWAYS case-sensitive per tinyproxy C behavior
                for (self.patterns.items) |entry| {
                    if (fnmatch(entry.pattern, input)) {
                        return true;
                    }
                }
                return false;
            },
            .bre, .ere => {
                // BRE/ERE: respect case_sensitive setting
                var input_buf: [4096]u8 = undefined;
                const match_input = if (!self.case_sensitive)
                    toLowerBuf(input, &input_buf)
                else
                    input;

                for (self.patterns.items) |entry| {
                    var pattern_buf: [4096]u8 = undefined;
                    const match_pattern = if (!self.case_sensitive)
                        toLowerBuf(entry.pattern, &pattern_buf)
                    else
                        entry.pattern;

                    // Use simple substring/glob match for BRE/ERE
                    // (Full POSIX regex would require external library or complex implementation)
                    // For now, treat as substring match which covers most use cases
                    if (std.mem.indexOf(u8, match_input, match_pattern) != null) {
                        return true;
                    }
                }
                return false;
            },
        }
    }

    /// Extract host from URL for matching
    pub fn extractHost(url: []const u8) []const u8 {
        // Skip scheme (http://, https://)
        var rest = url;
        if (std.mem.indexOf(u8, rest, "://")) |idx| {
            rest = rest[idx + 3 ..];
        }

        // Find end of host (port, path, or end)
        const host_end = blk: {
            for (rest, 0..) |c, i| {
                if (c == ':' or c == '/' or c == '?' or c == '#') {
                    break :blk i;
                }
            }
            break :blk rest.len;
        };

        return rest[0..host_end];
    }
};

/// Convert string to lowercase in provided buffer
fn toLowerBuf(input: []const u8, buf: []u8) []const u8 {
    const len = @min(input.len, buf.len);
    for (input[0..len], 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    return buf[0..len];
}

/// Simple fnmatch implementation supporting * and ? wildcards
/// * matches any sequence of characters
/// ? matches any single character
fn fnmatch(pattern: []const u8, input: []const u8) bool {
    var pi: usize = 0; // pattern index
    var si: usize = 0; // string index
    var star_pi: ?usize = null; // position after last *
    var star_si: usize = 0; // string position at last *

    while (si < input.len or pi < pattern.len) {
        if (pi < pattern.len) {
            const pc = pattern[pi];

            if (pc == '*') {
                // Remember this position
                star_pi = pi + 1;
                star_si = si;
                pi += 1;
                continue;
            }

            if (si < input.len) {
                if (pc == '?' or pc == input[si]) {
                    pi += 1;
                    si += 1;
                    continue;
                }
            }
        }

        // Mismatch - try advancing from last * position
        if (star_pi) |sp| {
            pi = sp;
            star_si += 1;
            si = star_si;
            if (si <= input.len) continue;
        }

        return false;
    }

    return true;
}

// ============================================================================
// Tests
// ============================================================================

test "fnmatch - exact match" {
    try std.testing.expect(fnmatch("hello", "hello"));
    try std.testing.expect(!fnmatch("hello", "world"));
    try std.testing.expect(!fnmatch("hello", "hell"));
    try std.testing.expect(!fnmatch("hello", "helloo"));
}

test "fnmatch - wildcard *" {
    try std.testing.expect(fnmatch("*", "anything"));
    try std.testing.expect(fnmatch("*", ""));
    try std.testing.expect(fnmatch("hello*", "hello"));
    try std.testing.expect(fnmatch("hello*", "helloworld"));
    try std.testing.expect(fnmatch("*world", "helloworld"));
    try std.testing.expect(fnmatch("*world", "world"));
    try std.testing.expect(fnmatch("he*ld", "helloworld"));
    try std.testing.expect(fnmatch("*o*o*", "helloworld"));
    try std.testing.expect(!fnmatch("hello*", "hell"));
    try std.testing.expect(!fnmatch("*world", "worldwide"));
}

test "fnmatch - wildcard ?" {
    try std.testing.expect(fnmatch("h?llo", "hello"));
    try std.testing.expect(fnmatch("h?llo", "hallo"));
    try std.testing.expect(!fnmatch("h?llo", "hllo"));
    try std.testing.expect(!fnmatch("h?llo", "heello"));
    try std.testing.expect(fnmatch("???", "abc"));
    try std.testing.expect(!fnmatch("???", "ab"));
    try std.testing.expect(!fnmatch("???", "abcd"));
}

test "fnmatch - combined wildcards" {
    try std.testing.expect(fnmatch("*.example.com", "www.example.com"));
    try std.testing.expect(fnmatch("*.example.com", "sub.example.com"));
    try std.testing.expect(fnmatch("*.example.com", ".example.com"));
    try std.testing.expect(!fnmatch("*.example.com", "example.com"));
    try std.testing.expect(fnmatch("*example*", "www.example.com"));
    try std.testing.expect(fnmatch("*.*.com", "www.example.com"));
}

test "Filter init and deinit" {
    const allocator = std.testing.allocator;
    var filter = Filter.init(allocator);
    defer filter.deinit();

    try std.testing.expect(!filter.enabled);
    try std.testing.expectEqual(FilterMode.default_allow, filter.mode);
    try std.testing.expectEqual(FilterTarget.host, filter.target);
    try std.testing.expectEqual(FilterType.fnmatch, filter.filter_type);
    try std.testing.expect(!filter.case_sensitive); // Only affects bre/ere
}

test "Filter loadFromText" {
    const allocator = std.testing.allocator;
    var filter = Filter.init(allocator);
    defer filter.deinit();

    const content =
        \\# Block ads
        \\*.ads.example.com
        \\tracking.example.com
        \\
        \\# More patterns
        \\*.doubleclick.net
    ;

    try filter.loadFromText(content);

    try std.testing.expect(filter.enabled);
    try std.testing.expectEqual(@as(usize, 3), filter.patterns.items.len);
}

test "Filter isBlocked - default allow (blacklist)" {
    const allocator = std.testing.allocator;
    var filter = Filter.init(allocator);
    defer filter.deinit();

    const content =
        \\*.ads.example.com
        \\tracking.example.com
        \\*.doubleclick.net
    ;
    try filter.loadFromText(content);

    // Matched patterns should be blocked
    try std.testing.expect(filter.isBlocked("www.ads.example.com"));
    try std.testing.expect(filter.isBlocked("tracking.example.com"));
    try std.testing.expect(filter.isBlocked("ad.doubleclick.net"));

    // Non-matched should be allowed
    try std.testing.expect(!filter.isBlocked("www.example.com"));
    try std.testing.expect(!filter.isBlocked("google.com"));
}

test "Filter isBlocked - default deny (whitelist)" {
    const allocator = std.testing.allocator;
    var filter = Filter.init(allocator);
    defer filter.deinit();

    filter.mode = .default_deny;

    const content =
        \\*.example.com
        \\localhost
    ;
    try filter.loadFromText(content);

    // Matched patterns should be allowed (not blocked)
    try std.testing.expect(!filter.isBlocked("www.example.com"));
    try std.testing.expect(!filter.isBlocked("api.example.com"));
    try std.testing.expect(!filter.isBlocked("localhost"));

    // Non-matched should be blocked
    try std.testing.expect(filter.isBlocked("google.com"));
    try std.testing.expect(filter.isBlocked("facebook.com"));
}

test "Filter fnmatch is always case-sensitive" {
    const allocator = std.testing.allocator;
    var filter = Filter.init(allocator);
    defer filter.deinit();

    // fnmatch mode (default) is always case-sensitive per tinyproxy C
    filter.filter_type = .fnmatch;
    try filter.addPattern("*.example.com");
    filter.enabled = true;

    try std.testing.expect(filter.isBlocked("www.example.com"));
    try std.testing.expect(!filter.isBlocked("WWW.EXAMPLE.COM")); // No match - case matters
    try std.testing.expect(!filter.isBlocked("www.Example.com")); // No match - case matters
}

test "Filter bre/ere respects case_sensitive setting" {
    const allocator = std.testing.allocator;
    var filter = Filter.init(allocator);
    defer filter.deinit();

    // BRE/ERE mode: case_sensitive=false makes matching case-insensitive
    filter.filter_type = .bre;
    filter.case_sensitive = false;
    try filter.addPattern("example");
    filter.enabled = true;

    try std.testing.expect(filter.isBlocked("www.example.com"));
    try std.testing.expect(filter.isBlocked("WWW.EXAMPLE.COM")); // Matches - case ignored
    try std.testing.expect(filter.isBlocked("www.Example.com")); // Matches - case ignored
}

test "Filter bre case sensitive" {
    const allocator = std.testing.allocator;
    var filter = Filter.init(allocator);
    defer filter.deinit();

    filter.filter_type = .bre;
    filter.case_sensitive = true;
    try filter.addPattern("example");
    filter.enabled = true;

    try std.testing.expect(filter.isBlocked("www.example.com"));
    try std.testing.expect(!filter.isBlocked("WWW.EXAMPLE.COM")); // No match
    try std.testing.expect(!filter.isBlocked("www.Example.com")); // No match
}

test "Filter extractHost" {
    try std.testing.expectEqualStrings("example.com", Filter.extractHost("http://example.com/path"));
    try std.testing.expectEqualStrings("example.com", Filter.extractHost("https://example.com:8080/path"));
    try std.testing.expectEqualStrings("example.com", Filter.extractHost("example.com/path"));
    try std.testing.expectEqualStrings("example.com", Filter.extractHost("example.com:8080"));
    try std.testing.expectEqualStrings("example.com", Filter.extractHost("example.com"));
    try std.testing.expectEqualStrings("sub.example.com", Filter.extractHost("http://sub.example.com?query=1"));
}

test "Filter disabled returns false" {
    const allocator = std.testing.allocator;
    var filter = Filter.init(allocator);
    defer filter.deinit();

    // Filter not enabled - nothing should be blocked
    try std.testing.expect(!filter.isBlocked("anything.com"));
    try std.testing.expect(!filter.isBlocked("blocked.example.com"));
}
