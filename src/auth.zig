//! HTTP Basic Authentication Module for tinyproxy-zig
//!
//! Implements RFC 7617 HTTP Basic Authentication.
//! Supports multiple username/password pairs with optional password hashing.
//!
//! Usage:
//!   var auth = BasicAuth.init(allocator);
//!   defer auth.deinit();
//!   try auth.addUser("user", "password");
//!   try auth.addUserHashed("admin", "{SHA256}hashed_password_here");
//!   if (!auth.verify(auth_header)) {
//!       try sendAuthRequired(stream, rt, auth.realm);
//!       return;
//!   }

const std = @import("std");

const SHA256_DIGEST_LENGTH = 32;

/// Password storage format
const PasswordFormat = enum {
    /// Plain text password (default, backward compatible)
    plain,
    /// SHA-256 hash in hex format: {SHA256}hexstring
    sha256,
};

/// HTTP Basic Authentication handler
pub const BasicAuth = struct {
    /// Username -> Password hash map
    credentials: std.StringHashMap([]const u8),
    /// Realm for WWW-Authenticate header
    realm: []const u8 = "tinyproxy",
    realm_owned: bool = false,
    /// Allocator for dynamic allocations
    allocator: std.mem.Allocator,

    const Self = @This();

    /// Initialize an empty BasicAuth
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .credentials = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    /// Set a custom realm
    pub fn setRealm(self: *Self, realm: []const u8) !void {
        const duped = try self.allocator.dupe(u8, realm);
        if (self.realm_owned) {
            self.allocator.free(@constCast(self.realm));
        }
        self.realm = duped;
        self.realm_owned = true;
    }

    /// Add a username/password pair (plain text, backward compatible)
    pub fn addUser(self: *Self, user: []const u8, pass: []const u8) !void {
        const user_duped = try self.allocator.dupe(u8, user);
        errdefer self.allocator.free(user_duped);

        const pass_duped = try self.allocator.dupe(u8, pass);
        errdefer self.allocator.free(pass_duped);

        // Remove old entry if exists
        if (self.credentials.fetchRemove(user_duped)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }

        try self.credentials.put(user_duped, pass_duped);
    }

    /// Add a username with pre-hashed password (SHA-256 hex format)
    /// Hash format: {SHA256}hex_digest
    pub fn addUserHashed(self: *Self, user: []const u8, hashed_pass: []const u8) !void {
        const user_duped = try self.allocator.dupe(u8, user);
        errdefer self.allocator.free(user_duped);

        const pass_duped = try self.allocator.dupe(u8, hashed_pass);
        errdefer self.allocator.free(pass_duped);

        // Remove old entry if exists
        if (self.credentials.fetchRemove(user_duped)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }

        try self.credentials.put(user_duped, pass_duped);
    }

    /// Add a username/password pair and store as SHA-256 hash
    pub fn addUserWithHash(self: *Self, user: []const u8, pass: []const u8) !void {
        const hash = try self.hashPassword(pass);
        errdefer self.allocator.free(hash);

        const user_duped = try self.allocator.dupe(u8, user);
        errdefer self.allocator.free(user_duped);

        // Remove old entry if exists
        if (self.credentials.fetchRemove(user_duped)) |kv| {
            self.allocator.free(kv.key);
            self.allocator.free(kv.value);
        }

        // hash ownership is transferred to the hashmap
        try self.credentials.put(user_duped, hash);
    }

    /// Hash a password using SHA-256
    /// Returns: {SHA256}hex_digest format
    fn hashPassword(self: *Self, password: []const u8) ![]u8 {
        var digest: [SHA256_DIGEST_LENGTH]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(password, &digest, .{});

        // Format: {SHA256} + hex digest (64 chars)
        const formatted = try self.allocator.alloc(u8, 8 + SHA256_DIGEST_LENGTH * 2);
        @memcpy(formatted[0..8], "{SHA256}");

        // Convert digest to hex string manually
        const hex_chars = "0123456789abcdef";
        for (digest, 0..) |byte, i| {
            formatted[8 + i * 2] = hex_chars[byte >> 4];
            formatted[8 + i * 2 + 1] = hex_chars[byte & 0x0f];
        }
        return formatted;
    }

    /// Check if any credentials are configured
    pub fn hasCredentials(self: *const Self) bool {
        return self.credentials.count() > 0;
    }

    /// Verify the Authorization header.
    /// Returns true if valid credentials, false otherwise.
    /// Uses constant-time comparison to prevent timing attacks.
    /// Performs a dummy password check on unknown usernames to prevent
    /// timing-based username enumeration.
    pub fn verify(self: *const Self, auth_header: ?[]const u8) bool {
        const header = auth_header orelse return false;

        // Must start with "Basic "
        if (!std.ascii.startsWithIgnoreCase(header, "Basic ")) {
            return false;
        }

        const encoded = std.mem.trim(u8, header[6..], " \t");
        if (encoded.len == 0) return false;

        // Decode Base64 using standard library decoder
        var decoded_buf: [4096]u8 = undefined;
        const decoded_len = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch return false;
        if (decoded_len > decoded_buf.len) return false;
        std.base64.standard.Decoder.decode(decoded_buf[0..decoded_len], encoded) catch return false;
        const decoded = decoded_buf[0..decoded_len];

        // Split into user:password
        const colon_pos = std.mem.indexOfScalar(u8, decoded, ':') orelse return false;
        const user = decoded[0..colon_pos];
        const pass = decoded[colon_pos + 1 ..];

        // Verify credentials using constant-time comparison.
        // When user is not found, still run a dummy verification to prevent
        // timing-based username enumeration.
        if (self.credentials.get(user)) |stored_pass| {
            return verifyPassword(stored_pass, pass);
        }

        // Dummy verification to equalize timing with valid-user path
        _ = verifyPassword("dummy_timing_equalization", pass);
        return false;
    }

    /// Verify a password against stored value (plain or hashed).
    /// Always compares SHA-256 digests using constant-time comparison
    /// to prevent timing attacks regardless of storage format.
    fn verifyPassword(stored: []const u8, provided: []const u8) bool {
        // Hash the provided password
        var provided_digest: [SHA256_DIGEST_LENGTH]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(provided, &provided_digest, .{});

        const format = detectPasswordFormat(stored);

        var stored_digest: [SHA256_DIGEST_LENGTH]u8 = undefined;
        switch (format) {
            .plain => {
                // Hash the stored plain password for constant-time comparison
                std.crypto.hash.sha2.Sha256.hash(stored, &stored_digest, .{});
            },
            .sha256 => {
                // Parse hex digest from stored value: {SHA256}hex_digest
                if (stored.len != 8 + SHA256_DIGEST_LENGTH * 2) return false;
                const hex_digest = stored[8..];

                for (0..SHA256_DIGEST_LENGTH) |i| {
                    const upper = std.fmt.charToDigit(hex_digest[i * 2], 16) catch return false;
                    const lower = std.fmt.charToDigit(hex_digest[i * 2 + 1], 16) catch return false;
                    stored_digest[i] = (upper << 4) | lower;
                }
            },
        }

        return std.crypto.timing_safe.eql([SHA256_DIGEST_LENGTH]u8, provided_digest, stored_digest);
    }

    /// Detect password format from stored value
    fn detectPasswordFormat(stored: []const u8) PasswordFormat {
        if (std.mem.startsWith(u8, stored, "{SHA256}")) {
            return .sha256;
        }
        return .plain;
    }

    /// Free all resources
    pub fn deinit(self: *Self) void {
        var it = self.credentials.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.credentials.deinit();

        if (self.realm_owned) {
            self.allocator.free(@constCast(self.realm));
        }
    }
};

/// Build a 407 Proxy Authentication Required response
pub fn build407Response(realm: []const u8, buf: []u8) ![]u8 {
    return std.fmt.bufPrint(buf,
        \\HTTP/1.1 407 Proxy Authentication Required
        \\Proxy-Authenticate: Basic realm="{s}"
        \\Content-Type: text/html
        \\Content-Length: 42
        \\Connection: close
        \\
        \\<html><body>Authentication required</body>
    , .{realm});
}

/// Build a 401 Unauthorized response
pub fn build401Response(realm: []const u8, buf: []u8) ![]u8 {
    return std.fmt.bufPrint(buf,
        \\HTTP/1.1 401 Unauthorized
        \\WWW-Authenticate: Basic realm="{s}"
        \\Content-Type: text/html
        \\Content-Length: 42
        \\Connection: close
        \\
        \\<html><body>Authentication required</body>
    , .{realm});
}

// ============================================================================
// Tests
// ============================================================================

test "BasicAuth add and verify user" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    try auth.addUser("admin", "secret123");

    // Valid credentials (base64 of "admin:secret123")
    try std.testing.expect(auth.verify("Basic YWRtaW46c2VjcmV0MTIz"));

    // Wrong password
    try std.testing.expect(!auth.verify("Basic YWRtaW46d3JvbmdwYXNz"));

    // Wrong user
    try std.testing.expect(!auth.verify("Basic dXNlcjpzZWNyZXQxMjM="));

    // No header
    try std.testing.expect(!auth.verify(null));

    // Invalid scheme
    try std.testing.expect(!auth.verify("Bearer token123"));
}

test "BasicAuth multiple users" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    try auth.addUser("alice", "password1");
    try auth.addUser("bob", "password2");

    // base64 of "alice:password1"
    try std.testing.expect(auth.verify("Basic YWxpY2U6cGFzc3dvcmQx"));

    // base64 of "bob:password2"
    try std.testing.expect(auth.verify("Basic Ym9iOnBhc3N3b3JkMg=="));
}

test "base64 decode via std.base64" {
    var buf: [64]u8 = undefined;
    const decoder = std.base64.standard.Decoder;

    // "Hello" -> "SGVsbG8="
    const len1 = try decoder.calcSizeForSlice("SGVsbG8=");
    try decoder.decode(buf[0..len1], "SGVsbG8=");
    try std.testing.expectEqualStrings("Hello", buf[0..len1]);

    // "user:pass" -> "dXNlcjpwYXNz"
    const len2 = try decoder.calcSizeForSlice("dXNlcjpwYXNz");
    try decoder.decode(buf[0..len2], "dXNlcjpwYXNz");
    try std.testing.expectEqualStrings("user:pass", buf[0..len2]);

    // "admin:secret123" -> "YWRtaW46c2VjcmV0MTIz"
    const len3 = try decoder.calcSizeForSlice("YWRtaW46c2VjcmV0MTIz");
    try decoder.decode(buf[0..len3], "YWRtaW46c2VjcmV0MTIz");
    try std.testing.expectEqualStrings("admin:secret123", buf[0..len3]);
}

test "build 407 response" {
    var buf: [512]u8 = undefined;
    const response = try build407Response("tinyproxy", &buf);

    try std.testing.expect(std.mem.indexOf(u8, response, "407 Proxy Authentication Required") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "realm=\"tinyproxy\"") != null);
}

test "build 401 response" {
    var buf: [512]u8 = undefined;
    const response = try build401Response("tinyproxy", &buf);

    try std.testing.expect(std.mem.indexOf(u8, response, "401 Unauthorized") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "WWW-Authenticate: Basic realm=\"tinyproxy\"") != null);
}

test "BasicAuth hasCredentials" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    try std.testing.expect(!auth.hasCredentials());

    try auth.addUser("user", "pass");

    try std.testing.expect(auth.hasCredentials());
}

test "BasicAuth SHA-256 hashed password" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    // Add user with SHA-256 hashed password
    // Hash of "secret123": fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4
    try auth.addUserHashed("alice", "{SHA256}fcf730b6d95236ecd3c9fc2d92d7b6b2bb061514961aec041d6c7a7192f592e4");

    // base64 of "alice:secret123"
    try std.testing.expect(auth.verify("Basic YWxpY2U6c2VjcmV0MTIz"));

    // Wrong password
    try std.testing.expect(!auth.verify("Basic YWxpY2U6d3JvbmdwYXNz"));
}

test "BasicAuth addUserWithHash" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    try auth.addUserWithHash("bob", "password123");

    // base64 of "bob:password123"
    try std.testing.expect(auth.verify("Basic Ym9iOnBhc3N3b3JkMTIz"));

    // Wrong password
    try std.testing.expect(!auth.verify("Basic Ym9iOnBhc3N3b3Jk"));
}

test "BasicAuth mixed plain and hashed passwords" {
    var auth = BasicAuth.init(std.testing.allocator);
    defer auth.deinit();

    // Plain text password
    try auth.addUser("plain_user", "plain_pass");

    // Hashed password (hash of "hash_pass")
    // 4c3c07ef6d98b08f7099dac843f0d556de7e42d133b9505c20444fd70b34e500
    try auth.addUserHashed("hash_user", "{SHA256}4c3c07ef6d98b08f7099dac843f0d556de7e42d133b9505c20444fd70b34e500");

    // base64 of "plain_user:plain_pass"
    try std.testing.expect(auth.verify("Basic cGxhaW5fdXNlcjpwbGFpbl9wYXNz"));

    // base64 of "hash_user:hash_pass"
    try std.testing.expect(auth.verify("Basic aGFzaF91c2VyOmhhc2hfcGFzcw=="));

    // Wrong passwords should fail
    try std.testing.expect(!auth.verify("Basic cGxhaW5fdXNlcjp3cm9uZw=="));
    try std.testing.expect(!auth.verify("Basic aGFzaF91c2VyOndyb25n"));
}
