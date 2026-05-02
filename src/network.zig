const std = @import("std");
const posix = std.posix;

const SEGMENT_LEN = 512;
const MAXIMUM_BUFFER_LENGTH = 128 * 1024;

const MSG = posix.MSG;

const ReadLines = struct {
    data: []u8,
    len: usize,
    next: ?*ReadLines,
};

/// Read a complete line from the socket, terminated by '\n'.
///
/// This function handles network buffering by reading data in segments
/// until a newline is found. The returned line includes the terminating
/// newline character and is NULL terminated.
///
/// The buffer is allocated on the heap using the provided allocator.
/// The caller is responsible for freeing this memory.
///
/// Returns:
///   - Length of buffer on success (not including NULL termination)
///   - 0 if socket was closed
///   - error if buffer size limit exceeded, or other socket errors
pub fn readline(allocator: std.mem.Allocator, sock: posix.socket_t, whole_buffer: *[]u8) !usize {
    var buffer: [SEGMENT_LEN]u8 = undefined;
    var whole_buffer_len: usize = 0;

    // Create first node in linked list
    const first_line = try allocator.create(ReadLines);
    first_line.* = ReadLines{
        .data = undefined,
        .len = 0,
        .next = null,
    };
    defer {
        // Cleanup linked list
        var current: ?*ReadLines = first_line;
        while (current) |node| {
            const next = node.next;
            if (node.len > 0) {
                allocator.free(node.data);
            }
            allocator.destroy(node);
            current = next;
        }
    }

    var line_ptr = first_line;

    while (true) {
        // Peek at the data without consuming it
        const ret = posix.recv(sock, &buffer, MSG.PEEK) catch |err| switch (err) {
            error.WouldBlock => continue,
            error.ConnectionResetByPeer, error.ConnectionRefused => return 0,
            else => return err,
        };

        if (ret == 0) {
            return 0; // Socket was closed
        }

        // Look for newline in the peeked data
        const peeked_data = buffer[0..ret];
        const newline_pos = std.mem.indexOf(u8, peeked_data, "\n");

        // Determine how much data to actually read
        const diff = if (newline_pos) |pos| pos + 1 else ret;

        whole_buffer_len += diff;

        // Don't allow the buffer to grow without bound
        if (whole_buffer_len > MAXIMUM_BUFFER_LENGTH) {
            return error.BufferTooLarge;
        }

        // Allocate memory for this segment
        line_ptr.data = try allocator.alloc(u8, diff);

        // Actually read the data
        const actual_ret = posix.recv(sock, line_ptr.data, 0) catch |err| switch (err) {
            error.WouldBlock => continue,
            error.ConnectionResetByPeer, error.ConnectionRefused => return 0,
            else => return err,
        };

        if (actual_ret == 0) {
            return 0;
        }

        line_ptr.len = diff;

        // If we found a newline, we're done
        if (newline_pos != null) {
            line_ptr.next = null;
            break;
        }

        // Create next node in linked list
        line_ptr.next = try allocator.create(ReadLines);
        line_ptr.next.?.* = ReadLines{
            .data = undefined,
            .len = 0,
            .next = null,
        };
        line_ptr = line_ptr.next.?;
    }

    // Allocate final buffer (including space for null terminator)
    whole_buffer.* = try allocator.alloc(u8, whole_buffer_len + 1);

    // Null terminate
    whole_buffer.*[whole_buffer_len] = 0;

    // Copy all segments into final buffer
    var copy_len: usize = 0;
    var current: ?*ReadLines = first_line;
    while (current) |node| {
        if (node.len > 0) {
            @memcpy(whole_buffer.*[copy_len .. copy_len + node.len], node.data[0..node.len]);
            copy_len += node.len;
        }
        current = node.next;
    }

    return whole_buffer_len;
}
