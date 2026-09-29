const std = @import("std");

/// Computes the DJB2 hash of a string.
pub fn djb2(str: []const u8) u32 {
    @setEvalBranchQuota(10000);
    var hash: u32 = 5381;
    for (str) |c| {
        hash = (hash *% 33) +% c;
    }
    return hash;
}

/// Computes the case-insensitive DJB2 hash of a string.
pub fn djb2_i(str: []const u8) u32 {
    @setEvalBranchQuota(10000);
    var hash: u32 = 5381;
    for (str) |c| {
        var char: u8 = c;
        if (c >= 'A' and c <= 'Z') {
            char = c + 32;
        }
        hash = (hash *% 33) +% char;
    }
    return hash;
}

/// Generates a unique 16-char hex agent ID by hashing PID, TID, and
/// the first bytes of the computer name via a LCG.
pub fn generateAgentId(pid: u32, tid: u32, name_seed: []const u8) [16]u8 {
    var seed: u64 = @as(u64, pid) ^ (@as(u64, tid) << 16);
    for (name_seed) |b| {
        seed = seed *% 6364136223846793005 +% b;
    }
    const hex_chars = "0123456789abcdef";
    var id: [16]u8 = undefined;
    var i: usize = 0;
    var v = seed;
    while (i < 16) : (i += 2) {
        id[i]     = hex_chars[(v >> 4) & 0xF];
        id[i + 1] = hex_chars[v & 0xF];
        v >>= 8;
    }
    return id;
}

/// RC4 stream cipher — symmetric, in-place XOR.
/// Call once to encrypt, call again on ciphertext to decrypt.
pub fn rc4(data: []u8, key: []const u8) void {
    var S: [256]u8 = undefined;
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        S[i] = @intCast(i);
    }
    var j: usize = 0;
    i = 0;
    while (i < 256) : (i += 1) {
        j = (j + S[i] + key[i % key.len]) % 256;
        const tmp = S[i]; S[i] = S[j]; S[j] = tmp;
    }
    i = 0;
    j = 0;
    for (data) |*byte| {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        const tmp = S[i]; S[i] = S[j]; S[j] = tmp;
        byte.* ^= S[(@as(usize, S[i]) + @as(usize, S[j])) % 256];
    }
}

/// Parses a lowercase hex string into a byte slice.
/// hex_str.len must be exactly 2 * out.len.
pub fn hexToBytes(out: []u8, hex_str: []const u8) void {
    const hex_chars = "0123456789abcdef";
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        var hi: u8 = 0;
        var lo: u8 = 0;
        for (hex_chars, 0..) |c, idx| {
            if (c == (hex_str[i * 2] | 0x20)) hi = @intCast(idx);
            if (c == (hex_str[i * 2 + 1] | 0x20)) lo = @intCast(idx);
        }
        out[i] = (hi << 4) | lo;
    }
}
