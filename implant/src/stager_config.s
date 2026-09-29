.section .text$A, "ax"
.global c2_host_val
.global c2_port_val
.global c2_flags_val
c2_host_val: .string "127.0.0.1"
c2_port_val: .short 8080
c2_flags_val: .long 0
