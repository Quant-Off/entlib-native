section __TEXT,__text,regular,pure_instructions
        .intel_syntax noprefix
        .globl  _audit_verify_u64_ct_eq
        .p2align        4
_audit_verify_u64_ct_eq:
Lfunc_begin0:
                // core/constant-time/src/wrapper.rs:6
                pub fn audit_verify_u64_ct_eq(a: &u64, b: &u64) -> Choice {
        .cfi_startproc
        push rbp
        .cfi_def_cfa_offset 16
        .cfi_offset rbp, -16
        mov rbp, rsp
        .cfi_def_cfa_register rbp
                // core/constant-time/src/lib.rs:22
                let v = *self ^ *other;
        mov rax, qword ptr [rdi]
                // core/constant-time/src/lib.rs:28
                let msb = (v | v.wrapping_neg()) >> (<$t>::BITS - 1);
        cmp rax, qword ptr [rsi]
        sete al
                // core/constant-time/src/choice.rs:32
                let is_nonzero = msb_set >> 7;
        neg al
                // core/constant-time/src/wrapper.rs:8
                }
        pop rbp
        ret