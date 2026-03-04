; ---------------------------------------------------------------------------
; syscall_dispatch.asm  —  hand-written NT syscall stubs
;
; Each stub is a drop-in replacement for the corresponding ntdll export:
;   mov r10, rcx         ; NT ABI: first arg in r10 AND rcx
;   mov eax, SYSNUM_REG  ; syscall number from a caller-provided DWORD ptr
;   syscall
;   ret
;
; We cannot hard-code the syscall number because it is computed at runtime
; from the obfuscated global (ROL32 decode).  So each stub takes a pointer
; to a DWORD holding the resolved syscall number as its FIRST argument
; (rcx), then shifts every NT argument down one slot.
;
; Prototype seen from C++:
;   extern "C" NTSTATUS __fastcall DoSyscall(
;       DWORD* p_sysnum,        // rcx  -> loaded into eax
;       ULONG_PTR ntArg0,       // rdx  -> r10 (and rcx after shift)
;       ULONG_PTR ntArg1,       // r8   -> rdx
;       ULONG_PTR ntArg2,       // r9   -> r8
;       ULONG_PTR ntArg3,       // [rsp+28h] -> r9
;       ULONG_PTR ntArg4,       // [rsp+30h] -> [rsp+28h]  (NtAVM only)
;       ULONG_PTR ntArg5);      // [rsp+38h] -> [rsp+30h]  (NtAVM only)
;
; The stub supports up to 6 NT arguments (7 total slots when counting sysnum).
; Windows x64 syscall ABI never uses rip-relative stack beyond [rsp+68h] for
; standard NT calls, so this is sufficient for all calls in this POC.
; ---------------------------------------------------------------------------

.code

; ---------------------------------------------------------------------------
; DoSyscall — generic 0..6-arg NT syscall trampoline
;
; Caller layout (MS x64):
;   rcx        = DWORD* p_sysnum
;   rdx        = NT arg0 (becomes r10/rcx)
;   r8         = NT arg1 (becomes rdx)
;   r9         = NT arg2 (becomes r8)
;   [rsp+28h]  = NT arg3 (becomes r9)
;   [rsp+30h]  = NT arg4 (stays  [rsp+28h] relative to syscall)
;   [rsp+38h]  = NT arg5 (stays  [rsp+30h] relative to syscall)
; ---------------------------------------------------------------------------
DoSyscall PROC
    ; Load syscall number from the DWORD* in rcx
    mov     eax, dword ptr [rcx]

    ; Shift NT arguments into the NT ABI positions:
    ;   NT arg0  rdx  -> r10 + rcx
    ;   NT arg1  r8   -> rdx
    ;   NT arg2  r9   -> r8
    ;   NT arg3  [rsp+28h] -> r9
    ;   NT arg4  [rsp+30h] -> [rsp+28h]   (only touched by 6-arg calls)
    ;   NT arg5  [rsp+38h] -> [rsp+30h]   (only touched by 6-arg calls)

    mov     r10, rdx       ; NT arg0 in r10  (NT ABI requirement)
    mov     rcx, rdx       ; NT arg0 also in rcx (shadow slot 0)
    mov     rdx, r8        ; NT arg1 -> rdx
    mov     r8,  r9        ; NT arg2 -> r8
    mov     r9,  qword ptr [rsp+28h]  ; NT arg3 -> r9

    ; Shift 5th and 6th args in the stack.
    ; We need a scratch register; use r11 (volatile, not saved).
    mov     r11, qword ptr [rsp+30h]  ; NT arg4
    mov     qword ptr [rsp+28h], r11  ; -> becomes NT arg4 slot

    mov     r11, qword ptr [rsp+38h]  ; NT arg5
    mov     qword ptr [rsp+30h], r11  ; -> becomes NT arg5 slot

    syscall
    ret
DoSyscall ENDP

END
