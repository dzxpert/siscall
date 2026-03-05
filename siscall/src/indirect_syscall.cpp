#include "indirect_syscall.h"
#include <cstdio>

namespace IndirectSyscall
{
    SyscallNumbers g_SysNums = {};

    bool g_NtQSI_hooked = false;
    bool g_NtAVM_hooked = false;
    bool g_NtFVM_hooked = false;

    void init()
    {
        // ---------------------------------------------------------------
        // Step 1 — Decode obfuscated syscall numbers from the ROL-XOR table
        // ---------------------------------------------------------------
        auto nums = SyscallTable::resolve();
        g_SysNums.NtQSI   = nums.NtQuerySystemInformation;
        g_SysNums.NtAVM   = nums.NtAllocateVirtualMemory;
        g_SysNums.NtFVM   = nums.NtFreeVirtualMemory;
        g_SysNums.NtWVM   = nums.NtWriteVirtualMemory;
        g_SysNums.NtClose = nums.NtClose;

        printf("[syscall_numbers] Decoded syscall table:\n");
        printf("  NtQuerySystemInformation  = 0x%02X (%u)\n", g_SysNums.NtQSI,   g_SysNums.NtQSI);
        printf("  NtAllocateVirtualMemory   = 0x%02X (%u)\n", g_SysNums.NtAVM,   g_SysNums.NtAVM);
        printf("  NtFreeVirtualMemory       = 0x%02X (%u)\n", g_SysNums.NtFVM,   g_SysNums.NtFVM);
        printf("  NtWriteVirtualMemory      = 0x%02X (%u)\n", g_SysNums.NtWVM,   g_SysNums.NtWVM);
        printf("  NtClose                   = 0x%02X (%u)\n", g_SysNums.NtClose, g_SysNums.NtClose);
        printf("\n");

        // ---------------------------------------------------------------
        // Step 2 — Run hook-detection shims
        // Checks the first 4 bytes of each ntdll export for the MinHook
        // trampoline signature (0x48CA8949).  We always call our own MASM
        // stub regardless — this is purely diagnostic / demonstrative.
        // ---------------------------------------------------------------
        printf("[hook_shim] Scanning ntdll stubs for hooks...\n");

        auto qsi_shim = Shim_Detect("NtQuerySystemInformation",
                                    reinterpret_cast<void*>(&DoSyscall),
                                    0xAB0EAB1u);
        g_NtQSI_hooked = qsi_shim.hooked;
        printf("  NtQuerySystemInformation  prologue=0x%08X  %s\n",
               qsi_shim.prologue_bytes,
               qsi_shim.hooked ? "[!] HOOK DETECTED (MinHook trampoline)" : "[-] Clean");

        auto avm_shim = Shim_Detect("NtAllocateVirtualMemory",
                                    reinterpret_cast<void*>(&DoSyscall),
                                    0xBB0EAB1u);
        g_NtAVM_hooked = avm_shim.hooked;
        printf("  NtAllocateVirtualMemory   prologue=0x%08X  %s\n",
               avm_shim.prologue_bytes,
               avm_shim.hooked ? "[!] HOOK DETECTED (MinHook trampoline)" : "[-] Clean");

        auto fvm_shim = Shim_Detect("NtFreeVirtualMemory",
                                    reinterpret_cast<void*>(&DoSyscall),
                                    0xCB0EAB1u);
        g_NtFVM_hooked = fvm_shim.hooked;
        printf("  NtFreeVirtualMemory       prologue=0x%08X  %s\n",
               fvm_shim.prologue_bytes,
               fvm_shim.hooked ? "[!] HOOK DETECTED (MinHook trampoline)" : "[-] Clean");

        printf("\n[*] Syscall stub lives at: 0x%p  (inside OUR binary)\n",
               reinterpret_cast<void*>(&DoSyscall));
        printf("[*] All syscalls issued from this binary — ntdll stubs bypassed.\n\n");

        // ---------------------------------------------------------------
        // Step 3 — Lock syscall numbers to PAGE_READONLY
        // The struct is contiguous, so a single VirtualProtect call covers
        // all five decoded numbers.  An attacker with an arbitrary-write
        // primitive can no longer silently redirect a syscall index.
        // ---------------------------------------------------------------
        DWORD old_protect = 0;
        if (VirtualProtect(&g_SysNums, sizeof(g_SysNums),
                           PAGE_READONLY, &old_protect))
        {
            printf("[+] Syscall number globals locked to PAGE_READONLY.\n\n");
        }
        else
        {
            printf("[!] WARNING: Failed to lock syscall globals (err=%lu).\n\n",
                   GetLastError());
        }
    }

} // namespace IndirectSyscall
