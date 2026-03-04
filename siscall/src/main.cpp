// ---------------------------------------------------------------------------
// main.cpp — Indirect Syscall POC
//
// Demonstrates calling Windows NT APIs directly via inline syscall, bypassing
// ntdll stubs and all usermode hooks, using:
//   1. ROL-XOR obfuscated syscall number storage (decoded at runtime)
//   2. Hook-detection shim (MinHook trampoline prologue check)
//   3. Hand-written MASM syscall stub inside our own binary
// ---------------------------------------------------------------------------

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>       // must come before winternl.h
#include <cstdio>
#include <cstdint>

#include "indirect_syscall.h"

// -------------------------------------------------------------------------
// Full SYSTEM_BASIC_INFORMATION — winternl.h only declares a stub version.
// Rename to avoid the redefinition conflict.
// -------------------------------------------------------------------------
struct SYSTEM_BASIC_INFO_FULL
{
    ULONG      Reserved;
    ULONG      TimerResolution;
    ULONG      PageSize;
    ULONG      NumberOfPhysicalPages;
    ULONG      LowestPhysicalPageNumber;
    ULONG      HighestPhysicalPageNumber;
    ULONG      AllocationGranularity;
    ULONG_PTR  MinimumUserModeAddress;
    ULONG_PTR  MaximumUserModeAddress;
    ULONG_PTR  ActiveProcessorsAffinityMask;
    CCHAR      NumberOfProcessors;
};

// -------------------------------------------------------------------------
// Demo 1: NtQuerySystemInformation via indirect syscall
// -------------------------------------------------------------------------
static void demo_NtQuerySystemInformation()
{
    printf("=== Demo 1: NtQuerySystemInformation (SystemBasicInformation) ===\n");

    SYSTEM_BASIC_INFO_FULL sbi{};
    ULONG ret_len = 0;

    NTSTATUS status = IndirectSyscall::NtQuerySystemInformation(
        0,                             // SystemBasicInformation = 0
        &sbi,
        static_cast<ULONG>(sizeof(sbi)),
        &ret_len);

    if (status >= 0)
    {
        printf("[+] NtQuerySystemInformation via indirect syscall  OK  (status=0x%08X)\n", status);
        printf("    PageSize              : %u bytes\n",  sbi.PageSize);
        printf("    AllocationGranularity : %u bytes\n",  sbi.AllocationGranularity);
        printf("    NumberOfProcessors    : %d\n",        (int)sbi.NumberOfProcessors);
        printf("    PhysicalPages         : %u  (~%u MB RAM)\n",
               sbi.NumberOfPhysicalPages,
               (sbi.NumberOfPhysicalPages * sbi.PageSize) / (1024u * 1024u));
        printf("    UserModeRange         : 0x%016llX - 0x%016llX\n",
               (unsigned long long)sbi.MinimumUserModeAddress,
               (unsigned long long)sbi.MaximumUserModeAddress);
    }
    else
    {
        printf("[-] NtQuerySystemInformation FAILED  status=0x%08X\n", status);
    }
    printf("\n");
}

// -------------------------------------------------------------------------
// Demo 2: NtAllocateVirtualMemory + NtWriteVirtualMemory + NtFreeVirtualMemory
// -------------------------------------------------------------------------
static void demo_VirtualMemory()
{
    printf("=== Demo 2: NtAllocateVirtualMemory / NtWriteVirtualMemory / NtFreeVirtualMemory ===\n");

    PVOID  base      = nullptr;
    SIZE_T region_sz = 0x1000; // 4 KB

    NTSTATUS status = IndirectSyscall::NtAllocateVirtualMemory(
        reinterpret_cast<HANDLE>(-1LL), // NtCurrentProcess()
        &base,
        0,
        &region_sz,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    if (status < 0 || !base)
    {
        printf("[-] NtAllocateVirtualMemory FAILED  status=0x%08X\n", status);
        return;
    }
    printf("[+] NtAllocateVirtualMemory OK  -- base=0x%p  size=%zu bytes\n", base, region_sz);

    // Write a test pattern
    static const char payload[] = "indirect_syscall_poc_pattern_0xDEADC0DE";
    SIZE_T written = 0;

    status = IndirectSyscall::NtWriteVirtualMemory(
        reinterpret_cast<HANDLE>(-1LL),
        base,
        const_cast<char*>(payload),
        sizeof(payload),
        &written);

    if (status >= 0)
    {
        printf("[+] NtWriteVirtualMemory  OK  -- wrote %zu bytes\n", written);
        printf("    Readback: \"%s\"\n", reinterpret_cast<char*>(base));
    }
    else
    {
        printf("[-] NtWriteVirtualMemory FAILED  status=0x%08X\n", status);
    }

    // Free
    region_sz = 0;
    status = IndirectSyscall::NtFreeVirtualMemory(
        reinterpret_cast<HANDLE>(-1LL),
        &base,
        &region_sz,
        MEM_RELEASE);

    if (status >= 0)
        printf("[+] NtFreeVirtualMemory   OK\n");
    else
        printf("[-] NtFreeVirtualMemory FAILED  status=0x%08X\n", status);

    printf("\n");
}

// -------------------------------------------------------------------------
// Demo 3: Show that syscall RIP comes from our binary, not ntdll
// -------------------------------------------------------------------------
static void demo_rip_origin()
{
    printf("=== Demo 3: Syscall instruction origin ===\n");

    void* stub_va = reinterpret_cast<void*>(&DoSyscall);

    HMODULE our_module = nullptr;
    GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(stub_va),
        &our_module);

    char our_path[MAX_PATH]{};
    GetModuleFileNameA(our_module, our_path, MAX_PATH);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    void*   ntdll_NtQSI = reinterpret_cast<void*>(
        GetProcAddress(ntdll, "NtQuerySystemInformation"));

    printf("    Our syscall stub VA  : 0x%p  (module: %s)\n", stub_va, our_path);
    printf("    ntdll!NtQSI VA       : 0x%p  (module: ntdll.dll)\n", ntdll_NtQSI);
    printf("    RIP at syscall time  : inside OUR binary -- ntdll stubs never executed.\n\n");

    printf("[+] All NT calls bypass ntdll.dll hooks completely.\n");
    printf("    Usermode API monitors (MinHook, Detours) see no invocations.\n");
    printf("    Kernel-level ETW / hypervisor monitors still observe the raw syscall,\n");
    printf("    but the return RIP points into this binary's .text section,\n");
    printf("    not into ntdll.dll.\n\n");
}

// -------------------------------------------------------------------------
// Entry point
// -------------------------------------------------------------------------
int main()
{
    printf("============================================================\n");
    printf("  Indirect Syscall POC\n");
    printf("  ROL-XOR obfuscation + hook-detection shim + direct syscall\n");
    printf("============================================================\n\n");

    IndirectSyscall::init();
    demo_NtQuerySystemInformation();
    demo_VirtualMemory();
    demo_rip_origin();

    printf("============================================================\n");
    printf("  All demos complete.\n");
    printf("============================================================\n");
    return 0;
}
