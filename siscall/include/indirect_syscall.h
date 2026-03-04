#pragma once
#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include "syscall_numbers.h"
#include "hook_shim.h"

// ---------------------------------------------------------------------------
// External MASM stub (defined in syscall_dispatch.asm)
//
// Prototype:
//   DoSyscall(DWORD* p_sysnum,
//             ULONG_PTR ntArg0, ntArg1, ntArg2, ntArg3, ntArg4, ntArg5)
//
// The stub loads eax from *p_sysnum, shifts NT arguments into NT ABI
// positions, then issues a `syscall` instruction inside OUR binary.
// ---------------------------------------------------------------------------
extern "C" NTSTATUS DoSyscall(
    uint32_t* p_sysnum,     // rcx — pointer to decoded syscall number
    uintptr_t ntArg0,       // rdx — NT arg 0 (→ r10 + rcx)
    uintptr_t ntArg1,       // r8  — NT arg 1 (→ rdx)
    uintptr_t ntArg2,       // r9  — NT arg 2 (→ r8)
    uintptr_t ntArg3,       // [rsp+28h] — NT arg 3 (→ r9)
    uintptr_t ntArg4,       // [rsp+30h] — NT arg 4 (→ [rsp+28h])
    uintptr_t ntArg5);      // [rsp+38h] — NT arg 5 (→ [rsp+30h])

// ---------------------------------------------------------------------------
// IndirectSyscall namespace
// ---------------------------------------------------------------------------
namespace IndirectSyscall
{
    // Resolved syscall number table — populated by init()
    extern uint32_t g_NtQSI;   // NtQuerySystemInformation
    extern uint32_t g_NtAVM;   // NtAllocateVirtualMemory
    extern uint32_t g_NtFVM;   // NtFreeVirtualMemory
    extern uint32_t g_NtWVM;   // NtWriteVirtualMemory
    extern uint32_t g_NtClose; // NtClose

    // Hook-detection results (populated by init(), cosmetic only)
    extern bool g_NtQSI_hooked;
    extern bool g_NtAVM_hooked;
    extern bool g_NtFVM_hooked;

    // Call once at process start
    void init();

    // -----------------------------------------------------------------------
    // NtQuerySystemInformation(Class, Buffer, Length, ReturnLength)
    // -----------------------------------------------------------------------
    inline NTSTATUS NtQuerySystemInformation(
        ULONG  SystemInformationClass,
        PVOID  SystemInformation,
        ULONG  SystemInformationLength,
        PULONG ReturnLength)
    {
        return DoSyscall(
            &g_NtQSI,
            static_cast<uintptr_t>(SystemInformationClass),
            reinterpret_cast<uintptr_t>(SystemInformation),
            static_cast<uintptr_t>(SystemInformationLength),
            reinterpret_cast<uintptr_t>(ReturnLength),
            0, 0);
    }

    // -----------------------------------------------------------------------
    // NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits,
    //                         RegionSize, AllocationType, Protect)
    // -----------------------------------------------------------------------
    inline NTSTATUS NtAllocateVirtualMemory(
        HANDLE    ProcessHandle,
        PVOID*    BaseAddress,
        ULONG_PTR ZeroBits,
        PSIZE_T   RegionSize,
        ULONG     AllocationType,
        ULONG     Protect)
    {
        return DoSyscall(
            &g_NtAVM,
            reinterpret_cast<uintptr_t>(ProcessHandle),
            reinterpret_cast<uintptr_t>(BaseAddress),
            static_cast<uintptr_t>(ZeroBits),
            reinterpret_cast<uintptr_t>(RegionSize),
            static_cast<uintptr_t>(AllocationType),
            static_cast<uintptr_t>(Protect));
    }

    // -----------------------------------------------------------------------
    // NtFreeVirtualMemory(ProcessHandle, BaseAddress, RegionSize, FreeType)
    // -----------------------------------------------------------------------
    inline NTSTATUS NtFreeVirtualMemory(
        HANDLE  ProcessHandle,
        PVOID*  BaseAddress,
        PSIZE_T RegionSize,
        ULONG   FreeType)
    {
        return DoSyscall(
            &g_NtFVM,
            reinterpret_cast<uintptr_t>(ProcessHandle),
            reinterpret_cast<uintptr_t>(BaseAddress),
            reinterpret_cast<uintptr_t>(RegionSize),
            static_cast<uintptr_t>(FreeType),
            0, 0);
    }

    // -----------------------------------------------------------------------
    // NtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer,
    //                      NumberOfBytesToWrite, NumberOfBytesWritten)
    // -----------------------------------------------------------------------
    inline NTSTATUS NtWriteVirtualMemory(
        HANDLE  ProcessHandle,
        PVOID   BaseAddress,
        PVOID   Buffer,
        SIZE_T  NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten)
    {
        return DoSyscall(
            &g_NtWVM,
            reinterpret_cast<uintptr_t>(ProcessHandle),
            reinterpret_cast<uintptr_t>(BaseAddress),
            reinterpret_cast<uintptr_t>(Buffer),
            static_cast<uintptr_t>(NumberOfBytesToWrite),
            reinterpret_cast<uintptr_t>(NumberOfBytesWritten),
            0);
    }

} // namespace IndirectSyscall
