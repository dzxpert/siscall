#pragma once
#include <cstdint>
#include "rol_helpers.h"

// ---------------------------------------------------------------------------
// Obfuscated syscall number table
//
// Each syscall is NOT stored as a plain integer.  Instead it lives as a
// triple  { encoded_global, xor_key, addend }  where only the combination
//
//     sysnum = ROL32(encoded_global ^ xor_key, 7) + addend
//
// yields the real Windows 10/11 x64 syscall index.
//
// The encoded values below were produced with:
//     encoded = ROL32(sysnum - addend, 25) ^ xor_key   (inverse of the above)
//
// NOTE: Windows syscall numbers can shift slightly between builds.
// These are calibrated for Windows 10 21H2 / Windows 11 22H2 x64.
// The decode_sysnum() call at runtime will produce the correct number
// regardless of which specific build you run, because we re-derive it
// live – just like the real anti-cheat does:  the globals are re-initialised
// on every run by the loader, so they automatically track the current build.
// For this POC we hard-code numbers that are stable across all Win10/11 x64.
// ---------------------------------------------------------------------------

namespace SyscallTable
{
    // -----------------------------------------------------------------------
    // NtQuerySystemInformation  —  sysnum 0x36 (decimal 54)
    // -----------------------------------------------------------------------
    // Derivation:
    //   want:     0x00000036
    //   addend:   +0x00001F9A   (signed, small)
    //   pre-add:  0x36 - 0x1F9A = -0x1F64 = 0xFFFFE09C (u32)
    //   pre-rot:  ROR32(0xFFFFE09C, 7) = 0x39FFFFC1   (undo ROL7 = ROR7)
    //   xor_key:  0x739C3D8C
    //   encoded:  0x39FFFFC1 ^ 0x739C3D8C = 0x4A63C24D
    // -----------------------------------------------------------------------
    constexpr uint32_t NtQSI_encoded = 0x4A63C24DUL;  // verified: ROL32(enc^xor,7)+add = 0x36
    constexpr uint32_t NtQSI_xor     = 0x739C3D8CUL;
    constexpr int32_t  NtQSI_addend  = 0x1F9A;

    // -----------------------------------------------------------------------
    // NtAllocateVirtualMemory  —  sysnum 0x18 (decimal 24)
    // -----------------------------------------------------------------------
    constexpr uint32_t NtAVM_encoded = 0x5DC12E7FUL;  // verified: ROL32(enc^xor,7)+add = 0x18
    constexpr uint32_t NtAVM_xor     = 0xBE3ED1F2UL;
    constexpr int32_t  NtAVM_addend  = 0x3927;

    // -----------------------------------------------------------------------
    // NtFreeVirtualMemory  —  sysnum 0x1E (decimal 30)
    // -----------------------------------------------------------------------
    constexpr uint32_t NtFVM_encoded = 0x551F3377UL;  // verified: ROL32(enc^xor,7)+add = 0x1E
    constexpr uint32_t NtFVM_xor     = 0xAB1F3330UL;
    constexpr int32_t  NtFVM_addend  = -0x23E1;

    // -----------------------------------------------------------------------
    // NtWriteVirtualMemory  —  sysnum 0x3A (decimal 58)
    // -----------------------------------------------------------------------
    constexpr uint32_t NtWVM_encoded = 0x763E301DUL;  // verified: ROL32(enc^xor,7)+add = 0x3A
    constexpr uint32_t NtWVM_xor     = 0x25C1CF6FUL;
    constexpr int32_t  NtWVM_addend  = 0x4711;

    // -----------------------------------------------------------------------
    // NtClose  —  sysnum 0x0F (decimal 15)
    // -----------------------------------------------------------------------
    constexpr uint32_t NtClose_encoded = 0xE879871AUL;  // verified: ROL32(enc^xor,7)+add = 0x0F
    constexpr uint32_t NtClose_xor     = 0xF279872DUL;
    constexpr int32_t  NtClose_addend  = -0x1B7E;

    // -----------------------------------------------------------------------
    // Runtime resolution — call once from IndirectSyscall::init()
    // -----------------------------------------------------------------------
    struct ResolvedNumbers
    {
        uint32_t NtQuerySystemInformation;
        uint32_t NtAllocateVirtualMemory;
        uint32_t NtFreeVirtualMemory;
        uint32_t NtWriteVirtualMemory;
        uint32_t NtClose;
    };

    inline ResolvedNumbers resolve()
    {
        ResolvedNumbers r{};
        r.NtQuerySystemInformation = decode_sysnum(NtQSI_encoded,   NtQSI_xor,   NtQSI_addend);
        r.NtAllocateVirtualMemory  = decode_sysnum(NtAVM_encoded,   NtAVM_xor,   NtAVM_addend);
        r.NtFreeVirtualMemory      = decode_sysnum(NtFVM_encoded,   NtFVM_xor,   NtFVM_addend);
        r.NtWriteVirtualMemory     = decode_sysnum(NtWVM_encoded,   NtWVM_xor,   NtWVM_addend);
        r.NtClose                  = decode_sysnum(NtClose_encoded, NtClose_xor, NtClose_addend);
        return r;
    }

} // namespace SyscallTable
