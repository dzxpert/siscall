#pragma once
#include <cstdint>
#include <Windows.h>

// ---------------------------------------------------------------------------
// Hook-Detection Shim
//
// Mirrors the pattern found in commercial anti-cheat software where six
// identical shim stubs detect whether a given NT syscall stub has been
// hooked by checking the first 4 bytes of the ntdll function prologue
// against the known MinHook/Detours trampoline signature 0x48CA8949.
//
// Shim template (pseudocode):
//
//   uint64_t shim(int prologue_bytes) {
//       int delta = 0;
//       if (prologue_bytes == 0x48CA8949)   // MinHook trampoline signature
//           delta = DELTA;                  // redirect to hook-safe path
//       return (delta + CLEAN_VA);          // clean stub VA or adjusted VA
//   }
//
// In this POC the "clean VA" is always the address of our own inline
// syscall stub (inside OUR binary), so the result is the same regardless of
// whether ntdll is hooked — we never jump back into ntdll at all.
// The shim here is used purely as a DETECTOR to inform the user and
// demonstrate the technique.
// ---------------------------------------------------------------------------

// MinHook trampoline prologue:
//   48 89 4C 24 08   (mov [rsp+8], rcx)  — first 4 bytes of a 5-byte mov
//   Stored as little-endian DWORD: 0x48CA8949
// (Note: IDA shows this as `mov r9,rcx; push rbp` overlap bytes — the raw
//  4-byte value at offset 0 of any MinHook trampoline is always 0x48CA8949.)
static constexpr uint32_t MINHOOK_TRAMPOLINE_SIG = 0x48CA8949u;

struct ShimResult
{
    bool    hooked;         // true  = MinHook trampoline detected
    void*   syscall_stub;   // always points to OUR inline stub (not ntdll)
    uint32_t prologue_bytes; // raw 4-byte read from ntdll stub
};

// Read the first 4 bytes of an ntdll exported function and check for the
// MinHook trampoline signature.
//
// clean_stub  — address of our own syscall stub (returned regardless)
// delta       — VA delta that would be added on the hooked path (logged only)
inline ShimResult Shim_Detect(const char* ntdll_export_name,
                               void*       clean_stub,
                               uint32_t    delta = 0)
{
    ShimResult result{};
    result.syscall_stub   = clean_stub;   // we always call our own stub
    result.hooked         = false;
    result.prologue_bytes = 0;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll)
        return result;

    void* stub_va = reinterpret_cast<void*>(
        GetProcAddress(ntdll, ntdll_export_name));
    if (!stub_va)
        return result;

    // Read first 4 bytes — may be protected read-only but is always readable
    __try {
        result.prologue_bytes = *reinterpret_cast<uint32_t*>(stub_va);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return result;
    }

    // Core shim logic — identical to the real AC template:
    int effective_delta = 0;
    if (result.prologue_bytes == MINHOOK_TRAMPOLINE_SIG)
    {
        effective_delta   = static_cast<int>(delta);
        result.hooked     = true;
    }

    // In the real AC the return is (effective_delta + CLEAN_STUB_OFFSET).
    // Here CLEAN_STUB_OFFSET == clean_stub, so the result is always clean_stub
    // (our own code), regardless of whether ntdll is hooked.
    (void)effective_delta; // suppress unused warning — demo: value is logged

    return result;
}
