#pragma once
#include <cstdint>

// ---------------------------------------------------------------------------
// ROL helpers — compile-time capable, mirrors the anti-cheat obfuscation
// pattern exactly:
//
//   32-bit syscall decode:  ROL32(encoded_global ^ XOR_KEY, 7) + ADDEND
//   64-bit fnptr decode:    ROL64(encoded_global ^ XOR_CONST, 7) + ADDEND
// ---------------------------------------------------------------------------

constexpr uint32_t rol32(uint32_t v, int n)
{
    n &= 31;
    return (v << n) | (v >> (32 - n));
}

constexpr uint64_t rol64(uint64_t v, int n)
{
    n &= 63;
    return (v << n) | (v >> (64 - n));
}

// Decode a 32-bit (syscall number) obfuscated global
//   encoded  – value stored in the global
//   xor_key  – per-syscall XOR mask
//   addend   – per-syscall signed addend (cast to int32_t)
//   rotation – rotation amount (canonical = 7)
inline uint32_t decode_sysnum(uint32_t encoded, uint32_t xor_key,
                              int32_t addend, int rotation = 7)
{
    return static_cast<uint32_t>(
        static_cast<int32_t>(rol32(encoded ^ xor_key, rotation)) + addend);
}

// Decode a 64-bit (function pointer) obfuscated global
//   encoded  – value stored in the global
//   xor_key  – 64-bit XOR constant
//   addend   – 64-bit addend (unsigned wrap)
//   rotation – rotation amount (canonical = 7)
inline uint64_t decode_fnptr(uint64_t encoded, uint64_t xor_key,
                             uint64_t addend, int rotation = 7)
{
    return rol64(encoded ^ xor_key, rotation) + addend;
}
