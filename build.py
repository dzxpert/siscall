#!/usr/bin/env python3
"""
build.py — Indirect Syscall POC build helper
=============================================

Reads the j00ru windows-syscalls database, lets you pick a Windows version,
generates the correct ROL-XOR encoded syscall number table in
siscall/include/syscall_numbers.h, then invokes MSBuild.

Usage:
  python build.py                         # interactive version picker
  python build.py --os "Windows 10" --ver "22H2"   # non-interactive
  python build.py --list                  # list all available versions
  python build.py --dry-run              # generate header only, skip build
"""

import argparse
import json
import os
import subprocess
import sys

# ---------------------------------------------------------------------------
# Paths (relative to this script)
# ---------------------------------------------------------------------------
SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH      = os.path.join(SCRIPT_DIR, "windows-syscalls", "x64", "json", "nt-per-syscall.json")
HEADER_PATH  = os.path.join(SCRIPT_DIR, "siscall", "include", "syscall_numbers.h")
SLN_PATH     = os.path.join(SCRIPT_DIR, "siscall.sln")

# ---------------------------------------------------------------------------
# Syscalls we care about — {name: (xor_key, addend)}
# The xor_key / addend values are fixed per-syscall (matching the pattern
# in the original AC binary).  Only the encoded constant changes per OS.
# ---------------------------------------------------------------------------
SYSCALL_CONFIG = {
    "NtQuerySystemInformation": (0x739C3D8C,  0x1F9A),
    "NtAllocateVirtualMemory":  (0xBE3ED1F2,  0x3927),
    "NtFreeVirtualMemory":      (0xAB1F3330, -0x23E1),
    "NtWriteVirtualMemory":     (0x25C1CF6F,  0x4711),
    "NtClose":                  (0xF279872D, -0x1B7E),
}

VAR_NAMES = {
    "NtQuerySystemInformation": "NtQSI",
    "NtAllocateVirtualMemory":  "NtAVM",
    "NtFreeVirtualMemory":      "NtFVM",
    "NtWriteVirtualMemory":     "NtWVM",
    "NtClose":                  "NtClose",
}

# ---------------------------------------------------------------------------
# ROL/ROR helpers
# ---------------------------------------------------------------------------
def rol32(v: int, n: int) -> int:
    v &= 0xFFFFFFFF
    n &= 31
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

def ror32(v: int, n: int) -> int:
    return rol32(v, 32 - n)

def encode(sysnum: int, xor_key: int, addend: int) -> int:
    """Produce the encoded global: ROR32((sysnum - addend) & mask, 7) ^ xor_key"""
    pre = (sysnum - addend) & 0xFFFFFFFF
    return ror32(pre, 7) ^ (xor_key & 0xFFFFFFFF)

def decode(encoded: int, xor_key: int, addend: int) -> int:
    """Verify round-trip: ROL32(encoded ^ xor_key, 7) + addend"""
    return (rol32(encoded ^ (xor_key & 0xFFFFFFFF), 7) + addend) & 0xFFFFFFFF

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def load_db() -> dict:
    if not os.path.exists(DB_PATH):
        print(f"[!] Database not found: {DB_PATH}", file=sys.stderr)
        sys.exit(1)
    with open(DB_PATH, encoding="utf-8") as f:
        return json.load(f)

def build_version_map(db: dict) -> dict[str, dict[str, int]]:
    """
    Returns { os_group: { version_label: sysnum_for_NtClose } } built from
    NtClose as a representative syscall so we can enumerate available versions.
    Returns { os_group: set_of_version_labels }.
    Actually returns { f"{os_group} / {ver}": { syscall: number } }.
    """
    # Collect all (os_group, ver) pairs that appear in every required syscall
    from collections import defaultdict
    version_coverage: dict[str, dict[str, int]] = {}   # "OS / ver" -> {syscall: num}

    for syscall_name in SYSCALL_CONFIG:
        if syscall_name not in db:
            print(f"[!] Syscall '{syscall_name}' not found in database.", file=sys.stderr)
            sys.exit(1)
        for os_group, versions in db[syscall_name].items():
            for ver, num in versions.items():
                key = f"{os_group} / {ver}"
                if key not in version_coverage:
                    version_coverage[key] = {}
                version_coverage[key][syscall_name] = num

    # Keep only keys where all 5 syscalls are present
    complete = {k: v for k, v in version_coverage.items()
                if len(v) == len(SYSCALL_CONFIG)}
    return complete

def lookup_syscall(db: dict, syscall: str, os_group: str, ver: str) -> int | None:
    entry = db.get(syscall, {})
    return entry.get(os_group, {}).get(ver)

# ---------------------------------------------------------------------------
# Header generator
# ---------------------------------------------------------------------------
HEADER_TEMPLATE = """\
#pragma once
#include <cstdint>
#include "rol_helpers.h"

// ---------------------------------------------------------------------------
// Obfuscated syscall number table
//
// AUTO-GENERATED by build.py — do not edit by hand.
// Target OS: {os_label}
//
// Decode formula:  sysnum = ROL32(encoded ^ xor_key, 7) + addend
// Encode formula:  encoded = ROR32((sysnum - addend) & 0xFFFFFFFF, 7) ^ xor_key
// ---------------------------------------------------------------------------

namespace SyscallTable
{{
{entries}

    // -----------------------------------------------------------------------
    // Runtime resolution — call once from IndirectSyscall::init()
    // -----------------------------------------------------------------------
    struct ResolvedNumbers
    {{
        uint32_t NtQuerySystemInformation;
        uint32_t NtAllocateVirtualMemory;
        uint32_t NtFreeVirtualMemory;
        uint32_t NtWriteVirtualMemory;
        uint32_t NtClose;
    }};

    inline ResolvedNumbers resolve()
    {{
        ResolvedNumbers r{{}};
        r.NtQuerySystemInformation = decode_sysnum(NtQSI_encoded,   NtQSI_xor,   NtQSI_addend);
        r.NtAllocateVirtualMemory  = decode_sysnum(NtAVM_encoded,   NtAVM_xor,   NtAVM_addend);
        r.NtFreeVirtualMemory      = decode_sysnum(NtFVM_encoded,   NtFVM_xor,   NtFVM_addend);
        r.NtWriteVirtualMemory     = decode_sysnum(NtWVM_encoded,   NtWVM_xor,   NtWVM_addend);
        r.NtClose                  = decode_sysnum(NtClose_encoded, NtClose_xor, NtClose_addend);
        return r;
    }}

}} // namespace SyscallTable
"""

ENTRY_TEMPLATE = """\
    // {syscall} — sysnum 0x{sysnum:02X} ({sysnum_dec}) on {os_label}
    constexpr uint32_t {var}_encoded = 0x{enc:08X}UL;  // verified ✓
    constexpr uint32_t {var}_xor     = 0x{xor:08X}UL;
    constexpr int32_t  {var}_addend  = {addend_str};
"""

def generate_header(syscall_map: dict[str, int], os_label: str) -> str:
    """syscall_map: { syscall_name: sysnum }"""
    entries = []
    for syscall_name, (xor_key, addend) in SYSCALL_CONFIG.items():
        sysnum = syscall_map[syscall_name]
        enc    = encode(sysnum, xor_key, addend)
        # sanity check
        dec = decode(enc, xor_key, addend)
        assert dec == sysnum, f"Round-trip failed for {syscall_name}!"

        var = VAR_NAMES[syscall_name]
        addend_u = addend & 0xFFFFFFFF
        addend_str = f"0x{addend:X}" if addend >= 0 else f"-0x{(-addend):X}"

        entries.append(ENTRY_TEMPLATE.format(
            syscall=syscall_name,
            sysnum=sysnum,
            sysnum_dec=sysnum,
            os_label=os_label,
            var=var,
            enc=enc,
            xor=xor_key & 0xFFFFFFFF,
            addend_str=addend_str,
        ))

    return HEADER_TEMPLATE.format(
        os_label=os_label,
        entries="".join(entries).rstrip(),
    )

# ---------------------------------------------------------------------------
# Interactive version picker
# ---------------------------------------------------------------------------
def pick_version_interactive(version_map: dict) -> str:
    keys = sorted(version_map.keys())

    # Group by OS family for display
    from collections import defaultdict
    by_family: dict[str, list] = defaultdict(list)
    for k in keys:
        family = k.split(" / ")[0]
        by_family[family].append(k)

    print("\nAvailable target OS versions:\n")
    indexed = []
    for family in sorted(by_family):
        print(f"  {family}")
        for k in by_family[family]:
            ver = k.split(" / ", 1)[1]
            print(f"    [{len(indexed):3d}] {ver}")
            indexed.append(k)
    print()

    while True:
        raw = input("  Select index: ").strip()
        try:
            idx = int(raw)
            if 0 <= idx < len(indexed):
                return indexed[idx]
        except ValueError:
            pass
        print(f"  Invalid — enter a number between 0 and {len(indexed)-1}")

# ---------------------------------------------------------------------------
# MSBuild invocation
# ---------------------------------------------------------------------------
def find_msbuild() -> str | None:
    # Common VS2022 locations
    candidates = [
        r"C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\Enterprise\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
        r"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe",
    ]
    for c in candidates:
        if os.path.exists(c):
            return c
    # Try PATH
    import shutil
    return shutil.which("msbuild") or shutil.which("MSBuild")

def run_build(config: str = "Release") -> bool:
    msbuild = find_msbuild()
    if not msbuild:
        print("[!] MSBuild not found. Header has been updated — build manually.", file=sys.stderr)
        return False

    cmd = [msbuild, SLN_PATH,
           f"/p:Configuration={config}",
           "/p:Platform=x64",
           "/v:m",
           "/nologo"]
    print(f"\n[build] {' '.join(cmd)}\n")
    result = subprocess.run(cmd)
    return result.returncode == 0

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Indirect Syscall POC — build helper")
    parser.add_argument("--list",    action="store_true", help="List available OS versions and exit")
    parser.add_argument("--os",      default="",  help='OS family, e.g. "Windows 10"')
    parser.add_argument("--ver",     default="",  help='Version label, e.g. "22H2"')
    parser.add_argument("--config",  default="Release", choices=["Release", "Debug"])
    parser.add_argument("--dry-run", action="store_true", help="Generate header only, skip MSBuild")
    args = parser.parse_args()

    db          = load_db()
    version_map = build_version_map(db)

    if args.list:
        from collections import defaultdict
        by_family: dict[str, list] = defaultdict(list)
        for k in sorted(version_map):
            by_family[k.split(" / ")[0]].append(k.split(" / ", 1)[1])
        for family in sorted(by_family):
            print(f"{family}:")
            for ver in by_family[family]:
                print(f"  {ver}")
        return

    # Resolve selection
    if args.os and args.ver:
        key = f"{args.os} / {args.ver}"
        if key not in version_map:
            # Try "Windows 11 and Server / 11 22H2" style
            alt = f"{args.os} and Server / {args.os.split()[-1]} {args.ver}"
            if alt in version_map:
                key = alt
            else:
                print(f"[!] Version not found: '{key}'\n    Run with --list to see options.")
                sys.exit(1)
    else:
        key = pick_version_interactive(version_map)

    syscall_map = version_map[key]
    os_label    = key

    # Print what we found
    print(f"\n[*] Target OS: {os_label}")
    print("[*] Resolved syscall numbers:")
    for name, num in syscall_map.items():
        print(f"    {name:<40} = 0x{num:02X} ({num})")

    # Generate header
    header = generate_header(syscall_map, os_label)
    with open(HEADER_PATH, "w", encoding="utf-8") as f:
        f.write(header)
    print(f"\n[+] Written: {HEADER_PATH}")

    if args.dry_run:
        print("[*] --dry-run: skipping build.")
        return

    # Build
    ok = run_build(args.config)
    if ok:
        out_exe = os.path.join(SCRIPT_DIR, args.config, "siscall.exe")
        print(f"\n[+] Build succeeded: {out_exe}")
    else:
        print("\n[!] Build failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
