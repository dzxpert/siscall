# Indirect Syscall POC

A minimal Windows x64 proof-of-concept that demonstrates the **indirect syscall** dispatch technique used by certain anti-cheat and security software.

The binary calls NT APIs (`NtQuerySystemInformation`, `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtFreeVirtualMemory`) directly via an inline `syscall` instruction located **inside this binary**, fully bypassing ntdll.dll stubs and any usermode hooks placed on them.

---

## Techniques Demonstrated

### 1. ROL-XOR Obfuscated Syscall Numbers

Syscall numbers are **not stored as plain integers**. Each one is encoded as a `{encoded_global, xor_key, addend}` triple:

```
sysnum  =  ROL32(encoded_global  XOR  xor_key, 7)  +  addend
```

At startup the triple is decoded to produce the real Windows NT syscall index. This pattern makes static analysis of syscall numbers non-trivial — the encoded values appear random, and the key and addend differ per-syscall.

### 2. Hook-Detection Shim

Before issuing any syscall the dispatch layer reads the **first 4 bytes** of the corresponding `ntdll.dll` export and compares them against `0x48CA8949` — the prologue bytes of a [MinHook](https://github.com/TsudaKageyu/minhook) / Detours trampoline stub. The result is printed at startup:

```
[hook_shim] Scanning ntdll stubs for hooks...
  NtQuerySystemInformation  prologue=0x4C8BD1B8  [-] Clean
  NtAllocateVirtualMemory   prologue=0x4C8BD1B8  [-] Clean
  NtFreeVirtualMemory       prologue=0x4C8BD1B8  [-] Clean
```

Regardless of the hook status, all syscalls are always issued from our own binary — the shim is purely diagnostic here.

### 3. Inline `syscall` Instruction (MASM)

The actual `syscall` instruction lives in a hand-written MASM stub (`syscall_dispatch.asm`) assembled into our `.text` section. At the moment the kernel transitions into ring-0, the `RIP` register points **into this binary**, not into `ntdll.dll`. Any hook on an ntdll stub is therefore never executed.

---

## Building

**Requirements:**
- Python 3.10+
- Visual Studio 2022 (any edition) with MASM support

### Recommended — `build.py` (version-aware)

The build script reads the bundled j00ru syscall database (`windows-syscalls/x64/json/nt-per-syscall.json`), lets you select the exact Windows version you're targeting, auto-generates the correct `syscall_numbers.h` with verified ROL-XOR encoded constants, then calls MSBuild.

```
# Interactive version picker
python build.py

# Non-interactive
python build.py --os "Windows 10" --ver "22H2"
python build.py --os "Windows 11 and Server" --ver "11 24H2"

# List all available versions
python build.py --list

# Generate header only, skip build
python build.py --os "Windows 11 and Server" --ver "11 24H2" --dry-run

# Debug build
python build.py --os "Windows 10" --ver "22H2" --config Debug
```

Output: `Release\siscall.exe` (or `Debug\siscall.exe`)

### Manual — MSBuild directly

If you just want to rebuild without changing the target OS:

```
msbuild siscall.sln /p:Configuration=Release /p:Platform=x64
```

---

## Expected Output

```
============================================================
  Indirect Syscall POC
  Demonstrates ROL-XOR obfusc. + hook-detection shim + direct syscall
============================================================

[syscall_numbers] Decoded syscall table:
  NtQuerySystemInformation  = 0x36 (54)
  NtAllocateVirtualMemory   = 0x18 (24)
  NtFreeVirtualMemory       = 0x1E (30)
  NtWriteVirtualMemory      = 0x3A (58)
  NtClose                   = 0x0F (15)

[hook_shim] Scanning ntdll stubs for hooks...
  NtQuerySystemInformation  prologue=0x4C8BD1B8  [-] Clean
  NtAllocateVirtualMemory   prologue=0x4C8BD1B8  [-] Clean
  NtFreeVirtualMemory       prologue=0x4C8BD1B8  [-] Clean

[*] Syscall stub lives at:  0x00007FF...  (inside OUR binary)
[*] All syscalls will be issued from this address regardless of ntdll hook state.

=== Demo 1: NtQuerySystemInformation (SystemBasicInformation) ===
[+] NtQuerySystemInformation via indirect syscall  OK  (status=0x00000000)
    PageSize              : 4096 bytes
    AllocationGranularity : 65536 bytes
    NumberOfProcessors    : 16
    PhysicalPages         : 2097152  (~8192 MB RAM)
    UserModeRange         : 0x0000000000010000 – 0x00007FFFFFFEFFFF

=== Demo 2: NtAllocateVirtualMemory / NtWriteVirtualMemory / NtFreeVirtualMemory ===
[+] NtAllocateVirtualMemory OK  — base=0x...  size=4096 bytes
[+] NtWriteVirtualMemory  OK  — wrote 41 bytes
    Readback: "indirect_syscall_poc_pattern_0xDEADC0DE"
[+] NtFreeVirtualMemory   OK

=== Demo 3: Syscall instruction origin ===
    Our syscall stub VA  : 0x... (module: ...\Release\siscall.exe)
    ntdll!NtQSI VA       : 0x... (module: ntdll.dll)
    RIP at syscall time  : inside OUR binary — ntdll stubs never executed.

[+] All NT calls bypass ntdll.dll hooks completely.
============================================================
  All demos complete.
============================================================
```

---

## Project Layout

```
siscall/
├── siscall.sln
└── siscall/
    ├── siscall.vcxproj
    ├── include/
    │   ├── rol_helpers.h        — ROL32/ROL64 decode primitives
    │   ├── syscall_numbers.h    — Obfuscated syscall number table + decoder
    │   ├── hook_shim.h          — Hook-detection shim (0x48CA8949 check)
    │   └── indirect_syscall.h   — High-level NT call wrappers
    └── src/
        ├── syscall_dispatch.asm — MASM: inline `syscall` stub
        ├── indirect_syscall.cpp — Init: decode numbers + run shims
        └── main.cpp             — Demo entry point
```

---

## Notes

- **Architecture:** x64 only. The technique is architecture-specific.
- **Windows version:** Syscall numbers are calibrated for Windows 10 21H2 / Windows 11 22H2 x64. Numbers rarely change across minor builds but can differ on very old or insider builds.
- **Detection:** While this technique defeats usermode hooks, kernel-level ETW providers and hypervisor-based monitors (e.g. VTx EPT hooks) will still observe the raw `syscall` instruction. The `RIP` at syscall time will point into this binary's `.text` section rather than `ntdll!Nt*`, which is itself a detectable signal.

---

## References

- [j00ru/windows-syscalls](https://github.com/j00ru/windows-syscalls) — Windows NT/win32k syscall tables across all major OS versions (XP → Win11 25H2), used by `build.py` to generate version-accurate syscall number encodings.
- [Cerebro Anti-Cheat Analysis — UnknownCheats](https://www.unknowncheats.me/forum/anti-cheat-bypass/732919-cerebro-analysis.html) — Static reverse engineering analysis of the Cerebro/Theia anti-cheat engine, documenting the ROL-XOR syscall obfuscation pattern, hook-detection shims, and behavioral analysis engine that inspired this POC.
