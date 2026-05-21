# malmaybe

> **Kernel-level process injection detection for Windows — research & lab use only.**

malmaybe is a Windows kernel-mode driver (`malmaybe.sys`) paired with a user-mode agent (`malmaybe.exe`) that detects process injection attacks in real time. The driver hooks into the Windows kernel's thread-creation notification system and inspects the memory region of every new thread's start address before it executes a single instruction. Suspicious threads — those starting in private, executable, non-image-backed memory — are flagged and streamed to the agent for display and logging.

---

## How It Works

When any program on the system creates a new thread, Windows calls malmaybe's registered callback (`PsSetCreateThreadNotifyRoutine`) before the thread runs. The driver then:

1. Reads the thread's **Win32 start address** — where the thread will actually begin executing
2. Queries the **memory type** at that address using `ZwQueryVirtualMemory`
3. Checks the **page protection flags** — is the memory executable?
4. If the memory is committed, not backed by a PE image on disk, and executable → **alert fired**

Events are placed in a kernel ring buffer and streamed to the agent via a custom IOCTL over a named device object (`\\.\malmaybe`). The agent prints colour-coded output to the console and appends all events to `C:\malmaybe.log`.

```
New thread created anywhere on system
  │
  ▼
ThreadNotify callback fires (kernel, PASSIVE_LEVEL)
  │
  ├─► Get Win32 start address
  ├─► Query virtual memory at that address
  ├─► Check: MEM_COMMIT + NOT MEM_IMAGE + executable protection?
  │
  ├─ YES → [ALERT] pushed to ring buffer → agent displays & logs
  └─ NO  → [info]  pushed to ring buffer → agent logs verbosely
```

### The Alert Condition

| Field | Required value | Meaning |
|---|---|---|
| `mbi.State` | `MEM_COMMIT` | Memory is backed by RAM/pagefile and can execute |
| `mbi.Type` | NOT `MEM_IMAGE` | Not from a real PE file on disk — private or mapped |
| `mbi.Protect` | Any `PAGE_EXECUTE_*` | The page is actually executable |

All three must be true simultaneously to fire an alert. This catches the classic shellcode injection pattern: `VirtualAllocEx` (creates `MEM_PRIVATE`) + `WriteProcessMemory` + `CreateRemoteThread`.

---

## Project Structure

```
malmaybe/
├── malmaybe.c           # Kernel-mode driver (WDM) — malmaybe.sys
├── malmaybe_agent.c     # User-mode console agent — malmaybe.exe
├── malmaybe_ipc.h       # Shared IPC definitions (IOCTL, event struct)
└── README.md
```

### Component Summary

| File | Role |
|---|---|
| `malmaybe.c` | Kernel driver. Registers thread-create callback, maintains ring buffer, exposes `\\.\malmaybe` device, streams events via IOCTL |
| `malmaybe_agent.c` | User-mode agent. Opens the device, blocks on IOCTL until events arrive, prints colour-coded output, writes `C:\malmaybe.log` |
| `malmaybe_ipc.h` | Shared header. Defines `MALMAYBE_EVENT` struct, IOCTL code, and flag constants — must be consistent between both projects |

---

## Detection Coverage

| Injection Technique | Detected | Notes |
|---|---|---|
| Classic shellcode (VirtualAllocEx + CreateRemoteThread) | ✅ Yes | Primary target — MEM_PRIVATE + executable start address |
| Reflective DLL injection | ✅ Partial | Detected if loader starts in private memory |
| APC injection | ❌ No | No new thread created |
| Thread hijacking (SetThreadContext) | ❌ No | Hijacks existing thread |
| Module stomping | ❌ No | Retains MEM_IMAGE type, bypasses heuristic |
| Process hollowing | ❌ No | Main thread resumes, no remote thread |
| Process Doppelgänging | ❌ No | Requires additional kernel signals |

---

## Requirements

### Test Environment (validated configuration)

| Component | Requirement |
|---|---|
| OS | Windows 10 / 11 x64 (tested on Windows 11) |
| Secure Boot | **Disabled** |
| Device Encryption | **Disabled** |
| Boot mode | **Debug mode enabled** (`bcdedit /debug on`) |
| Driver signing | **TestSigning enabled** (`bcdedit /set testsigning on`) |
| Driver loader | OSRLoader (or `sc.exe`) |
| Debug viewer | DebugView (Sysinternals) — optional, for kernel DbgPrint output |

> ⚠️ These settings weaken system security. Use a dedicated virtual machine, never a production machine.

### Build Requirements

**Driver (`malmaybe.sys`):**
- Visual Studio 2022
- Windows Driver Kit (WDK) matching your VS version
- Target: Windows 11, x64, Release

**Agent (`malmaybe.exe`):**
- Any C compiler with Win32 headers
- Recommended: Build Tools for Visual Studio 2022

---

## Building

### Driver

1. Open the WDK kernel-mode driver project in Visual Studio
2. Add `malmaybe.c` and `malmaybe_ipc.h` to the project
3. Set configuration to **Release / x64**
4. In **Project Properties → Inf2Cat → Run Inf2Cat** → set to **No** (not needed for lab use)
5. Build → produces `malmaybe.sys`

### Agent (compile on the VM)

Install [Build Tools for Visual Studio 2022](https://aka.ms/vs/17/release/vs_BuildTools.exe) on the VM, selecting the **Desktop development with C++** workload.

Open **Developer Command Prompt for VS 2022** as Administrator:

```cmd
cd C:\malmaybe

cl /W4 /O2 /MT /nologo malmaybe_agent.c /link /SUBSYSTEM:CONSOLE kernel32.lib user32.lib
```

This produces a fully self-contained `malmaybe_agent.exe` with no DLL dependencies.

---

## Running

Copy to the test VM:
```
malmaybe.sys
malmaybe_agent.exe
```

**Order of operations:**

```
1.  Load driver:   OSRLoader → select malmaybe.sys → Register Service → Start Service
2.  Run agent:     Open Administrator cmd → malmaybe_agent.exe
3.  Simulate:      Run your injection test (see below)
4.  Observe:       Alerts appear live in the agent console
5.  Review log:    C:\malmaybe.log contains all events
6.  Unload driver: OSRLoader → Stop Service
```

### Expected Agent Output

```
╔══════════════════════════════════════════════════════╗
║              malmaybe  —  Agent v2.0                ║
║     Kernel-Level Process Injection Detection         ║
╚══════════════════════════════════════════════════════╝

  Device  : \\.\malmaybe
  Log     : C:\malmaybe.log

[2025-01-01 12:00:01] [info ] #1      PID=1234    TID=5678    Start=0x00007FF6A1B20000
                                Type=MEM_IMAGE       Protect=EXECUTE_READ          State=COMMIT

[2025-01-01 12:00:02] [ALERT] #2      PID=4321    TID=8765    Start=0x000001F3A0010000
                                Type=MEM_PRIVATE     Protect=EXECUTE_READWRITE     State=COMMIT

  *** INJECTION DETECTED ***  Non-image executable thread start address.
  PID=4321  TID=8765  Type=MEM_PRIVATE  Protect=EXECUTE_READWRITE
```

### Simulating Injection (NOP Shellcode Test)

A basic injection simulation using NOP (`0x90`) shellcode:

```c
// Target an existing process (e.g. notepad.exe)
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);

// Allocate RWX memory in the target
LPVOID addr = VirtualAllocEx(hProc, NULL, 4096,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);   // ← this triggers the alert

// Write NOP sled
BYTE nops[4096];
memset(nops, 0x90, sizeof(nops));
WriteProcessMemory(hProc, addr, nops, sizeof(nops), NULL);

// Create remote thread pointing at the shellcode
CreateRemoteThread(hProc, NULL, 0,
                   (LPTHREAD_START_ROUTINE)addr,
                   NULL, 0, NULL);
```

malmaybe detects this at the `CreateRemoteThread` call — before the NOPs execute.

---

## Architecture: Kernel ↔ User IPC

The driver and agent communicate through a custom device and IOCTL, defined in `malmaybe_ipc.h`.

```
┌─────────────────────────────────────┐
│           malmaybe.sys              │  KERNEL MODE
│                                     │
│  ThreadNotify callback              │
│       │                             │
│       ▼                             │
│  Ring buffer [256 events]           │
│  (KSPIN_LOCK protected)             │
│       │                             │
│       ▼                             │
│  \\Device\\malmaybe                 │
│  IOCTL_MALMAYBE_READ_EVENTS         │
└──────────────┬──────────────────────┘
               │  DeviceIoControl (blocking)
┌──────────────▼──────────────────────┐
│          malmaybe.exe               │  USER MODE
│                                     │
│  Blocking IOCTL loop                │
│  (zero CPU when idle)               │
│       │                             │
│       ├─► Colour-coded console      │
│       └─► C:\malmaybe.log           │
└─────────────────────────────────────┘
```

**Key design properties:**
- The IOCTL **blocks** when the ring is empty — zero CPU usage while idle, no polling
- The ring buffer holds 256 events; oldest are overwritten if the agent falls behind
- Access to `\\.\malmaybe` requires Administrator — enforced by the device ACL
- The driver handles agent crashes gracefully via `IRP_MJ_CLEANUP`

---

## Known Limitations

- **Detection scope:** Only catches injection techniques that create a new thread with a non-image start address. Techniques that reuse existing threads (APC injection, thread hijacking) or maintain image-type memory (module stomping) are not detected.
- **False positives:** JIT compilers (.NET CLR, V8, LuaJIT) legitimately create threads in private executable memory. In a production context these would need to be filtered by process allow-list.
- **No kernel signature:** Requires TestSigning mode. Will not load on a standard consumer or enterprise Windows machine without WHQL signing.
- **Single consumer:** The device is designed for one agent at a time.

---

## Future Roadmap

- [ ] `PsSetLoadImageNotifyRoutine` — detect suspicious DLL loads and module stomping
- [ ] `ObRegisterCallbacks` — intercept `OpenProcess` calls with write access (earliest injection signal)
- [ ] `PsSetCreateProcessNotifyRoutineEx` — detect process hollowing at process-create time
- [ ] Process allow-list for known JIT runtimes (reduce false positives)
- [ ] GUI agent (system tray, alert popups, one-click allow-listing)
- [ ] WHQL driver signing for deployment on standard Windows machines
- [ ] SIEM/ETW integration for enterprise environments

---

## Disclaimer

> This project is intended **strictly for security research, education, and testing on systems you own or have explicit written authorisation to test.**
>
> Loading unsigned kernel drivers requires disabling Windows security features (Secure Boot, TestSigning). Do this only inside a dedicated virtual machine.
>
> The authors accept no responsibility for misuse.

---

## References

- [PsSetCreateThreadNotifyRoutine — Microsoft Docs](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine)
- [ZwQueryVirtualMemory — NT DDK Reference](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/)
- [Windows Internals, 7th Edition — Yosifovich, Ionescu et al.](https://docs.microsoft.com/en-us/sysinternals/resources/windows-internals)
- [OSRLoader — Open Systems Resources](https://www.osronline.com/article.cfm%5Earticle=157.htm)
- [DebugView — Sysinternals](https://docs.microsoft.com/en-us/sysinternals/downloads/debugview)
