# MalMaybe

> **Kernel-level process injection detection for Windows — research & lab use only.**

MalMaybe is a Windows kernel-mode driver (`MalMaybe.sys`) paired with a user-mode agent (`MalMaybe.exe`) that detects process injection attacks in real time. The driver hooks into the Windows kernel's thread-creation notification system and inspects the memory region of every new thread's start address before it executes a single instruction. Suspicious threads — those starting in private, executable, non-image-backed memory — are flagged and streamed to the agent for display and logging.

---

## How It Works

When any program on the system creates a new thread, Windows calls MalMaybe's registered callback (`PsSetCreateThreadNotifyRoutine`) before the thread runs. The driver then:

1. Reads the thread's **Win32 start address** — where the thread will actually begin executing
2. Queries the **memory type** at that address using `ZwQueryVirtualMemory`
3. Checks the **page protection flags** — is the memory executable?
4. If the memory is committed, not backed by a PE image on disk, and executable → **alert fired**

Events are placed in a kernel ring buffer and streamed to the agent via a custom IOCTL over a named device object (`\\.\MalMaybe`). The agent prints colour-coded output to the console and appends all events to `C:\MalMaybe.log`.

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

### Component Summary

| File | Role |
|---|---|
| `MalMaybe.c` | Kernel driver. Registers thread-create callback, maintains ring buffer, exposes `\\.\MalMaybe` device, streams events via IOCTL |
| `MalMaybe_agent.c` | User-mode agent. Opens the device, blocks on IOCTL until events arrive, prints colour-coded output, writes `C:\MalMaybe.log` |
| `MalMaybe_ipc.h` | Shared header. Defines `MalMaybe_EVENT` struct, IOCTL code, and flag constants — must be consistent between both projects |

---

## Detection Coverage

| Injection Technique | Detected | Notes |
|---|---|---|
| Classic shellcode (VirtualAllocEx + CreateRemoteThread) |  Yes | Primary target — MEM_PRIVATE + executable start address |
| Reflective DLL injection |  Partial | Detected if loader starts in private memory |
| APC injection |  No | No new thread created |
| Thread hijacking (SetThreadContext) |  No | Hijacks existing thread |
| Module stomping |  No | Retains MEM_IMAGE type, bypasses heuristic |
| Process hollowing |  No | Main thread resumes, no remote thread |
| Process Doppelgänging |  No | Requires additional kernel signals |

---

## Requirements

### Build Requirements

**Driver (`MalMaybe.sys`):**
- Visual Studio 2022
- Windows Driver Kit (WDK) matching your VS version
- Target: Windows 11, x64, Release

**Agent (`MalMaybe.exe`):**
- Any C compiler with Win32 headers
- Recommended: Build Tools for Visual Studio 2022

---

## Building

### Driver

1. Open the WDK kernel-mode driver project in Visual Studio
2. Add `MalMaybe.c` and `MalMaybe_ipc.h` to the project
3. Set configuration to **Release / x64**
4. In **Project Properties → Inf2Cat → Run Inf2Cat** → set to **No** (not needed for lab use)
5. Build → produces `MalMaybe.sys`

### Agent (compile on the VM)

Install [Build Tools for Visual Studio 2022](https://aka.ms/vs/17/release/vs_BuildTools.exe) on the VM, selecting the **Desktop development with C++** workload.

Open **Developer Command Prompt for VS 2022** as Administrator:

```cmd
cd C:\MalMaybe

cl /W4 /O2 /MT /nologo MalMaybe_agent.c /link /SUBSYSTEM:CONSOLE kernel32.lib user32.lib
```

This produces a fully self-contained `MalMaybe_agent.exe` with no DLL dependencies.

---

## Running

Copy to the test VM:
```
MalMaybe.sys
MalMaybe_agent.exe
```

**Order of operations:**

```
1.  Make VM:       Will require bigger RAM and DISK, Recommended to increase from Default values
2.  Decrypt Device:Windows 11 Bitlocker Encryption is ON by deafult. Turn OFF
3.  Secure Boot:   Turn OFF Secure Boot. 
4.  Load driver:   OSRLoader → select MalMaybe.sys → Register Service → Start Service
5.  Run agent:     Open Administrator cmd → MalMaybe_agent.exe
6.  Simulate:      Run your injection code
7.  Observe:       Alerts appear live in the agent console
8.  Review log:    C:\MalMaybe.log contains all events
9.  Unload driver: OSRLoader → Stop Service
```

### Expected Agent Output

```
╔══════════════════════════════════════════════════════╗
║              MalMaybe  —  Agent v2.0                 ║
║     Kernel-Level Process Injection Detection         ║
╚══════════════════════════════════════════════════════╝

  Device  : \\.\MalMaybe
  Log     : C:\MalMaybe.log

[2025-01-01 12:00:01] [info ] #1      PID=1234    TID=5678    Start=0x00007FF6A1B20000
                                Type=MEM_IMAGE       Protect=EXECUTE_READ          State=COMMIT

[2025-01-01 12:00:02] [ALERT] #2      PID=4321    TID=8765    Start=0x000001F3A0010000
                                Type=MEM_PRIVATE     Protect=EXECUTE_READWRITE     State=COMMIT

  *** INJECTION DETECTED ***  Non-image executable thread start address.
  PID=4321  TID=8765  Type=MEM_PRIVATE  Protect=EXECUTE_READWRITE
```


## Architecture: Kernel ↔ User IPC

The driver and agent communicate through a custom device and IOCTL, defined in `MalMaybe_ipc.h`.

```
┌─────────────────────────────────────┐
│           MalMaybe.sys              │  KERNEL MODE
│                                     │
│  ThreadNotify callback              │
│       │                             │
│       ▼                             │
│  Ring buffer [256 events]           │
│  (KSPIN_LOCK protected)             │
│       │                             │
│       ▼                             │
│  \\Device\\MalMaybe                 │
│  IOCTL_MalMaybe_READ_EVENTS         │
└──────────────┬──────────────────────┘
               │  DeviceIoControl (blocking)
┌──────────────▼──────────────────────┐
│          MalMaybe.exe               │  USER MODE
│                                     │
│  Blocking IOCTL loop                │
│  (zero CPU when idle)               │
│       │                             │
│       ├─► Colour-coded console      │
│       └─► C:\MalMaybe.log           │
└─────────────────────────────────────┘
```

**Key design properties:**
- The IOCTL **blocks** when the ring is empty — zero CPU usage while idle, no polling
- The ring buffer holds 256 events; oldest are overwritten if the agent falls behind
- Access to `\\.\MalMaybe` requires Administrator — enforced by the device ACL
- The driver handles agent crashes gracefully via `IRP_MJ_CLEANUP`

---

## Known Limitations

- **Detection scope:** Only catches injection techniques that create a new thread with a non-image start address. Techniques that reuse existing threads (APC injection, thread hijacking) or maintain image-type memory (module stomping) are not detected.
- **False positives:** JIT compilers (.NET CLR, V8, LuaJIT) legitimately create threads in private executable memory.
- **No kernel signature:** Requires TestSigning mode. Will not load on a standard consumer or enterprise Windows machine without WHQL signing & Microsoft charges money for that so nope
- **Single consumer:** The device is designed for one agent at a time.
---

## Future Roadmap


Detect More Injections, Make WhiteList for legit Software that trigger flags and Licensing - Make a Distributable Software Basically

---

## Disclaimer

> This project is intended **strictly for security research, education, and testing on systems you own or have explicit written authorisation to test.**
>
> Loading unsigned kernel drivers requires disabling Windows security features (Secure Boot, TestSigning). Do this only inside a virtual machine istg.
>
> I accept no responsibility for misuse. I dont get paid & idc.

---
