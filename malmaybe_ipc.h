/*
 * malmaybe_ipc.h
 *
 * Shared definitions between malmaybe.sys (kernel) and malmaybe.exe (user).
 * Include this header in BOTH projects.
 *
 * Kernel side  : #include "malmaybe_ipc.h"  (after ntifs.h)
 * User mode    : #include "malmaybe_ipc.h"  (after windows.h / winioctl.h)
 */

#pragma once

/* ── Device name ─────────────────────────────────────────────────────────────── */
#define MALMAYBE_DEVICE_NAME_KERNEL   L"\\Device\\malmaybe"
#define MALMAYBE_DEVICE_NAME_SYMLINK  L"\\DosDevices\\malmaybe"
#define MALMAYBE_DEVICE_NAME_WIN32    "\\\\.\\malmaybe"
#define MALMAYBE_DEVICE_NAME_WIN32W   L"\\\\.\\malmaybe"

/* ── IOCTL ───────────────────────────────────────────────────────────────────── */
#define MALMAYBE_DEVICE_TYPE  0x8000u

/*
 * IOCTL_MALMAYBE_READ_EVENTS
 *
 *   Input  : none
 *   Output : array of MALMAYBE_EVENT records
 *
 *   Behaviour:
 *     If events are queued in the kernel ring buffer, the call returns
 *     immediately with as many events as fit in the output buffer.
 *     If the ring is empty, the call BLOCKS until at least one event
 *     is produced by the thread-create callback.
 *     Returns ERROR_NO_MORE_ITEMS if the driver is unloading.
 */
#define IOCTL_MALMAYBE_READ_EVENTS \
    CTL_CODE(MALMAYBE_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

/* ── Event flags ─────────────────────────────────────────────────────────────── */
#define MALMAYBE_FLAG_ALERT  0x00000001u  /* alert condition met        */
#define MALMAYBE_FLAG_ERROR  0x00000002u  /* kernel-side query failed   */

/* ── Event structure ─────────────────────────────────────────────────────────── */
/*
 * IMPORTANT: this structure is copied raw across the kernel/user boundary.
 * Do NOT change field order or sizes without updating both sides.
 * Total size = 4+4+4+4+8+4+4+4+4+192 = 232 bytes.
 */
#pragma pack(push, 1)
typedef struct _MALMAYBE_EVENT {
    ULONG     Sequence;         /* monotonically increasing counter              */
    ULONG     Flags;            /* MALMAYBE_FLAG_* bitmask                       */
    ULONG     ProcessId;        /* owning process ID                             */
    ULONG     ThreadId;         /* new thread ID                                 */
    ULONGLONG StartAddress;     /* Win32 thread start address (64-bit always)    */
    ULONG     MemType;          /* MEMORY_BASIC_INFORMATION.Type                 */
    ULONG     MemProtect;       /* MEMORY_BASIC_INFORMATION.Protect              */
    ULONG     MemState;         /* MEMORY_BASIC_INFORMATION.State                */
    ULONG     _pad;             /* reserved, always 0                            */
    CHAR      Message[192];     /* null-terminated human-readable event text     */
} MALMAYBE_EVENT, *PMALMAYBE_EVENT;
#pragma pack(pop)

/*
 * Convenient batch size for the user-mode receive buffer.
 * Agent allocates: MALMAYBE_EVENT batch[MALMAYBE_BATCH_SIZE];
 */
#define MALMAYBE_BATCH_SIZE  32u
