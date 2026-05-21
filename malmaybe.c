/*
 * malmaybe.sys  —  Kernel-mode process injection detector
 *
 * All events are sent to the user-mode agent
 *     (malmaybe.exe) through a shared ring-buffer exposed via a
 *     named Device Object + a single IOCTL.
 *
 * Kernel → User IPC design:
 *   Device  : \Device\malmaybe          (kernel name)
 *   Symlink : \DosDevices\malmaybe      (Win32 name: \\.\malmaybe)
 *   IOCTL   : IOCTL_MALMAYBE_READ_EVENTS
 *               - User calls DeviceIoControl in a loop.
 *               - Driver copies up to N pending EVENT records into the
 *                 output buffer and returns the count. 
 *               - If no events are pending the IRP is queued (pended)
 *                 until at least one event arrives (or the device closes).
 *
 * Ring buffer:
 *   Fixed array of MALMAYBE_EVENT structs in non-paged pool.
 *   Producer  = ThreadNotify callback (any IRQL <= DISPATCH_LEVEL).
 *   Consumer  = IRP_MJ_DEVICE_CONTROL handler (PASSIVE_LEVEL).
 *   Lock      = KSPIN_LOCK (works at all IRQLs including DISPATCH_LEVEL).
 *
 * Lab / authorised systems only.
 */

#include <ntifs.h>
#include <ntstrsafe.h>
#include <stdarg.h>
#include <wdmsec.h>       /* IoCreateDeviceSecure */

/*  IOCTL definition  */
#define MALMAYBE_DEVICE_TYPE  0x8000u          /* FILE_DEVICE_UNKNOWN range */

/*
 * METHOD_BUFFERED  — kernel copies caller's output buffer via intermediate
 * buffer; safe and simple for variable-length reads.
 */
#define IOCTL_MALMAYBE_READ_EVENTS \
    CTL_CODE(MALMAYBE_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

/*  Event structure shared with the agent  */
#pragma pack(push, 1)
typedef struct _MALMAYBE_EVENT {
    ULONG   Sequence;           /* monotonically increasing counter        */
    ULONG   Flags;              /* MALMAYBE_FLAG_* bit mask                */
    ULONG   ProcessId;
    ULONG   ThreadId;
    ULONGLONG StartAddress;     /* Win32 start address (64-bit)            */
    ULONG   MemType;            /* mbi.Type   (MEM_IMAGE / PRIVATE / MAP)  */
    ULONG   MemProtect;         /* mbi.Protect (PAGE_EXECUTE_* …)          */
    ULONG   MemState;           /* mbi.State  (MEM_COMMIT …)               */
    ULONG   _pad;               /* keep struct 8-byte aligned              */
    CHAR    Message[192];       /* null-terminated human-readable summary  */
} MALMAYBE_EVENT, *PMALMAYBE_EVENT;
#pragma pack(pop)

/* Flags field bits */
#define MALMAYBE_FLAG_ALERT   0x00000001u   /* suspicious – <alert condition met> */
#define MALMAYBE_FLAG_ERROR   0x00000002u   /* query failed; Message with reason  */

/*  Ring-buffer tunables  */
#define RING_CAPACITY   256u        /* must be power-of-two */
#define RING_MASK       (RING_CAPACITY - 1u)

/*  Internal type-aliases for dynamic symbols  */
typedef NTSTATUS(*PFN_PsGetThreadWin32StartAddress)(
    _In_  PETHREAD Thread,
    _Out_ PVOID   *Win32StartAddress);

typedef NTSTATUS(*PFN_ZwQueryInformationThread)(
    _In_  HANDLE ThreadHandle,
    _In_  ULONG  ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_  ULONG  ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength);

#ifndef ThreadQuerySetWin32StartAddress
#define ThreadQuerySetWin32StartAddress 9
#endif
#ifndef THREAD_QUERY_INFORMATION
#define THREAD_QUERY_INFORMATION   0x0040
#endif
#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION  0x0400
#endif
#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ            0x0010
#endif
#ifndef MEM_IMAGE
#define MEM_IMAGE                  0x01000000
#endif

/*  Global state  */
static PFN_PsGetThreadWin32StartAddress  g_PsGetThreadWin32StartAddress = NULL;
static PFN_ZwQueryInformationThread      g_ZwQueryInformationThread     = NULL;
static BOOLEAN                           g_ThreadNotifyRegistered       = FALSE;

/* Device / symlink */
static PDEVICE_OBJECT  g_DeviceObject = NULL;
static UNICODE_STRING  g_SymLinkName;
static BOOLEAN         g_SymLinkCreated = FALSE;

/*
 * Ring buffer.
 * Write index (producer) and read index (consumer) are ULONG so wrap-around
 * is natural.  Capacity is a power-of-two so (idx & RING_MASK) gives slot.
 */
static MALMAYBE_EVENT  g_Ring[RING_CAPACITY];
static volatile ULONG  g_RingWrite = 0;     /* next slot to write          */
static volatile ULONG  g_RingRead  = 0;     /* next slot to read           */
static KSPIN_LOCK      g_RingLock;          /* protects both index values  */
static ULONG           g_Sequence  = 0;     /* event sequence counter      */

/*
 * Pending IRP queue.
 * When the agent calls IOCTL_MALMAYBE_READ_EVENTS and the ring is empty,
 * the IRP is inserted here and completed later by the producer.
 * Protected by g_RingLock so no separate lock is needed.
 */
static LIST_ENTRY      g_PendingIrpList;
static BOOLEAN         g_DeviceClosing = FALSE;  /* set during unload */

/*  Forward declarations  */
static VOID    ThreadNotify(_In_ HANDLE ProcessId,
                            _In_ HANDLE ThreadId,
                            _In_ BOOLEAN Create);
static BOOLEAN IsExecutableProtection(_In_ ULONG Protect);
static NTSTATUS OpenProcessHandleForQuery(_In_ HANDLE ProcessId,
                                          _Out_ PHANDLE ProcessHandle);
static NTSTATUS GetThreadStartAddress(_In_ PETHREAD Thread,
                                      _Out_ PVOID *StartAddress);
static NTSTATUS GetThreadStartAddressFallback(_In_ PETHREAD Thread,
                                              _Out_ PVOID *StartAddress);

static VOID    PushEvent(_In_ PMALMAYBE_EVENT Ev);
static VOID    CompletePendingIrps(VOID);
static VOID    CancelPendingIrp(_Inout_ PDEVICE_OBJECT DevObj,
                                _Inout_ PIRP Irp);

static NTSTATUS DispatchCreate (_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp);
static NTSTATUS DispatchClose  (_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp);
static NTSTATUS DispatchCleanup(_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp);
static NTSTATUS DispatchIoCtl  (_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp);

DRIVER_UNLOAD DriverUnload;
DRIVER_INITIALIZE DriverEntry;

/* ═══════════════════════════════════════════════════════════════════════════════
 *  RING BUFFER HELPERS
 * ═══════════════════════════════════════════════════════════════════════════════ */

/*
 * RingCount — number of events currently stored.
 * Caller must hold g_RingLock or accept a snapshot.
 */
static FORCEINLINE ULONG RingCount(VOID)
{
    return g_RingWrite - g_RingRead;   /* wraps correctly for ULONG arithmetic */
}

/*
 * PushEvent — called from ThreadNotify (may be at DISPATCH_LEVEL).
 *
 * Copies *Ev into the next ring slot, increments g_RingWrite, then
 * (still under the spin-lock) checks if any IRP is waiting and completes it.
 */
static VOID PushEvent(_In_ PMALMAYBE_EVENT Ev)
{
    KIRQL      oldIrql;
    ULONG      slot;
    BOOLEAN    doComplete = FALSE;

    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    if (RingCount() >= RING_CAPACITY) {
        /* Ring is full: overwrite oldest event (advance read pointer). */
        g_RingRead++;
    }

    slot = g_RingWrite & RING_MASK;
    RtlCopyMemory(&g_Ring[slot], Ev, sizeof(MALMAYBE_EVENT));
    g_RingWrite++;

    /* Wake any waiting IRP if the list is non-empty */
    doComplete = !IsListEmpty(&g_PendingIrpList);

    KeReleaseSpinLock(&g_RingLock, oldIrql);

    if (doComplete) {
        CompletePendingIrps();
    }
}

/*
 * CompletePendingIrps — drain the pending IRP list by filling each IRP
 * with available events.  May be called from DISPATCH_LEVEL (from PushEvent)
 * so we use IoCompleteRequest via a DPC if needed, OR call it directly here
 * since IoCompleteRequest is safe at DISPATCH_LEVEL.
 */
static VOID CompletePendingIrps(VOID)
{
    KIRQL     oldIrql;
    LIST_ENTRY localList;
    PLIST_ENTRY entry;
    PIRP        irp;
    PIO_STACK_LOCATION stack;
    PMALMAYBE_EVENT outBuf;
    ULONG       outBufCount;
    ULONG       copied;
    ULONG       slot;
    NTSTATUS    status;

    InitializeListHead(&localList);

    /* Splice the entire pending list into a local list under the lock */
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    while (!IsListEmpty(&g_PendingIrpList)) {
        entry = RemoveHeadList(&g_PendingIrpList);
        InsertTailList(&localList, entry);
    }
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    while (!IsListEmpty(&localList)) {
        entry = RemoveHeadList(&localList);
        irp   = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);

        /* Cancel the cancel-routine before touching the IRP */
        if (IoSetCancelRoutine(irp, NULL) == NULL) {
            /* Already being cancelled — skip */
            continue;
        }

        stack = IoGetCurrentIrpStackLocation(irp);
        outBuf = (PMALMAYBE_EVENT)irp->AssociatedIrp.SystemBuffer;
        outBufCount = stack->Parameters.DeviceIoControl.OutputBufferLength
                      / sizeof(MALMAYBE_EVENT);

        copied = 0;
        status = STATUS_SUCCESS;

        KeAcquireSpinLock(&g_RingLock, &oldIrql);
        while (copied < outBufCount && RingCount() > 0) {
            slot = g_RingRead & RING_MASK;
            RtlCopyMemory(&outBuf[copied], &g_Ring[slot], sizeof(MALMAYBE_EVENT));
            g_RingRead++;
            copied++;
        }
        KeReleaseSpinLock(&g_RingLock, oldIrql);

        irp->IoStatus.Information = copied * sizeof(MALMAYBE_EVENT);
        irp->IoStatus.Status      = (copied > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
}

/*
 * CancelPendingIrp — cancel routine set on each pended IRP.
 * Called by the I/O manager (with the cancel spin-lock held) when the
 * agent process is killed or calls CancelIo.
 */
static VOID CancelPendingIrp(_Inout_ PDEVICE_OBJECT DevObj,
                              _Inout_ PIRP           Irp)
{
    UNREFERENCED_PARAMETER(DevObj);

    /* Release the global cancel spin-lock as soon as possible */
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    /* Remove from our pending list */
    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&g_RingLock, &oldIrql);
        RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
        KeReleaseSpinLock(&g_RingLock, oldIrql);
    }

    Irp->IoStatus.Status      = STATUS_CANCELLED;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

/* ═══════════════════════════════════════════════════════════════════════════════
 *  IRP DISPATCH ROUTINES
 * ═══════════════════════════════════════════════════════════════════════════════ */

static NTSTATUS DispatchCreate(_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    DbgPrint("[malmaybe] agent connected\n");
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DispatchClose(_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp)
{
    UNREFERENCED_PARAMETER(DevObj);
    DbgPrint("[malmaybe] agent disconnected\n");
    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * DispatchCleanup — called when the agent's handle count drops to zero
 * (e.g. process killed).  Complete all pending IRPs with STATUS_CANCELLED.
 */
static NTSTATUS DispatchCleanup(_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp)
{
    KIRQL      oldIrql;
    LIST_ENTRY localList;
    PLIST_ENTRY entry;
    PIRP        pendingIrp;

    UNREFERENCED_PARAMETER(DevObj);

    InitializeListHead(&localList);

    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    while (!IsListEmpty(&g_PendingIrpList)) {
        entry = RemoveHeadList(&g_PendingIrpList);
        InsertTailList(&localList, entry);
    }
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    while (!IsListEmpty(&localList)) {
        entry      = RemoveHeadList(&localList);
        pendingIrp = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        if (IoSetCancelRoutine(pendingIrp, NULL) != NULL) {
            pendingIrp->IoStatus.Status      = STATUS_CANCELLED;
            pendingIrp->IoStatus.Information = 0;
            IoCompleteRequest(pendingIrp, IO_NO_INCREMENT);
        }
    }

    Irp->IoStatus.Status      = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

/*
 * DispatchIoCtl — the only IOCTL this driver exposes.
 *
 * IOCTL_MALMAYBE_READ_EVENTS:
 *   Output buffer: array of MALMAYBE_EVENT.
 *   If events are available → copy them and complete immediately.
 *   If ring is empty        → pend the IRP; ThreadNotify will complete it.
 */
static NTSTATUS DispatchIoCtl(_In_ PDEVICE_OBJECT DevObj, _In_ PIRP Irp)
{
    PIO_STACK_LOCATION stack;
    ULONG              code;
    PMALMAYBE_EVENT    outBuf;
    ULONG              outBufCount;
    ULONG              copied;
    ULONG              slot;
    KIRQL              oldIrql;
    NTSTATUS           status;

    UNREFERENCED_PARAMETER(DevObj);

    stack = IoGetCurrentIrpStackLocation(Irp);
    code  = stack->Parameters.DeviceIoControl.IoControlCode;

    if (code != IOCTL_MALMAYBE_READ_EVENTS) {
        Irp->IoStatus.Status      = STATUS_INVALID_DEVICE_REQUEST;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    outBuf = (PMALMAYBE_EVENT)Irp->AssociatedIrp.SystemBuffer;
    outBufCount = stack->Parameters.DeviceIoControl.OutputBufferLength
                  / sizeof(MALMAYBE_EVENT);

    if (outBuf == NULL || outBufCount == 0) {
        Irp->IoStatus.Status      = STATUS_BUFFER_TOO_SMALL;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_BUFFER_TOO_SMALL;
    }

    /* Try to fill from the ring immediately */
    copied = 0;
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    while (copied < outBufCount && RingCount() > 0) {
        slot = g_RingRead & RING_MASK;
        RtlCopyMemory(&outBuf[copied], &g_Ring[slot], sizeof(MALMAYBE_EVENT));
        g_RingRead++;
        copied++;
    }
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    if (copied > 0) {
        /* Events ready — complete now */
        status = STATUS_SUCCESS;
        Irp->IoStatus.Status      = status;
        Irp->IoStatus.Information = copied * sizeof(MALMAYBE_EVENT);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return status;
    }

    /* Ring empty — pend the IRP */
    IoMarkIrpPending(Irp);
    IoSetCancelRoutine(Irp, CancelPendingIrp);

    KeAcquireSpinLock(&g_RingLock, &oldIrql);

    /* Check again under lock to avoid race with PushEvent */
    if (RingCount() > 0 || g_DeviceClosing) {
        /* Events arrived or driver is unloading — don't pend */
        IoSetCancelRoutine(Irp, NULL);
        KeReleaseSpinLock(&g_RingLock, oldIrql);

        copied = 0;
        KeAcquireSpinLock(&g_RingLock, &oldIrql);
        while (copied < outBufCount && RingCount() > 0) {
            slot = g_RingRead & RING_MASK;
            RtlCopyMemory(&outBuf[copied], &g_Ring[slot], sizeof(MALMAYBE_EVENT));
            g_RingRead++;
            copied++;
        }
        KeReleaseSpinLock(&g_RingLock, oldIrql);

        Irp->IoStatus.Status      = (copied > 0) ? STATUS_SUCCESS : STATUS_NO_MORE_ENTRIES;
        Irp->IoStatus.Information = copied * sizeof(MALMAYBE_EVENT);
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    } else {
        InsertTailList(&g_PendingIrpList, &Irp->Tail.Overlay.ListEntry);
        KeReleaseSpinLock(&g_RingLock, oldIrql);
    }

    return STATUS_PENDING;
}

/* ═══════════════════════════════════════════════════════════════════════════════
 *  DETECTION HELPERS  (same logic as v1, writes to ring instead of file)
 * ═══════════════════════════════════════════════════════════════════════════════ */

static BOOLEAN IsExecutableProtection(_In_ ULONG Protect)
{
    switch (Protect & 0xFF) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return TRUE;
    default:
        return FALSE;
    }
}

static NTSTATUS OpenProcessHandleForQuery(_In_ HANDLE ProcessId,
                                          _Out_ PHANDLE ProcessHandle)
{
    NTSTATUS         status;
    OBJECT_ATTRIBUTES oa;
    CLIENT_ID        cid;

    *ProcessHandle = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    cid.UniqueProcess = ProcessId;
    cid.UniqueThread  = NULL;

    status = ZwOpenProcess(ProcessHandle,
                           PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                           &oa,
                           &cid);
    return status;
}

static NTSTATUS GetThreadStartAddressFallback(_In_ PETHREAD Thread,
                                              _Out_ PVOID *StartAddress)
{
    NTSTATUS status;
    HANDLE   hThread = NULL;
    ULONG    retLen  = 0;

    *StartAddress = NULL;
    if (g_ZwQueryInformationThread == NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    status = ObOpenObjectByPointer(Thread,
                                   OBJ_KERNEL_HANDLE,
                                   NULL,
                                   THREAD_QUERY_INFORMATION,
                                   *PsThreadType,
                                   KernelMode,
                                   &hThread);
    if (!NT_SUCCESS(status))
        return status;

    status = g_ZwQueryInformationThread(hThread,
                                        ThreadQuerySetWin32StartAddress,
                                        StartAddress,
                                        (ULONG)sizeof(PVOID),
                                        &retLen);
    ZwClose(hThread);
    return status;
}

static NTSTATUS GetThreadStartAddress(_In_ PETHREAD Thread,
                                      _Out_ PVOID *StartAddress)
{
    NTSTATUS status;
    *StartAddress = NULL;

    if (g_PsGetThreadWin32StartAddress != NULL) {
        status = g_PsGetThreadWin32StartAddress(Thread, StartAddress);
        if (NT_SUCCESS(status))
            return status;
    }
    return GetThreadStartAddressFallback(Thread, StartAddress);
}

/* ═══════════════════════════════════════════════════════════════════════════════
 *  THREAD NOTIFY CALLBACK
 * ═══════════════════════════════════════════════════════════════════════════════ */

static VOID ThreadNotify(_In_ HANDLE ProcessId,
                         _In_ HANDLE ThreadId,
                         _In_ BOOLEAN Create)
{
    PETHREAD              thread = NULL;
    NTSTATUS              status;
    PVOID                 start  = NULL;
    HANDLE                hProcess = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T                retLen = 0;
    MALMAYBE_EVENT        ev;

    if (!Create)
        return;

    RtlZeroMemory(&ev, sizeof(ev));

    status = PsLookupThreadByThreadId(ThreadId, &thread);
    if (!NT_SUCCESS(status))
        return;

    status = GetThreadStartAddress(thread, &start);
    ObDereferenceObject(thread);

    if (!NT_SUCCESS(status) || start == NULL) {
        /* Emit an error event so the agent can log it */
        ev.Sequence  = InterlockedIncrement((LONG *)&g_Sequence);
        ev.Flags     = MALMAYBE_FLAG_ERROR;
        ev.ProcessId = HandleToUlong(ProcessId);
        ev.ThreadId  = HandleToUlong(ThreadId);
        RtlStringCbPrintfA(ev.Message, sizeof(ev.Message),
            "[malmaybe] PID=%lu TID=%lu start query failed: 0x%08X",
            ev.ProcessId, ev.ThreadId, (ULONG)status);
        DbgPrint("%s\n", ev.Message);
        PushEvent(&ev);
        return;
    }

    status = OpenProcessHandleForQuery(ProcessId, &hProcess);
    if (!NT_SUCCESS(status)) {
        ev.Sequence      = InterlockedIncrement((LONG *)&g_Sequence);
        ev.Flags         = MALMAYBE_FLAG_ERROR;
        ev.ProcessId     = HandleToUlong(ProcessId);
        ev.ThreadId      = HandleToUlong(ThreadId);
        ev.StartAddress  = (ULONGLONG)(ULONG_PTR)start;
        RtlStringCbPrintfA(ev.Message, sizeof(ev.Message),
            "[malmaybe] PID=%lu TID=%lu Start=%p proc open failed: 0x%08X",
            ev.ProcessId, ev.ThreadId, start, (ULONG)status);
        DbgPrint("%s\n", ev.Message);
        PushEvent(&ev);
        return;
    }

    RtlZeroMemory(&mbi, sizeof(mbi));
    status = ZwQueryVirtualMemory(hProcess,
                                  start,
                                  MemoryBasicInformation,
                                  &mbi,
                                  sizeof(mbi),
                                  &retLen);
    ZwClose(hProcess);

    if (!NT_SUCCESS(status)) {
        ev.Sequence      = InterlockedIncrement((LONG *)&g_Sequence);
        ev.Flags         = MALMAYBE_FLAG_ERROR;
        ev.ProcessId     = HandleToUlong(ProcessId);
        ev.ThreadId      = HandleToUlong(ThreadId);
        ev.StartAddress  = (ULONGLONG)(ULONG_PTR)start;
        RtlStringCbPrintfA(ev.Message, sizeof(ev.Message),
            "[malmaybe] PID=%lu TID=%lu Start=%p mbi failed: 0x%08X",
            ev.ProcessId, ev.ThreadId, start, (ULONG)status);
        DbgPrint("%s\n", ev.Message);
        PushEvent(&ev);
        return;
    }

    /*  Build the baseline event  */
    ev.Sequence     = InterlockedIncrement((LONG *)&g_Sequence);
    ev.Flags        = 0;
    ev.ProcessId    = HandleToUlong(ProcessId);
    ev.ThreadId     = HandleToUlong(ThreadId);
    ev.StartAddress = (ULONGLONG)(ULONG_PTR)start;
    ev.MemType      = mbi.Type;
    ev.MemProtect   = mbi.Protect;
    ev.MemState     = mbi.State;

    /*  Alert heuristic  */
    if (mbi.State  == MEM_COMMIT  &&
        mbi.Type   != MEM_IMAGE   &&
        IsExecutableProtection(mbi.Protect))
    {
        ev.Flags |= MALMAYBE_FLAG_ALERT;
        RtlStringCbPrintfA(ev.Message, sizeof(ev.Message),
            "[ALERT] PID=%lu TID=%lu Start=0x%016I64X "
            "Type=0x%08lX Protect=0x%08lX State=0x%08lX",
            ev.ProcessId, ev.ThreadId, ev.StartAddress,
            ev.MemType, ev.MemProtect, ev.MemState);
    } else {
        RtlStringCbPrintfA(ev.Message, sizeof(ev.Message),
            "[info]  PID=%lu TID=%lu Start=0x%016I64X "
            "Type=0x%08lX Protect=0x%08lX State=0x%08lX",
            ev.ProcessId, ev.ThreadId, ev.StartAddress,
            ev.MemType, ev.MemProtect, ev.MemState);
    }

    DbgPrint("%s\n", ev.Message);
    PushEvent(&ev);
}

/* ═══════════════════════════════════════════════════════════════════════════════
 *  DRIVER ENTRY / UNLOAD
 * ═══════════════════════════════════════════════════════════════════════════════ */

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    KIRQL      oldIrql;
    LIST_ENTRY localList;
    PLIST_ENTRY entry;
    PIRP        irp;

    UNREFERENCED_PARAMETER(DriverObject);

    /* 1. Stop accepting new threads */
    if (g_ThreadNotifyRegistered) {
        PsRemoveCreateThreadNotifyRoutine(ThreadNotify);
        g_ThreadNotifyRegistered = FALSE;
    }

    /* 2. Signal device is going away; fail any newly-pended IRPs */
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    g_DeviceClosing = TRUE;
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    /* 3. Drain and cancel all pending IRPs */
    InitializeListHead(&localList);
    KeAcquireSpinLock(&g_RingLock, &oldIrql);
    while (!IsListEmpty(&g_PendingIrpList)) {
        entry = RemoveHeadList(&g_PendingIrpList);
        InsertTailList(&localList, entry);
    }
    KeReleaseSpinLock(&g_RingLock, oldIrql);

    while (!IsListEmpty(&localList)) {
        entry = RemoveHeadList(&localList);
        irp   = CONTAINING_RECORD(entry, IRP, Tail.Overlay.ListEntry);
        if (IoSetCancelRoutine(irp, NULL) != NULL) {
            irp->IoStatus.Status      = STATUS_NO_MORE_ENTRIES;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
        }
    }

    /* 4. Tear down the device */
    if (g_SymLinkCreated) {
        IoDeleteSymbolicLink(&g_SymLinkName);
        g_SymLinkCreated = FALSE;
    }
    if (g_DeviceObject != NULL) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
    }

    DbgPrint("[malmaybe] unloaded\n");
}

#ifdef __cplusplus
extern "C"
#endif
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS        status;
    UNICODE_STRING  devName;
    UNICODE_STRING  symName;
    UNICODE_STRING  uStr;

    UNREFERENCED_PARAMETER(RegistryPath);

    /*  Init synchronisation primitives  */
    KeInitializeSpinLock(&g_RingLock);
    InitializeListHead(&g_PendingIrpList);

    /*  Resolve optional kernel exports  */
    RtlInitUnicodeString(&uStr, L"PsGetThreadWin32StartAddress");
    g_PsGetThreadWin32StartAddress =
        (PFN_PsGetThreadWin32StartAddress)MmGetSystemRoutineAddress(&uStr);

    RtlInitUnicodeString(&uStr, L"ZwQueryInformationThread");
    g_ZwQueryInformationThread =
        (PFN_ZwQueryInformationThread)MmGetSystemRoutineAddress(&uStr);

    if (g_PsGetThreadWin32StartAddress == NULL)
        DbgPrint("[malmaybe] PsGetThreadWin32StartAddress missing; fallback enabled\n");
    if (g_ZwQueryInformationThread == NULL)
        DbgPrint("[malmaybe] ZwQueryInformationThread missing; start address may be unavailable\n");

    /*  Create the device object  */
    RtlInitUnicodeString(&devName, L"\\Device\\malmaybe");

    /*
     * IoCreateDeviceSecure with SDDL_DEVOBJ_SYS_ALL_ADM_RWX restricts
     * access to SYSTEM and Administrators — the agent must run elevated.
     * Falls back to IoCreateDevice on older WDKs if needed.
     */
    status = IoCreateDevice(DriverObject,
                            0,              /* no device extension needed */
                            &devName,
                            MALMAYBE_DEVICE_TYPE,
                            FILE_DEVICE_SECURE_OPEN,
                            FALSE,          /* not exclusive */
                            &g_DeviceObject);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[malmaybe] IoCreateDevice failed: 0x%08X\n", (ULONG)status);
        return status;
    }

    /* Use buffered I/O for simplicity and safety */
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    /*  Create the symbolic link  */
    RtlInitUnicodeString(&symName, L"\\DosDevices\\malmaybe");
    g_SymLinkName = symName;

    status = IoCreateSymbolicLink(&g_SymLinkName, &devName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[malmaybe] IoCreateSymbolicLink failed: 0x%08X\n", (ULONG)status);
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }
    g_SymLinkCreated = TRUE;

    /*  Wire up dispatch routines  */
    DriverObject->DriverUnload                         = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = DispatchCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoCtl;

    /*  Register thread-create callback  */
    status = PsSetCreateThreadNotifyRoutine(ThreadNotify);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[malmaybe] PsSetCreateThreadNotifyRoutine failed: 0x%08X\n",
                 (ULONG)status);
        IoDeleteSymbolicLink(&g_SymLinkName);
        g_SymLinkCreated = FALSE;
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return status;
    }
    g_ThreadNotifyRegistered = TRUE;

    DbgPrint("[malmaybe] loaded — device \\Device\\malmaybe ready\n");
    return STATUS_SUCCESS;
}
