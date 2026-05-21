/*
 * malmaybe.exe  —  User-mode agent for the malmaybe kernel driver
 *
 * What it does:
 *   1. Opens \\.\malmaybe  (the device exposed by malmaybe.sys)
 *   2. Loops calling DeviceIoControl(IOCTL_MALMAYBE_READ_EVENTS)
 *      - The call BLOCKS inside the kernel until at least one event
 *        is ready, so the agent consumes zero CPU while idle.
 *   3. For each received MALMAYBE_EVENT:
 *        - Prints a colour-coded, verbose line to the console.
 *        - Appends the same line (plain text) to C:\malmaybe.log
 *   4. Handles Ctrl-C cleanly.
 *
 * Build (Developer Command Prompt for VS, x64):
 *   cl /W4 /WX /O2 /nologo malmaybe_agent.c ^
 *      /link /SUBSYSTEM:CONSOLE kernel32.lib user32.lib
 *
 * Must be run as Administrator (the device ACL requires it).
 *
 * Lab / authorised systems only.
 */

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>

/* ── IOCTL — must match malmaybe.sys exactly ────────────────────────────────── */
#define MALMAYBE_DEVICE_TYPE  0x8000u
#define IOCTL_MALMAYBE_READ_EVENTS \
    CTL_CODE(MALMAYBE_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

/* ── Event structure — must match malmaybe.sys exactly ─────────────────────── */
#pragma pack(push, 1)
typedef struct _MALMAYBE_EVENT {
    ULONG     Sequence;
    ULONG     Flags;
    ULONG     ProcessId;
    ULONG     ThreadId;
    ULONGLONG StartAddress;
    ULONG     MemType;
    ULONG     MemProtect;
    ULONG     MemState;
    ULONG     _pad;
    CHAR      Message[192];
} MALMAYBE_EVENT, *PMALMAYBE_EVENT;
#pragma pack(pop)

/* Flag bits */
#define MALMAYBE_FLAG_ALERT  0x00000001u
#define MALMAYBE_FLAG_ERROR  0x00000002u

/* ── Tuning ──────────────────────────────────────────────────────────────────── */
#define BATCH_SIZE       32u           /* events to request per IOCTL call  */
#define LOG_PATH         "C:\\malmaybe.log"
#define DEVICE_PATH      "\\\\.\\malmaybe"

/* ── Console colours ─────────────────────────────────────────────────────────── */
#define COL_RESET        7             /* white on black (default)          */
#define COL_INFO         11            /* bright cyan    — normal events     */
#define COL_ALERT        12            /* bright red     — alert events      */
#define COL_ERROR        14            /* bright yellow  — error events      */
#define COL_BANNER       13            /* bright magenta — startup banner    */
#define COL_DIM          8             /* dark grey      — timestamps etc.   */

/* ── Globals ─────────────────────────────────────────────────────────────────── */
static HANDLE   g_Device  = INVALID_HANDLE_VALUE;
static FILE    *g_LogFile = NULL;
static HANDLE   g_StdOut;
static volatile LONG g_Running = 1;   /* set to 0 by Ctrl-C handler */

/* ── Helpers ─────────────────────────────────────────────────────────────────── */

static void SetColour(int colour)
{
    SetConsoleTextAttribute(g_StdOut, (WORD)colour);
}

/* Printf to both console (with colour) and log file (plain) */
static void DualPrint(int colour, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    SetColour(colour);
    fputs(buf, stdout);
    SetColour(COL_RESET);

    if (g_LogFile) {
        fputs(buf, g_LogFile);
        fflush(g_LogFile);
    }
}

/* Current timestamp string — "YYYY-MM-DD HH:MM:SS" */
static void Timestamp(char *buf, size_t sz)
{
    time_t     t  = time(NULL);
    struct tm  tm;
    localtime_s(&tm, &t);
    strftime(buf, sz, "%Y-%m-%d %H:%M:%S", &tm);
}

/* Human-readable memory type */
static const char *MemTypeName(ULONG t)
{
    switch (t) {
    case 0x01000000: return "MEM_IMAGE";
    case 0x00040000: return "MEM_MAPPED";
    case 0x00020000: return "MEM_PRIVATE";
    default:         return "MEM_UNKNOWN";
    }
}

/* Human-readable page protection */
static const char *ProtectName(ULONG p)
{
    switch (p & 0xFF) {
    case PAGE_NOACCESS:          return "NOACCESS";
    case PAGE_READONLY:          return "READONLY";
    case PAGE_READWRITE:         return "READWRITE";
    case PAGE_WRITECOPY:         return "WRITECOPY";
    case PAGE_EXECUTE:           return "EXECUTE";
    case PAGE_EXECUTE_READ:      return "EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "EXECUTE_READWRITE";
    case PAGE_EXECUTE_WRITECOPY: return "EXECUTE_WRITECOPY";
    default:                     return "OTHER";
    }
}

/* Human-readable memory state */
static const char *StateName(ULONG s)
{
    switch (s) {
    case MEM_COMMIT:  return "COMMIT";
    case MEM_RESERVE: return "RESERVE";
    case MEM_FREE:    return "FREE";
    default:          return "UNKNOWN";
    }
}

/* ── Ctrl-C handler ──────────────────────────────────────────────────────────── */
static BOOL WINAPI CtrlHandler(DWORD ctrl)
{
    if (ctrl == CTRL_C_EVENT || ctrl == CTRL_BREAK_EVENT ||
        ctrl == CTRL_CLOSE_EVENT) {
        InterlockedExchange(&g_Running, 0);
        /* Close the device handle — this causes the blocked DeviceIoControl
         * to return immediately with an error, unblocking the main loop. */
        if (g_Device != INVALID_HANDLE_VALUE) {
            CloseHandle(g_Device);
            g_Device = INVALID_HANDLE_VALUE;
        }
        return TRUE;
    }
    return FALSE;
}

/* ── Print one event verbosely ───────────────────────────────────────────────── */
static void PrintEvent(const MALMAYBE_EVENT *ev)
{
    char   ts[32];
    int    colour;
    const char *kind;

    Timestamp(ts, sizeof(ts));

    if (ev->Flags & MALMAYBE_FLAG_ALERT) {
        colour = COL_ALERT;
        kind   = "ALERT";
    } else if (ev->Flags & MALMAYBE_FLAG_ERROR) {
        colour = COL_ERROR;
        kind   = "ERROR";
    } else {
        colour = COL_INFO;
        kind   = "info ";
    }

    /* ── Timestamp + kind ── */
    DualPrint(COL_DIM,    "[%s] ", ts);
    DualPrint(colour,     "[%s] ", kind);
    DualPrint(COL_RESET,  "#%-6lu  ", (unsigned long)ev->Sequence);

    /* ── Core fields ── */
    DualPrint(COL_RESET,
              "PID=%-6lu  TID=%-6lu  Start=0x%016I64X\n",
              (unsigned long)ev->ProcessId,
              (unsigned long)ev->ThreadId,
              ev->StartAddress);

    /* ── Memory details (indented) — only for non-error events ── */
    if (!(ev->Flags & MALMAYBE_FLAG_ERROR)) {
        DualPrint(COL_DIM,
                  "                              "
                  "  Type=%-12s  Protect=%-20s  State=%s\n",
                  MemTypeName(ev->MemType),
                  ProtectName(ev->MemProtect),
                  StateName(ev->MemState));
    }

    /* ── Driver message ── */
    DualPrint(COL_DIM, "                                %s\n\n",
              ev->Message);

    /* ── Extra alert banner ── */
    if (ev->Flags & MALMAYBE_FLAG_ALERT) {
        DualPrint(COL_ALERT,
                  "  *** INJECTION DETECTED ***  "
                  "Non-image executable thread start address.\n"
                  "  PID=%lu  TID=%lu  "
                  "Type=%s  Protect=%s\n\n",
                  (unsigned long)ev->ProcessId,
                  (unsigned long)ev->ThreadId,
                  MemTypeName(ev->MemType),
                  ProtectName(ev->MemProtect));
    }

    fflush(stdout);
}

/* ── Banner ──────────────────────────────────────────────────────────────────── */
static void PrintBanner(void)
{
    char ts[32];
    Timestamp(ts, sizeof(ts));

    DualPrint(COL_BANNER,
        "╔══════════════════════════════════════════════════════╗\n"
        "║              malmaybe  —  Agent v2.0                ║\n"
        "║     Kernel-Level Process Injection Detection         ║\n"
        "╚══════════════════════════════════════════════════════╝\n\n");

    DualPrint(COL_RESET,  "  Device  : " DEVICE_PATH "\n");
    DualPrint(COL_RESET,  "  Log     : " LOG_PATH "\n");
    DualPrint(COL_RESET,  "  Started : %s\n", ts);
    DualPrint(COL_DIM,    "  Press Ctrl-C to exit.\n\n");
    DualPrint(COL_DIM,
        "  %-6s  %-8s  %-6s  %-6s  %-18s  %-12s  %-20s  %s\n",
        "Kind", "Seq", "PID", "TID", "StartAddress", "MemType",
        "Protection", "State");
    DualPrint(COL_DIM,
        "  %s\n\n",
        "──────────────────────────────────────────────────────────"
        "───────────────────────────────────────────");
}

/* ── Entry point ─────────────────────────────────────────────────────────────── */
int main(void)
{
    MALMAYBE_EVENT  batch[BATCH_SIZE];
    DWORD           bytesReturned;
    DWORD           count;
    DWORD           i;
    BOOL            ok;
    DWORD           err;

    /* ── Console setup ── */
    g_StdOut = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTitle("malmaybe Agent");

    /* ── Open log file (append) ── */
    if (fopen_s(&g_LogFile, LOG_PATH, "a") != 0) {
        fprintf(stderr,
            "[malmaybe] WARNING: Cannot open log file %s  (err=%lu)\n"
            "           Console output only.\n\n",
            LOG_PATH, GetLastError());
        g_LogFile = NULL;
    }

    /* ── Register Ctrl-C handler ── */
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    PrintBanner();

    /* ── Open the kernel device ── */
    g_Device = CreateFileA(
        DEVICE_PATH,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (g_Device == INVALID_HANDLE_VALUE) {
        err = GetLastError();
        fprintf(stderr,
            "[malmaybe] ERROR: Cannot open %s  (Win32 error %lu)\n"
            "  Is malmaybe.sys loaded and running?\n"
            "  Are you running as Administrator?\n",
            DEVICE_PATH, err);
        if (g_LogFile) fclose(g_LogFile);
        return 1;
    }

    DualPrint(COL_RESET, "[malmaybe] Connected to driver. Waiting for events...\n\n");

    /* ── Main event loop ── */
    while (InterlockedCompareExchange(&g_Running, 1, 1) == 1) {

        RtlSecureZeroMemory(batch, sizeof(batch));

        ok = DeviceIoControl(
            g_Device,
            IOCTL_MALMAYBE_READ_EVENTS,
            NULL, 0,                            /* no input buffer */
            batch, sizeof(batch),               /* output buffer   */
            &bytesReturned,
            NULL);                              /* synchronous (blocking) */

        if (!ok) {
            err = GetLastError();
            if (err == ERROR_OPERATION_ABORTED ||
                err == ERROR_INVALID_HANDLE    ||
                err == ERROR_NO_MORE_ITEMS) {
                /* Device closed or unloaded — clean exit */
                break;
            }
            /* Unexpected error — print and retry */
            DualPrint(COL_ERROR,
                "[malmaybe] DeviceIoControl error %lu — retrying...\n", err);
            Sleep(500);
            continue;
        }

        if (bytesReturned == 0)
            continue;

        count = bytesReturned / (DWORD)sizeof(MALMAYBE_EVENT);
        for (i = 0; i < count; i++) {
            PrintEvent(&batch[i]);
        }
    }

    /* ── Cleanup ── */
    DualPrint(COL_BANNER, "\n[malmaybe] Agent shutting down.\n");
    if (g_Device != INVALID_HANDLE_VALUE) {
        CloseHandle(g_Device);
        g_Device = INVALID_HANDLE_VALUE;
    }
    if (g_LogFile) {
        fclose(g_LogFile);
        g_LogFile = NULL;
    }
    return 0;
}
