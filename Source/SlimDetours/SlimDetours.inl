#pragma once

#include <Wintexports/Wintexports.h>

#include <limits.h>

#ifdef __cplusplus
#include <new>
#endif

#include "SlimDetours.h"

#if _DEBUG
#define DETOUR_TRACE DbgPrint
#define DETOUR_BREAK() __debugbreak()
#else
#define DETOUR_TRACE(Format, ...)
#define DETOUR_BREAK()
#endif

#define _512KB KB_TO_BYTES((ULONG_PTR)512)
#define _1GB GB_TO_BYTES((ULONG_PTR)1)
#define _2GB GB_TO_BYTES((ULONG_PTR)2)

EXTERN_C_START

VOID detour_init();

/* Basic structures */

typedef struct _DETOUR_ALIGN
{
    BYTE obTarget : 3;
    BYTE obTrampoline : 5;
} DETOUR_ALIGN, *PDETOUR_ALIGN;

_STATIC_ASSERT(sizeof(DETOUR_ALIGN) == 1);

typedef struct _DETOUR_TRAMPOLINE
{
    // An X64 instuction can be 15 bytes long.
    // In practice 11 seems to be the limit.
    // 
    // An ARM64 instruction is 4 bytes long.
    //
    // The overwrite is always composed of 3 instructions (12 bytes) which perform an indirect jump
    // using _DETOUR_TRAMPOLINE::pbDetour as the address holding the target location.
    //
    // Copied instructions can expand.
    //
    // The scheme using MovImmediate can cause an instruction
    // to grow as much as 6 times.
    // That would be Bcc or Tbz with a large address space:
    //   4 instructions to form immediate
    //   inverted tbz/bcc
    //   br
    //
    // An expansion of 4 is not uncommon -- bl/blr and small address space:
    //   3 instructions to form immediate
    //   br or brl
    //
    // A theoretical maximum for rbCode is thefore 4*4*6 + 16 = 112 (another 16 for jmp to pbRemain).
    //
    // With literals, the maximum expansion is 5, including the literals: 4*4*5 + 16 = 96.
    //
    // The number is rounded up to 128. m_rbScratchDst should match this.
    //
#if defined(_M_IX86) || defined(_M_X64)
    BYTE            rbCode[30];         // target code + jmp to pbRemain.
#elif defined(_M_ARM64)
    BYTE            rbCode[128];        // target code + jmp to pbRemain.
#endif
    BYTE            cbCode;             // size of moved target code.
#if defined(_M_IX86) || defined(_M_X64)
    BYTE            cbCodeBreak;        // padding to make debugging easier.
#elif defined(_M_ARM64)
    BYTE            cbCodeBreak[3];     // padding to make debugging easier.
#endif
#if defined(_M_IX86)
    BYTE            rbRestore[22];      // original target code.
#elif defined(_M_X64)
    BYTE            rbRestore[30];      // original target code.
#elif defined(_M_ARM64)
    BYTE            rbRestore[24];      // original target code.
#endif
    BYTE            cbRestore;          // size of original target code.
#if defined(_M_IX86) || defined(_M_X64)
    BYTE            cbRestoreBreak;     // padding to make debugging easier.
#elif defined(_M_ARM64)
    BYTE            cbRestoreBreak[3];  // padding to make debugging easier.
#endif
    DETOUR_ALIGN    rAlign[8];          // instruction alignment array.
    PBYTE           pbRemain;           // first instruction after moved code. [free list]
    PBYTE           pbDetour;           // first instruction of detour function.
#if defined(_M_X64)
    BYTE            rbCodeIn[8];        // jmp [pbDetour]
#endif
} DETOUR_TRAMPOLINE, *PDETOUR_TRAMPOLINE;

#if defined(_M_IX86)
_STATIC_ASSERT(sizeof(DETOUR_TRAMPOLINE) == 72);
#elif defined(_M_X64)
_STATIC_ASSERT(sizeof(DETOUR_TRAMPOLINE) == 96);
#elif defined(_M_ARM64)
_STATIC_ASSERT(sizeof(DETOUR_TRAMPOLINE) == 184);
#endif

typedef struct _DETOUR_OPERATION DETOUR_OPERATION, *PDETOUR_OPERATION;

struct _DETOUR_OPERATION
{
    PDETOUR_OPERATION pNext;
    BOOL fIsRemove;
    PBYTE* ppbPointer;
    PBYTE pbTarget;
    PDETOUR_TRAMPOLINE pTrampoline;
    ULONG dwPerm;
};

/* Memory management */

VOID detour_memory_init();

BOOL detour_memory_is_system_reserved(_In_ PVOID Address);

_Ret_notnull_
PVOID detour_memory_2gb_below(_In_ PVOID Address);

_Ret_notnull_
PVOID detour_memory_2gb_above(_In_ PVOID Address);

/* Instruction Utility */

enum
{
#if defined(_M_IX86) || defined(_M_X64)
    SIZE_OF_JMP = 5
#elif defined(_M_ARM64)
    SIZE_OF_JMP = 12
#endif
};

#if defined(_M_IX86) || defined(_M_X64)

_Ret_notnull_
PBYTE detour_gen_jmp_immediate(_In_ PBYTE pbCode, _In_ PBYTE pbJmpVal);

_Ret_notnull_
PBYTE detour_gen_jmp_indirect(_In_ PBYTE pbCode, _In_ PBYTE* ppbJmpVal);

#elif defined(_M_ARM64)

_Ret_notnull_
PBYTE detour_gen_jmp_immediate(_In_ PBYTE pbCode, _In_opt_ PBYTE* ppPool, _In_ PBYTE pbJmpVal);

_Ret_notnull_
PBYTE detour_gen_jmp_indirect(_In_ PBYTE pbCode, _In_ PULONG64 pbJmpVal);

#endif

_Ret_notnull_
PBYTE detour_gen_brk(_In_ PBYTE pbCode, _In_ PBYTE pbLimit);

_Ret_notnull_
PBYTE detour_skip_jmp(_In_ PBYTE pbCode);

VOID detour_find_jmp_bounds(_In_ PBYTE pbCode, _Outptr_ PVOID* ppLower, _Outptr_ PVOID* ppUpper);

BOOL detour_does_code_end_function(_In_ PBYTE pbCode);

ULONG detour_is_code_filler(_In_ PBYTE pbCode);

/* Thread management */

NTSTATUS detour_thread_suspend(
    _Outptr_result_maybenull_ PHANDLE* SuspendedHandles,
    _Out_ PULONG SuspendedHandleCount);

VOID detour_thread_resume(
    _In_reads_(SuspendedHandleCount) _Frees_ptr_ PHANDLE SuspendedHandles,
    _In_ ULONG SuspendedHandleCount);

NTSTATUS detour_thread_update(_In_ HANDLE ThreadHandle, _In_ PDETOUR_OPERATION PendingOperations);

/* Trampoline management */

NTSTATUS detour_writable_trampoline_regions();

VOID detour_runnable_trampoline_regions();

_Ret_maybenull_
PDETOUR_TRAMPOLINE detour_alloc_trampoline(_In_ PBYTE pbTarget);

VOID detour_free_trampoline(_In_ PDETOUR_TRAMPOLINE pTrampoline);

VOID detour_free_unused_trampoline_regions();

BYTE detour_align_from_trampoline(_In_ PDETOUR_TRAMPOLINE pTrampoline, BYTE obTrampoline);

BYTE detour_align_from_target(_In_ PDETOUR_TRAMPOLINE pTrampoline, BYTE obTarget);

EXTERN_C_END
