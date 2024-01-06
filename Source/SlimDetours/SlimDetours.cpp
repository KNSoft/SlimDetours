/*
 * KNSoft SlimDetours (https://github.com/KNSoft/SlimDetours) Core Functionality
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MPL-2.0 license.
 *
 * Source base on Microsoft Detours:
 *
 * Microsoft Research Detours Package, Version 4.0.1
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT license.
 */

#include "SlimDetours.inl"
#include "SlimDetours.h"

static RTL_RUN_ONCE g_InitOnce = RTL_RUN_ONCE_INIT;

static VOID detour_init()
{
    if (RtlRunOnceBeginInitialize(&g_InitOnce, 0, NULL) == STATUS_PENDING)
    {
        detour_memory_init();
        RtlRunOnceComplete(&g_InitOnce, 0, NULL);
    }
}

//////////////////////////////////////////////// Trampoline Memory Management.
//
struct DETOUR_REGION
{
    ULONG dwSignature;
    DETOUR_REGION* pNext;       // Next region in list of regions.
    DETOUR_TRAMPOLINE* pFree;   // List of free trampolines in this region.
};
typedef DETOUR_REGION* PDETOUR_REGION;

const ULONG DETOUR_REGION_SIGNATURE = 'Rrtd';
const ULONG DETOUR_REGION_SIZE = 0x10000;
const ULONG DETOUR_TRAMPOLINES_PER_REGION = (DETOUR_REGION_SIZE / sizeof(DETOUR_TRAMPOLINE)) - 1;
static PDETOUR_REGION s_pRegions = NULL; // List of all regions.
static PDETOUR_REGION s_pRegion = NULL; // Default region.

static NTSTATUS detour_writable_trampoline_regions()
{
    NTSTATUS Status;
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    // Mark all of the regions as writable.
    sMem = DETOUR_REGION_SIZE;
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext)
    {
        pMem = pRegion;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, PAGE_EXECUTE_READWRITE, &dwOld);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }
    return STATUS_SUCCESS;
}

static void detour_runnable_trampoline_regions()
{
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    // Mark all of the regions as executable.
    sMem = DETOUR_REGION_SIZE;
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext)
    {
        pMem = pRegion;
        NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, PAGE_EXECUTE_READ, &dwOld);
        NtFlushInstructionCache(NtCurrentProcess(), pRegion, DETOUR_REGION_SIZE);
    }
}

static PBYTE detour_alloc_round_down_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0)
    {
        pbTry -= extra;
    }
    return pbTry;
}

static PBYTE detour_alloc_round_up_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0)
    {
        ULONG_PTR adjust = DETOUR_REGION_SIZE - extra;
        pbTry += adjust;
    }
    return pbTry;
}

// Starting at pbLo, try to allocate a memory region, continue until pbHi.

static PVOID detour_alloc_region_from_lo(PBYTE pbLo, PBYTE pbHi)
{
    NTSTATUS Status;
    PVOID pMem;
    SIZE_T sMem;
    MEMORY_BASIC_INFORMATION mbi;

    PBYTE pbTry = detour_alloc_round_up_to_region(pbLo);

    DETOUR_TRACE(" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry);

    while (pbTry < pbHi)
    {
        if (detour_memory_is_system_reserved(pbTry))
        {
            // Skip region reserved for system DLLs, but preserve address space entropy.
            pbTry += 0x08000000;
            continue;
        }

        if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),
                                             pbTry,
                                             MemoryBasicInformation,
                                             &mbi,
                                             sizeof(mbi),
                                             NULL)))
        {
            break;
        }

        DETOUR_TRACE("  Try %p => %p..%p %6lx\n",
                     pbTry,
                     mbi.BaseAddress,
                     Add2Ptr(mbi.BaseAddress, mbi.RegionSize - 1),
                     mbi.State);

        if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE)
        {
            pMem = pbTry;
            sMem = DETOUR_REGION_SIZE;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                             &pMem,
                                             0,
                                             &sMem,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
            if (NT_SUCCESS(Status))
            {
                return pMem;
            } else if (Status == STATUS_DYNAMIC_CODE_BLOCKED)
            {
                return NULL;
            }
            pbTry += DETOUR_REGION_SIZE;
        } else
        {
            pbTry = detour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
        }
    }
    return NULL;
}

// Starting at pbHi, try to allocate a memory region, continue until pbLo.

static PVOID detour_alloc_region_from_hi(PBYTE pbLo, PBYTE pbHi)
{
    NTSTATUS Status;
    PVOID pMem;
    SIZE_T sMem;
    MEMORY_BASIC_INFORMATION mbi;

    PBYTE pbTry = detour_alloc_round_down_to_region(pbHi - DETOUR_REGION_SIZE);

    DETOUR_TRACE(" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry);

    while (pbTry > pbLo)
    {
        DETOUR_TRACE("  Try %p\n", pbTry);
        if (detour_memory_is_system_reserved(pbTry))
        {
            // Skip region reserved for system DLLs, but preserve address space entropy.
            pbTry -= 0x08000000;
            continue;
        }

        if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),
                                             pbTry,
                                             MemoryBasicInformation,
                                             &mbi,
                                             sizeof(mbi),
                                             NULL)))
        {
            break;
        }

        DETOUR_TRACE("  Try %p => %p..%p %6lx\n",
                     pbTry,
                     mbi.BaseAddress,
                     Add2Ptr(mbi.BaseAddress, mbi.RegionSize - 1),
                     mbi.State);

        if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE)
        {
            pMem = pbTry;
            sMem = DETOUR_REGION_SIZE;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                             &pMem,
                                             0,
                                             &sMem,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
            if (NT_SUCCESS(Status))
            {
                return pMem;
            } else if (Status == STATUS_DYNAMIC_CODE_BLOCKED)
            {
                return NULL;
            }
            pbTry -= DETOUR_REGION_SIZE;
        } else
        {
            pbTry = detour_alloc_round_down_to_region((PBYTE)mbi.AllocationBase - DETOUR_REGION_SIZE);
        }
    }
    return NULL;
}

static PVOID detour_alloc_trampoline_allocate_new(PBYTE pbTarget, PVOID pLo, PVOID pHi)
{
    PVOID pbTry = NULL;

    // NB: We must always also start the search at an offset from pbTarget
    //     in order to maintain ASLR entropy.

#if defined(_WIN64)
    // Try looking 1GB below or lower.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000)
    {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget - 0x40000000);
    }
    // Try looking 1GB above or higher.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget + 0x40000000, (PBYTE)pHi);
    }
    // Try looking 1GB below or higher.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget);
    }
    // Try looking 1GB above or lower.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000)
    {
        pbTry = detour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000);
    }
#endif

    // Try anything below.
    if (pbTry == NULL)
    {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget);
    }
    // try anything above.
    if (pbTry == NULL)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget, (PBYTE)pHi);
    }

    return pbTry;
}

static PDETOUR_TRAMPOLINE detour_alloc_trampoline(PBYTE pbTarget)
{
    // We have to place trampolines within +/- 2GB of target.

    PVOID pLo;
    PVOID pHi;

    detour_find_jmp_bounds(pbTarget, &pLo, &pHi);

    PDETOUR_TRAMPOLINE pTrampoline = NULL;

    // Insure that there is a default region.
    if (s_pRegion == NULL && s_pRegions != NULL)
    {
        s_pRegion = s_pRegions;
    }

    // First check the default region for an valid free block.
    if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
        s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi)
    {

found_region:
        pTrampoline = s_pRegion->pFree;
        // do a last sanity check on region.
        if (pTrampoline < pLo || pTrampoline > pHi)
        {
            return NULL;
        }
        s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pTrampoline->pbRemain;
        RtlFillMemory(pTrampoline, sizeof(*pTrampoline), 0xcc);
        return pTrampoline;
    }

    // Then check the existing regions for a valid free block.
    for (s_pRegion = s_pRegions; s_pRegion != NULL; s_pRegion = s_pRegion->pNext)
    {
        if (s_pRegion != NULL && s_pRegion->pFree != NULL && s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi)
        {
            goto found_region;
        }
    }

    // We need to allocate a new region.

    // Round pbTarget down to 64KB block.
    // /RTCc RuntimeChecks breaks PtrToUlong.
    pbTarget = pbTarget - (ULONG)((ULONG_PTR)pbTarget & 0xffff);

    PVOID pbNewlyAllocated = detour_alloc_trampoline_allocate_new(pbTarget, pLo, pHi);
    if (pbNewlyAllocated != NULL)
    {
        s_pRegion = (DETOUR_REGION*)pbNewlyAllocated;
        s_pRegion->dwSignature = DETOUR_REGION_SIGNATURE;
        s_pRegion->pFree = NULL;
        s_pRegion->pNext = s_pRegions;
        s_pRegions = s_pRegion;
        DETOUR_TRACE("  Allocated region %p..%p\n\n", s_pRegion, Add2Ptr(s_pRegion, DETOUR_REGION_SIZE - 1));

        // Put everything but the first trampoline on the free list.
        PBYTE pFree = NULL;
        pTrampoline = ((PDETOUR_TRAMPOLINE)s_pRegion) + 1;
        for (int i = DETOUR_TRAMPOLINES_PER_REGION - 1; i > 1; i--)
        {
            pTrampoline[i].pbRemain = pFree;
            pFree = (PBYTE)&pTrampoline[i];
        }
        s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pFree;
        goto found_region;
    }

    DETOUR_TRACE("Couldn't find available memory region!\n");
    return NULL;
}

static void detour_free_trampoline(PDETOUR_TRAMPOLINE pTrampoline)
{
    PDETOUR_REGION pRegion = (PDETOUR_REGION)((ULONG_PTR)pTrampoline & ~(ULONG_PTR)0xffff);

    RtlZeroMemory(pTrampoline, sizeof(*pTrampoline));
    pTrampoline->pbRemain = (PBYTE)pRegion->pFree;
    pRegion->pFree = pTrampoline;
}

static BOOL detour_is_region_empty(PDETOUR_REGION pRegion)
{
    // Stop if the region isn't a region (this would be bad).
    if (pRegion->dwSignature != DETOUR_REGION_SIGNATURE)
    {
        return FALSE;
    }

    PBYTE pbRegionBeg = (PBYTE)pRegion;
    PBYTE pbRegionLim = pbRegionBeg + DETOUR_REGION_SIZE;

    // Stop if any of the trampolines aren't free.
    PDETOUR_TRAMPOLINE pTrampoline = ((PDETOUR_TRAMPOLINE)pRegion) + 1;
    for (int i = 0; i < DETOUR_TRAMPOLINES_PER_REGION; i++)
    {
        if (pTrampoline[i].pbRemain != NULL &&
            (pTrampoline[i].pbRemain < pbRegionBeg ||
             pTrampoline[i].pbRemain >= pbRegionLim))
        {
            return FALSE;
        }
    }

    // OK, the region is empty.
    return TRUE;
}

static void detour_free_unused_trampoline_regions()
{
    PVOID pMem;
    SIZE_T sMem;

    PDETOUR_REGION* ppRegionBase = &s_pRegions;
    PDETOUR_REGION pRegion = s_pRegions;

    while (pRegion != NULL)
    {
        if (detour_is_region_empty(pRegion))
        {
            *ppRegionBase = pRegion->pNext;

            pMem = pRegion;
            sMem = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &pMem, &sMem, MEM_RELEASE);
            s_pRegion = NULL;
        } else
        {
            ppRegionBase = &pRegion->pNext;
        }
        pRegion = *ppRegionBase;
    }
}

///////////////////////////////////////////////////////// Transaction Structs.
//
struct DetourThread
{
    DetourThread* pNext;
    HANDLE hThread;
};

struct DetourOperation
{
    DetourOperation* pNext;
    BOOL fIsRemove;
    PBYTE* ppbPointer;
    PBYTE pbTarget;
    PDETOUR_TRAMPOLINE pTrampoline;
    ULONG dwPerm;
};

static ULONG s_nPendingThreadId = 0; // Thread owning pending transaction.
static DetourThread* s_pPendingThreads = NULL;
static DetourOperation* s_pPendingOperations = NULL;

//////////////////////////////////////////////////////////////////////////////
//
PVOID NTAPI SlimDetoursCodeFromPointer(_In_ PVOID pPointer)
{
    return detour_skip_jmp((PBYTE)pPointer);
}

//////////////////////////////////////////////////////////// Transaction APIs.
//
NTSTATUS NTAPI SlimDetoursTransactionBegin()
{
    NTSTATUS Status;

    // Make sure only one thread can start a transaction.
    if (_InterlockedCompareExchange(&s_nPendingThreadId, CURRENT_THREAD_ID, 0) != 0)
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    detour_init();

    // Make sure the trampoline pages are writable.
    Status = detour_writable_trampoline_regions();
    if (!NT_SUCCESS(Status))
    {
        goto fail;
    }

    s_pPendingOperations = NULL;
    s_pPendingThreads = NULL;
    return STATUS_SUCCESS;

fail:
#pragma warning(disable: __WARNING_INTERLOCKED_ACCESS)
    s_nPendingThreadId = 0;
#pragma warning(default: __WARNING_INTERLOCKED_ACCESS)
    return Status;
}

NTSTATUS NTAPI SlimDetoursTransactionAbort()
{
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    if (s_nPendingThreadId != CURRENT_THREAD_ID)
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    // Restore all of the page permissions.
    for (DetourOperation* o = s_pPendingOperations; o != NULL;)
    {
        // We don't care if this fails, because the code is still accessible.
        pMem = o->pbTarget;
        sMem = o->pTrampoline->cbRestore;
        NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, o->dwPerm, &dwOld);
        if (!o->fIsRemove)
        {
            if (o->pTrampoline)
            {
                detour_free_trampoline(o->pTrampoline);
                o->pTrampoline = NULL;
            }
        }

        DetourOperation* n = o->pNext;
        delete o;
        o = n;
    }
    s_pPendingOperations = NULL;

    // Make sure the trampoline pages are no longer writable.
    detour_runnable_trampoline_regions();

    // Resume any suspended threads.
    for (DetourThread* t = s_pPendingThreads; t != NULL;)
    {
        // There is nothing we can do if this fails.
        NtResumeThread(t->hThread, NULL);

        DetourThread* n = t->pNext;
        delete t;
        t = n;
    }
    s_pPendingThreads = NULL;
    s_nPendingThreadId = 0;

    return STATUS_SUCCESS;
}

static BYTE detour_align_from_trampoline(PDETOUR_TRAMPOLINE pTrampoline, BYTE obTrampoline)
{
    for (LONG n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++)
    {
        if (pTrampoline->rAlign[n].obTrampoline == obTrampoline)
        {
            return pTrampoline->rAlign[n].obTarget;
        }
    }
    return 0;
}

static LONG detour_align_from_target(PDETOUR_TRAMPOLINE pTrampoline, LONG obTarget)
{
    for (LONG n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++)
    {
        if (pTrampoline->rAlign[n].obTarget == obTarget)
        {
            return pTrampoline->rAlign[n].obTrampoline;
        }
    }
    return 0;
}

NTSTATUS NTAPI SlimDetoursTransactionCommit()
{
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    // Common variables.
    DetourOperation* o;
    DetourThread* t;
    BOOL freed = FALSE;

    if (s_nPendingThreadId != CURRENT_THREAD_ID)
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    // Insert or remove each of the detours.
    for (o = s_pPendingOperations; o != NULL; o = o->pNext)
    {
        if (o->fIsRemove)
        {
            RtlCopyMemory(o->pbTarget, o->pTrampoline->rbRestore, o->pTrampoline->cbRestore);
            *o->ppbPointer = o->pbTarget;
        } else
        {
            DETOUR_TRACE("detours: pbTramp =%p, pbRemain=%p, pbDetour=%p, cbRestore=%u\n",
                         o->pTrampoline,
                         o->pTrampoline->pbRemain,
                         o->pTrampoline->pbDetour,
                         o->pTrampoline->cbRestore);

            DETOUR_TRACE("detours: pbTarget=%p: "
                         "%02x %02x %02x %02x "
                         "%02x %02x %02x %02x "
                         "%02x %02x %02x %02x [before]\n",
                         o->pbTarget,
                         o->pbTarget[0], o->pbTarget[1], o->pbTarget[2], o->pbTarget[3],
                         o->pbTarget[4], o->pbTarget[5], o->pbTarget[6], o->pbTarget[7],
                         o->pbTarget[8], o->pbTarget[9], o->pbTarget[10], o->pbTarget[11]);

#if defined(_M_X64)
            detour_gen_jmp_indirect(o->pTrampoline->rbCodeIn, &o->pTrampoline->pbDetour);
            PBYTE pbCode = detour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->rbCodeIn);
#elif defined(_M_IX86)
            PBYTE pbCode = detour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->pbDetour);
#elif defined(_M_ARM64)
            PBYTE pbCode = detour_gen_jmp_indirect(o->pbTarget, (ULONG64*)&(o->pTrampoline->pbDetour));
#endif
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);

            DETOUR_TRACE("detours: pbTarget=%p: "
                         "%02x %02x %02x %02x "
                         "%02x %02x %02x %02x "
                         "%02x %02x %02x %02x [after]\n",
                         o->pbTarget,
                         o->pbTarget[0], o->pbTarget[1], o->pbTarget[2], o->pbTarget[3],
                         o->pbTarget[4], o->pbTarget[5], o->pbTarget[6], o->pbTarget[7],
                         o->pbTarget[8], o->pbTarget[9], o->pbTarget[10], o->pbTarget[11]);

            DETOUR_TRACE("detours: pbTramp =%p: "
                         "%02x %02x %02x %02x "
                         "%02x %02x %02x %02x "
                         "%02x %02x %02x %02x\n",
                         o->pTrampoline,
                         o->pTrampoline->rbCode[0], o->pTrampoline->rbCode[1],
                         o->pTrampoline->rbCode[2], o->pTrampoline->rbCode[3],
                         o->pTrampoline->rbCode[4], o->pTrampoline->rbCode[5],
                         o->pTrampoline->rbCode[6], o->pTrampoline->rbCode[7],
                         o->pTrampoline->rbCode[8], o->pTrampoline->rbCode[9],
                         o->pTrampoline->rbCode[10], o->pTrampoline->rbCode[11]);
        }
    }

    // Update any suspended threads.
    for (t = s_pPendingThreads; t != NULL; t = t->pNext)
    {
        CONTEXT cxt;
        cxt.ContextFlags = CONTEXT_CONTROL;

#undef DETOURS_EIP

#if defined(_M_IX86)
#define DETOURS_EIP Eip
#elif defined(_M_X64)
#define DETOURS_EIP Rip
#elif defined(_M_ARM64)
#define DETOURS_EIP Pc
#endif

        if (NT_SUCCESS(NtGetContextThread(t->hThread, &cxt)))
        {
            for (o = s_pPendingOperations; o != NULL; o = o->pNext)
            {
                if (o->fIsRemove)
                {
                    if (cxt.DETOURS_EIP >= (ULONG_PTR)o->pTrampoline &&
                        cxt.DETOURS_EIP < ((ULONG_PTR)o->pTrampoline + sizeof(o->pTrampoline)))
                    {

                        cxt.DETOURS_EIP = (ULONG_PTR)o->pbTarget +
                            detour_align_from_trampoline(o->pTrampoline,
                                                         (BYTE)(cxt.DETOURS_EIP - (ULONG_PTR)o->pTrampoline));

                        NtSetContextThread(t->hThread, &cxt);
                    }
                } else
                {
                    if (cxt.DETOURS_EIP >= (ULONG_PTR)o->pbTarget &&
                        cxt.DETOURS_EIP < ((ULONG_PTR)o->pbTarget + o->pTrampoline->cbRestore))
                    {

                        cxt.DETOURS_EIP = (ULONG_PTR)o->pTrampoline +
                            detour_align_from_target(o->pTrampoline, (BYTE)(cxt.DETOURS_EIP - (ULONG_PTR)o->pbTarget));

                        NtSetContextThread(t->hThread, &cxt);
                    }
                }
            }
        }
#undef DETOURS_EIP
    }

    // Restore all of the page permissions and flush the icache.
    for (o = s_pPendingOperations; o != NULL;)
    {
        // We don't care if this fails, because the code is still accessible.
        pMem = o->pbTarget;
        sMem = o->pTrampoline->cbRestore;
        NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, o->dwPerm, &dwOld);
        NtFlushInstructionCache(NtCurrentProcess(), o->pbTarget, o->pTrampoline->cbRestore);

        if (o->fIsRemove && o->pTrampoline)
        {
            detour_free_trampoline(o->pTrampoline);
            o->pTrampoline = NULL;
            freed = true;
        }

        DetourOperation* n = o->pNext;
        delete o;
        o = n;
    }
    s_pPendingOperations = NULL;

    // Free any trampoline regions that are now unused.
    if (freed)
    {
        detour_free_unused_trampoline_regions();
    }

    // Make sure the trampoline pages are no longer writable.
    detour_runnable_trampoline_regions();

    // Resume any suspended threads.
    for (t = s_pPendingThreads; t != NULL;)
    {
        // There is nothing we can do if this fails.
        NtResumeThread(t->hThread, NULL);

        DetourThread* n = t->pNext;
        delete t;
        t = n;
    }
    s_pPendingThreads = NULL;
    s_nPendingThreadId = 0;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SlimDetoursUpdateThread(_In_ HANDLE hThread)
{
    NTSTATUS Status;

    // Silently (and safely) drop any attempt to suspend our own thread.
    if (hThread == NtCurrentThread())
    {
        return STATUS_SUCCESS;
    }

    DetourThread* t = new(std::nothrow) DetourThread;
    if (t == NULL)
    {
        Status = STATUS_NO_MEMORY;
fail:
        if (t != NULL)
        {
            delete t;
            t = NULL;
        }
        DETOUR_BREAK();
        return Status;
    }

    Status = NtSuspendThread(hThread, NULL);
    if (!NT_SUCCESS(Status))
    {
        DETOUR_BREAK();
        goto fail;
    }

    t->hThread = hThread;
    t->pNext = s_pPendingThreads;
    s_pPendingThreads = t;

    return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////// Transacted APIs.
//
NTSTATUS NTAPI SlimDetoursAttach(_Inout_ PVOID* ppPointer, _In_ PVOID pDetour)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    if (s_nPendingThreadId != CURRENT_THREAD_ID)
    {
        DETOUR_TRACE("transaction conflict with thread id=%lu\n", s_nPendingThreadId);
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    PBYTE pbTarget = (PBYTE)*ppPointer;
    PDETOUR_TRAMPOLINE pTrampoline = NULL;
    DetourOperation* o = NULL;

    pbTarget = (PBYTE)detour_skip_jmp(pbTarget);
    pDetour = detour_skip_jmp((PBYTE)pDetour);

    // Don't follow a jump if its destination is the target function.
    // This happens when the detour does nothing other than call the target.
    if (pDetour == (PVOID)pbTarget)
    {
        DETOUR_BREAK();
        goto fail;
    }

    o = new(std::nothrow) DetourOperation;
    if (o == NULL)
    {
        Status = STATUS_NO_MEMORY;
fail:
        DETOUR_BREAK();
        if (pTrampoline != NULL)
        {
            detour_free_trampoline(pTrampoline);
            pTrampoline = NULL;
        }
        if (o != NULL)
        {
            delete o;
            o = NULL;
        }
        SlimDetoursTransactionAbort();
        return Status;
    }

    pTrampoline = detour_alloc_trampoline(pbTarget);
    if (pTrampoline == NULL)
    {
        Status = STATUS_NO_MEMORY;
        DETOUR_BREAK();
        goto fail;
    }

    DETOUR_TRACE("detours: pbTramp=%p, pDetour=%p\n", pTrampoline, pDetour);

    RtlZeroMemory(pTrampoline->rAlign, sizeof(pTrampoline->rAlign));

    // Determine the number of movable target instructions.
    PBYTE pbSrc = pbTarget;
    PBYTE pbTrampoline = pTrampoline->rbCode;
    PBYTE pbPool = pbTrampoline + sizeof(pTrampoline->rbCode);
    ULONG cbTarget = 0;
    ULONG cbJump = SIZE_OF_JMP;
    ULONG nAlign = 0;

    while (cbTarget < cbJump)
    {
        PBYTE pbOp = pbSrc;
        LONG lExtra = 0;

        DETOUR_TRACE(" SlimDetoursCopyInstruction(%p,%p)\n", pbTrampoline, pbSrc);
        pbSrc = (PBYTE)SlimDetoursCopyInstruction(pbTrampoline, (PVOID*)&pbPool, pbSrc, NULL, &lExtra);
        DETOUR_TRACE(" SlimDetoursCopyInstruction() = %p (%d bytes)\n", pbSrc, (int)(pbSrc - pbOp));
        pbTrampoline += (pbSrc - pbOp) + lExtra;
        cbTarget = PtrOffset(pbTarget, pbSrc);
        pTrampoline->rAlign[nAlign].obTarget = cbTarget;
        pTrampoline->rAlign[nAlign].obTrampoline = pbTrampoline - pTrampoline->rbCode;
        nAlign++;

        if (nAlign >= ARRAYSIZE(pTrampoline->rAlign))
        {
            break;
        }

        if (detour_does_code_end_function(pbOp))
        {
            break;
        }
    }

    // Consume, but don't duplicate padding if it is needed and available.
    while (cbTarget < cbJump)
    {
        LONG cFiller = detour_is_code_filler(pbSrc);
        if (cFiller == 0)
        {
            break;
        }

        pbSrc += cFiller;
        cbTarget = PtrOffset(pbTarget, pbSrc);
    }

#if _DEBUG
    {
        DETOUR_TRACE(" detours: rAlign [");
        LONG n = 0;
        for (n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++)
        {
            if (pTrampoline->rAlign[n].obTarget == 0 && pTrampoline->rAlign[n].obTrampoline == 0)
            {
                break;
            }
            DETOUR_TRACE(" %u/%u", pTrampoline->rAlign[n].obTarget, pTrampoline->rAlign[n].obTrampoline);

        }
        DETOUR_TRACE(" ]\n");
    }
#endif

    if (cbTarget < cbJump || nAlign > ARRAYSIZE(pTrampoline->rAlign))
    {
        // Too few instructions.
        Status = STATUS_INVALID_BLOCK_LENGTH;
        DETOUR_BREAK();
        goto fail;
    }

    if (pbTrampoline > pbPool)
    {
        __debugbreak();
    }

    pTrampoline->cbCode = (BYTE)(pbTrampoline - pTrampoline->rbCode);
    pTrampoline->cbRestore = (BYTE)cbTarget;
    RtlCopyMemory(pTrampoline->rbRestore, pbTarget, cbTarget);

    if (cbTarget > sizeof(pTrampoline->rbCode) - cbJump)
    {
        // Too many instructions.
        Status = STATUS_INVALID_HANDLE;
        DETOUR_BREAK();
        goto fail;
    }

    pTrampoline->pbRemain = pbTarget + cbTarget;
    pTrampoline->pbDetour = (PBYTE)pDetour;

    pbTrampoline = pTrampoline->rbCode + pTrampoline->cbCode;
#if defined(_M_X64)
    pbTrampoline = detour_gen_jmp_indirect(pbTrampoline, &pTrampoline->pbRemain);
#elif defined(_M_IX86)
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline, pTrampoline->pbRemain);
#elif defined(_M_ARM64)
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline, &pbPool, pTrampoline->pbRemain);
#endif
    pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);
    UNREFERENCED_PARAMETER(pbTrampoline);

    pMem = pbTarget;
    sMem = cbTarget;
    Status = NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, PAGE_EXECUTE_READWRITE, &dwOld);
    if (!NT_SUCCESS(Status))
    {
        DETOUR_BREAK();
        goto fail;
    }

    DETOUR_TRACE("detours: pbTarget=%p: "
                 "%02x %02x %02x %02x "
                 "%02x %02x %02x %02x "
                 "%02x %02x %02x %02x\n",
                 pbTarget,
                 pbTarget[0], pbTarget[1], pbTarget[2], pbTarget[3],
                 pbTarget[4], pbTarget[5], pbTarget[6], pbTarget[7],
                 pbTarget[8], pbTarget[9], pbTarget[10], pbTarget[11]);
    DETOUR_TRACE("detours: pbTramp =%p: "
                 "%02x %02x %02x %02x "
                 "%02x %02x %02x %02x "
                 "%02x %02x %02x %02x\n",
                 pTrampoline,
                 pTrampoline->rbCode[0], pTrampoline->rbCode[1],
                 pTrampoline->rbCode[2], pTrampoline->rbCode[3],
                 pTrampoline->rbCode[4], pTrampoline->rbCode[5],
                 pTrampoline->rbCode[6], pTrampoline->rbCode[7],
                 pTrampoline->rbCode[8], pTrampoline->rbCode[9],
                 pTrampoline->rbCode[10], pTrampoline->rbCode[11]);

    o->fIsRemove = FALSE;
    o->ppbPointer = (PBYTE*)ppPointer;
    o->pTrampoline = pTrampoline;
    o->pbTarget = pbTarget;
    o->dwPerm = dwOld;
    o->pNext = s_pPendingOperations;
    s_pPendingOperations = o;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SlimDetoursDetach(_Inout_ PVOID* ppPointer, _In_ PVOID pDetour)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    if (s_nPendingThreadId != CURRENT_THREAD_ID)
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    DetourOperation* o = new(std::nothrow) DetourOperation;
    if (o == NULL)
    {
        Status = STATUS_NO_MEMORY;
fail:
        DETOUR_BREAK();
        if (o != NULL)
        {
            delete o;
            o = NULL;
        }
        SlimDetoursTransactionAbort();
        return Status;
    }

    PDETOUR_TRAMPOLINE pTrampoline = (PDETOUR_TRAMPOLINE)detour_skip_jmp((PBYTE)*ppPointer);
    pDetour = detour_skip_jmp((PBYTE)pDetour);

    ////////////////////////////////////// Verify that Trampoline is in place.
    //
    LONG cbTarget = pTrampoline->cbRestore;
    PBYTE pbTarget = pTrampoline->pbRemain - cbTarget;
    if (cbTarget == 0 || cbTarget > sizeof(pTrampoline->rbCode) || pTrampoline->pbDetour != pDetour)
    {
        Status = STATUS_INVALID_BLOCK_LENGTH;
        DETOUR_BREAK();
        goto fail;
    }

    pMem = pbTarget;
    sMem = cbTarget;
    Status = NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, PAGE_EXECUTE_READWRITE, &dwOld);
    if (!NT_SUCCESS(Status))
    {
        DETOUR_BREAK();
        goto fail;
    }

    o->fIsRemove = TRUE;
    o->ppbPointer = (PBYTE*)ppPointer;
    o->pTrampoline = pTrampoline;
    o->pbTarget = pbTarget;
    o->dwPerm = dwOld;
    o->pNext = s_pPendingOperations;
    s_pPendingOperations = o;

    return STATUS_SUCCESS;
}
