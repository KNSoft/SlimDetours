/*
 * KNSoft SlimDetours (https://github.com/KNSoft/SlimDetours) Transaction APIs
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

#pragma comment(lib, "KNSoft.NDK.WinAPI.lib")

typedef struct _DETOUR_DELAY_ATTACH DETOUR_DELAY_ATTACH, *PDETOUR_DELAY_ATTACH;
typedef VOID(CALLBACK* DETOUR_DELAY_ATTACH_CALLBACK)(
    _In_ NTSTATUS Status,
    _In_ PVOID* ppPointer,
    _In_ PCWSTR DllName,
    _In_ PCSTR Function,
    _In_opt_ PVOID Context);

struct _DETOUR_DELAY_ATTACH
{
    PDETOUR_DELAY_ATTACH pNext;
    UNICODE_STRING usDllName;
    PCSTR pszFunction;
    PVOID* ppPointer;
    PVOID pDetour;
    DETOUR_DELAY_ATTACH_CALLBACK pfnCallback;
    PVOID Context;
};

static HANDLE s_nPendingThreadId = 0; // Thread owning pending transaction.
static PHANDLE s_phSuspendedThreads = NULL;
static ULONG s_ulSuspendedThreadCount = 0;
static PDETOUR_OPERATION s_pPendingOperations = NULL;
static RTL_SRWLOCK g_DelayedAttachesLock = RTL_SRWLOCK_INIT;
static PVOID g_DllNotifyCookie = NULL;
static PDETOUR_DELAY_ATTACH g_DelayedAttaches = NULL;

NTSTATUS NTAPI SlimDetoursTransactionBegin()
{
    NTSTATUS Status;

    // Make sure only one thread can start a transaction.
    if (_InterlockedCompareExchangePointer(&s_nPendingThreadId, NtGetCurrentThreadId(), 0) != 0)
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    // Make sure the trampoline pages are writable.
    Status = detour_writable_trampoline_regions();
    if (!NT_SUCCESS(Status))
    {
        goto fail;
    }

    Status = detour_thread_suspend(&s_phSuspendedThreads, &s_ulSuspendedThreadCount);
    if (!NT_SUCCESS(Status))
    {
        detour_runnable_trampoline_regions();
        goto fail;
    }

    s_pPendingOperations = NULL;
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

    if (s_nPendingThreadId != NtGetCurrentThreadId())
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    // Restore all of the page permissions.
    for (PDETOUR_OPERATION o = s_pPendingOperations; o != NULL;)
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

        PDETOUR_OPERATION n = o->pNext;
        detour_memory_free(o);
        o = n;
    }
    s_pPendingOperations = NULL;

    // Make sure the trampoline pages are no longer writable.
    detour_runnable_trampoline_regions();

    // Resume any suspended threads.
    detour_thread_resume(s_phSuspendedThreads, s_ulSuspendedThreadCount);

    s_phSuspendedThreads = NULL;
    s_ulSuspendedThreadCount = 0;
    s_nPendingThreadId = 0;
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SlimDetoursTransactionCommit()
{
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    // Common variables.
    PDETOUR_OPERATION o, n;
    PBYTE pbCode;
    BOOL freed = FALSE;
    ULONG i;

    if (s_nPendingThreadId != NtGetCurrentThreadId())
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    if (s_pPendingOperations == NULL)
    {
        goto _exit;
    }

    // Insert or remove each of the detours.
    o = s_pPendingOperations;
    do
    {
        if (o->fIsRemove)
        {
            RtlCopyMemory(o->pbTarget, o->pTrampoline->rbRestore, o->pTrampoline->cbRestore);
            NtFlushInstructionCache(NtCurrentProcess(), o->pbTarget, o->pTrampoline->cbRestore);
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
            pbCode = detour_gen_jmp_indirect(o->pTrampoline->rbCodeIn, &o->pTrampoline->pbDetour);
            NtFlushInstructionCache(NtCurrentProcess(), pbCode, pbCode - o->pTrampoline->rbCodeIn);
            pbCode = detour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->rbCodeIn);
#elif defined(_M_IX86)
            pbCode = detour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->pbDetour);
#elif defined(_M_ARM64)
            pbCode = detour_gen_jmp_indirect(o->pbTarget, (ULONG64*)&(o->pTrampoline->pbDetour));
#endif
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            NtFlushInstructionCache(NtCurrentProcess(), o->pbTarget, pbCode - o->pbTarget);
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

        o = o->pNext;
    } while (o != NULL);

    // Update any suspended threads.
    for (i = 0; i < s_ulSuspendedThreadCount; i++)
    {
        detour_thread_update(s_phSuspendedThreads[i], s_pPendingOperations);
    }

    // Restore all of the page permissions and free any trampoline regions that are now unused.
    for (o = s_pPendingOperations; o != NULL;)
    {
        // We don't care if this fails, because the code is still accessible.
        pMem = o->pbTarget;
        sMem = o->pTrampoline->cbRestore;
        NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, o->dwPerm, &dwOld);
        if (o->fIsRemove && o->pTrampoline)
        {
            detour_free_trampoline(o->pTrampoline);
            o->pTrampoline = NULL;
            freed = TRUE;
        }

        n = o->pNext;
        detour_memory_free(o);
        o = n;
    }
    s_pPendingOperations = NULL;
    if (freed)
    {
        detour_free_unused_trampoline_regions();
    }

_exit:
    // Make sure the trampoline pages are no longer writable.
    detour_runnable_trampoline_regions();

    // Resume any suspended threads.
    detour_thread_resume(s_phSuspendedThreads, s_ulSuspendedThreadCount);
    s_phSuspendedThreads = NULL;
    s_ulSuspendedThreadCount = 0;
    s_nPendingThreadId = 0;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI SlimDetoursAttach(_Inout_ PVOID* ppPointer, _In_ PVOID pDetour)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    if (s_nPendingThreadId != NtGetCurrentThreadId())
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    PBYTE pbTarget = (PBYTE)*ppPointer;
    PDETOUR_TRAMPOLINE pTrampoline = NULL;
    PDETOUR_OPERATION o = NULL;

    pbTarget = (PBYTE)detour_skip_jmp(pbTarget);
    pDetour = detour_skip_jmp((PBYTE)pDetour);

    // Don't follow a jump if its destination is the target function.
    // This happens when the detour does nothing other than call the target.
    if (pDetour == (PVOID)pbTarget)
    {
        DETOUR_BREAK();
        goto fail;
    }

    o = detour_memory_alloc(sizeof(DETOUR_OPERATION));
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
            detour_memory_free(o);
        }
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
        pbSrc = (PBYTE)SlimDetoursCopyInstruction(pbTrampoline, pbSrc, NULL, &lExtra);
        DETOUR_TRACE(" SlimDetoursCopyInstruction() = %p (%d bytes)\n", pbSrc, (int)(pbSrc - pbOp));
        pbTrampoline += (pbSrc - pbOp) + lExtra;
        cbTarget = PtrOffset(pbTarget, pbSrc);
        pTrampoline->rAlign[nAlign].obTarget = (BYTE)cbTarget;
        pTrampoline->rAlign[nAlign].obTrampoline = (BYTE)(pbTrampoline - pTrampoline->rbCode);
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

    if (s_nPendingThreadId != NtGetCurrentThreadId())
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    PDETOUR_OPERATION o = detour_memory_alloc(sizeof(DETOUR_OPERATION));
    if (o == NULL)
    {
        Status = STATUS_NO_MEMORY;
fail:
        DETOUR_BREAK();
        if (o != NULL)
        {
            detour_memory_free(o);
        }
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

static NTSTATUS NTAPI detour_attach_now(
    _Out_ PVOID* ppPointer,
    _In_ PVOID pDetour,
    _In_ PVOID DllBase,
    _In_ PCSTR Function)
{
    NTSTATUS Status;
    ANSI_STRING FunctionString;
    ULONG Ordinal;
    PANSI_STRING pFunctionString;
    PVOID FunctionAddress;

    if ((ULONG_PTR)Function <= MAXUSHORT)
    {
        Ordinal = (ULONG)(ULONG_PTR)Function;
        if (Ordinal == 0)
        {
            return STATUS_INVALID_PARAMETER;
        }
        pFunctionString = NULL;
    } else
    {
        Ordinal = 0;
        Status = RtlInitAnsiStringEx(&FunctionString, Function);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
        pFunctionString = &FunctionString;
    }
    /*
     * False positive.
     * Ordinal always > 0 when pFunctionString is NULL,
     * SAL is right but compiler didn't recognize Ordinal than immediate value
     */
#pragma warning(disable: __WARNING_INVALID_PARAM_VALUE_1)
    Status = LdrGetProcedureAddress(DllBase, pFunctionString, Ordinal, &FunctionAddress);
#pragma warning(default: __WARNING_INVALID_PARAM_VALUE_1)
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = SlimDetoursTransactionBegin();
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    *ppPointer = FunctionAddress;
    Status = SlimDetoursAttach(ppPointer, pDetour);
    if (!NT_SUCCESS(Status))
    {
        SlimDetoursTransactionAbort();
        return Status;
    }
    return SlimDetoursTransactionCommit();
}

static VOID CALLBACK detour_dll_notify_proc(
    _In_ ULONG NotificationReason,
    _In_ PCLDR_DLL_NOTIFICATION_DATA NotificationData,
    _In_opt_ PVOID Context)
{
    NTSTATUS Status;
    PDETOUR_DELAY_ATTACH pAttach, pPrevAttach, pNextAttach;

    if (NotificationReason != LDR_DLL_NOTIFICATION_REASON_LOADED || g_DelayedAttaches == NULL)
    {
        return;
    }

    RtlAcquireSRWLockExclusive(&g_DelayedAttachesLock);

    pPrevAttach = NULL;
    pAttach = g_DelayedAttaches;
    while (pAttach != NULL)
    {
        /* Match Dll name */
        if (!RtlEqualUnicodeString(&pAttach->usDllName, NotificationData->Loaded.BaseDllName, FALSE))
        {
            pPrevAttach = pAttach;
            pAttach = pAttach->pNext;
            continue;
        }

        /* Attach detours */
        Status = detour_attach_now(pAttach->ppPointer,
                                   pAttach->pDetour,
                                   NotificationData->Loaded.DllBase,
                                   pAttach->pszFunction);
        if (pAttach->pfnCallback != NULL)
        {
            pAttach->pfnCallback(Status,
                                 pAttach->ppPointer,
                                 pAttach->usDllName.Buffer,
                                 pAttach->pszFunction,
                                 pAttach->Context);
        }

        /* Free the delayed attach node */
        pNextAttach = pAttach->pNext;
        detour_memory_free(pAttach);
        if (pPrevAttach != NULL)
        {
            pPrevAttach->pNext = pNextAttach;
        } else
        {
            g_DelayedAttaches = pNextAttach;
        }
        pAttach = pNextAttach;
    }

    RtlReleaseSRWLockExclusive(&g_DelayedAttachesLock);
}

NTSTATUS NTAPI SlimDetoursDelayAttach(
    _In_ PVOID* ppPointer,
    _In_ PVOID pDetour,
    _In_ PCWSTR DllName,
    _In_ PCSTR Function,
    _In_opt_ __callback DETOUR_DELAY_ATTACH_CALLBACK Callback,
    _In_opt_ PVOID Context)
{
    NTSTATUS Status;
    UNICODE_STRING DllNameString;
    PVOID DllBase;
    PDETOUR_DELAY_ATTACH NewNode;

    /* Check if Dll is already loaded */
    RtlInitUnicodeStringEx(&DllNameString, DllName);
    Status = LdrGetDllHandle(NULL, NULL, &DllNameString, &DllBase);
    if (NT_SUCCESS(Status))
    {
        /* Attach immediately if Dll is loaded */
        Status = detour_attach_now(ppPointer, pDetour, DllBase, Function);
        if (Callback != NULL)
        {
            Callback(Status, ppPointer, DllName, Function, Context);
        }
        return Status;
    } else if (Status != STATUS_DLL_NOT_FOUND)
    {
        return Status;
    }

    /* Insert into delayed attach list */
    RtlAcquireSRWLockExclusive(&g_DelayedAttachesLock);

    if (g_DllNotifyCookie == NULL)
    {
        Status = LdrRegisterDllNotification(0, detour_dll_notify_proc, NULL, &g_DllNotifyCookie);
        if (!NT_SUCCESS(Status))
        {
            RtlReleaseSRWLockExclusive(&g_DelayedAttachesLock);
            return Status;
        }
    }

    NewNode = detour_memory_alloc(sizeof(*NewNode));
    if (NewNode == NULL)
    {
        RtlReleaseSRWLockExclusive(&g_DelayedAttachesLock);
        return STATUS_NO_MEMORY;
    }
    NewNode->pNext = g_DelayedAttaches;
    NewNode->usDllName = DllNameString;
    NewNode->pszFunction = Function;
    NewNode->ppPointer = ppPointer;
    NewNode->pDetour = pDetour;
    NewNode->pfnCallback = Callback;
    NewNode->Context = Context;
    g_DelayedAttaches = NewNode;

    RtlReleaseSRWLockExclusive(&g_DelayedAttachesLock);

    return STATUS_PENDING;
}
