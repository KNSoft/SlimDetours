﻿/*
 * KNSoft SlimDetours (https://github.com/KNSoft/SlimDetours) Thread management
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MPL-2.0 license.
 */

#include "SlimDetours.inl"

NTSTATUS detour_thread_suspend(
    _Outptr_result_maybenull_ PHANDLE* SuspendedHandles,
    _Out_ PULONG SuspendedHandleCount)
{
    NTSTATUS Status;
    ULONG i, SuspendedCount;
    PSYSTEM_PROCESS_INFORMATION pSPI, pCurrentSPI;
    PSYSTEM_THREAD_INFORMATION pSTI;
    PHANDLE Buffer;
    OBJECT_ATTRIBUTES ObjectAttributes;
    HANDLE ThreadHandle, CurrentPID, CurrentTID;

    /* Get system process and thread information */

    i = MB_TO_BYTES(1);
_try_alloc:
    pSPI = (PSYSTEM_PROCESS_INFORMATION)detour_memory_alloc(i);
    if (pSPI == NULL)
    {
        return STATUS_NO_MEMORY;
    }
    Status = NtQuerySystemInformation(SystemProcessInformation, pSPI, i, &i);
    if (!NT_SUCCESS(Status))
    {
        detour_memory_free(pSPI);
        if (Status == STATUS_INFO_LENGTH_MISMATCH)
        {
            goto _try_alloc;
        }
        return Status;
    }

    /* Find current process and threads */

    CurrentPID = (HANDLE)ReadTeb(ClientId.UniqueProcess);
    pCurrentSPI = pSPI;
_next_proc:
    if (pCurrentSPI->UniqueProcessId != CurrentPID)
    {
        if (pCurrentSPI->NextEntryOffset == 0)
        {
            detour_memory_free(pSPI);
            return STATUS_NOT_FOUND;
        } else
        {
            pCurrentSPI = (PSYSTEM_PROCESS_INFORMATION)Add2Ptr(pCurrentSPI, pCurrentSPI->NextEntryOffset);
            goto _next_proc;
        }
    }
    pSTI = (PSYSTEM_THREAD_INFORMATION)Add2Ptr(pCurrentSPI, sizeof(*pCurrentSPI));

    /* Suspend threads and create handle array */

    Buffer = (PHANDLE)detour_memory_alloc(pCurrentSPI->NumberOfThreads * sizeof(HANDLE));
    if (Buffer == NULL)
    {
        detour_memory_free(pSPI);
        return STATUS_NO_MEMORY;
    }

    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
    SuspendedCount = 0;
    CurrentTID = (HANDLE)ReadTeb(ClientId.UniqueThread);
    for (i = 0; i < pCurrentSPI->NumberOfThreads; i++)
    {
        if (pSTI[i].ClientId.UniqueThread == CurrentTID ||
            !NT_SUCCESS(NtOpenThread(&ThreadHandle,
                                     THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,
                                     &ObjectAttributes,
                                     &pSTI[i].ClientId)))
        {
            continue;
        }
        if (NT_SUCCESS(NtSuspendThread(ThreadHandle, NULL)))
        {
            Buffer[SuspendedCount++] = ThreadHandle;
        } else
        {
            NtClose(ThreadHandle);
        }
    }
    detour_memory_free(pSPI);

    /* Return suspended thread handles */

    *SuspendedHandleCount = SuspendedCount;
    if (SuspendedCount > 0)
    {
        *SuspendedHandles = Buffer;
    } else
    {
        detour_memory_free(Buffer);
        *SuspendedHandles = NULL;
    }
    return STATUS_SUCCESS;
}

VOID detour_thread_resume(
    _In_reads_(SuspendedHandleCount) _Frees_ptr_ PHANDLE SuspendedHandles,
    _In_ ULONG SuspendedHandleCount)
{
    ULONG i;

    for (i = 0; i < SuspendedHandleCount; i++)
    {
        NtResumeThread(SuspendedHandles[i], NULL);
        NtClose(SuspendedHandles[i]);
    }
    detour_memory_free(SuspendedHandles);
}

NTSTATUS detour_thread_update(_In_ HANDLE ThreadHandle, _In_ PDETOUR_OPERATION PendingOperations)
{
    NTSTATUS Status;
    PDETOUR_OPERATION o;
    CONTEXT cxt;
    BOOL bUpdateContext;

    cxt.ContextFlags = CONTEXT_CONTROL;
    Status = NtGetContextThread(ThreadHandle, &cxt);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    for (o = PendingOperations; o != NULL; o = o->pNext)
    {
        bUpdateContext = FALSE;
        if (o->fIsRemove)
        {
            if (cxt.CONTEXT_PC >= (ULONG_PTR)o->pTrampoline &&
                cxt.CONTEXT_PC < ((ULONG_PTR)o->pTrampoline + sizeof(o->pTrampoline)))
            {
                cxt.CONTEXT_PC = (ULONG_PTR)o->pbTarget +
                    detour_align_from_trampoline(o->pTrampoline, (BYTE)(cxt.CONTEXT_PC - (ULONG_PTR)o->pTrampoline));
                bUpdateContext = TRUE;
            }
        } else
        {
            if (cxt.CONTEXT_PC >= (ULONG_PTR)o->pbTarget &&
                cxt.CONTEXT_PC < ((ULONG_PTR)o->pbTarget + o->pTrampoline->cbRestore))
            {
                cxt.CONTEXT_PC = (ULONG_PTR)o->pTrampoline +
                    detour_align_from_target(o->pTrampoline, (BYTE)(cxt.CONTEXT_PC - (ULONG_PTR)o->pbTarget));
                bUpdateContext = TRUE;
            }
        }
        if (bUpdateContext)
        {
            Status = NtSetContextThread(ThreadHandle, &cxt);
            break;
        }
    }

    return Status;
}
