/*
 * KNSoft SlimDetours (https://github.com/KNSoft/SlimDetours) Core Functionality
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MPL-2.0 license.
 */

#include "SlimDetours.inl"

static RTL_RUN_ONCE g_InitOnce = RTL_RUN_ONCE_INIT;

VOID detour_init()
{
    if (RtlRunOnceBeginInitialize(&g_InitOnce, 0, NULL) == STATUS_PENDING)
    {
        detour_memory_init();
        RtlRunOnceComplete(&g_InitOnce, 0, NULL);
    }
}

PVOID NTAPI SlimDetoursCodeFromPointer(_In_ PVOID pPointer)
{
    return detour_skip_jmp((PBYTE)pPointer);
}
