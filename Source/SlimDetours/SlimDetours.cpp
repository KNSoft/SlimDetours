/*
 * KNSoft SlimDetours (https://github.com/KNSoft/SlimDetours) Core Functionality
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MPL-2.0 license.
 */

#include "SlimDetours.inl"

BOOL detour_init()
{
    detour_memory_init();
    return TRUE;
}

static BOOL g_bStaticInit = detour_init();
