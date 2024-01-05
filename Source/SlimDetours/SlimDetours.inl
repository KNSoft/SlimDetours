#pragma once

#include <Wintexports/Wintexports.h>

#include <limits.h>

#ifdef __cplusplus
#include <new>
#endif

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

/* Memory management */

VOID detour_memory_init();

BOOL detour_memory_is_system_reserved(_In_ PVOID Address);

_Ret_notnull_
PVOID detour_memory_2gb_below(_In_ PVOID Address);

_Ret_notnull_
PVOID detour_memory_2gb_above(_In_ PVOID Address);

EXTERN_C_END
