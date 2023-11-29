#pragma once

#include <Wintexports/Wintexports.h>

#if defined(_VC_NODEFAULTLIB)
#define _NO_CRT_STDIO_INLINE
#pragma comment(lib, "WIE_CRT.lib")
#endif

#ifdef __cplusplus
#include <new>
#endif

#if _DEBUG
#define DETOUR_TRACE(Format, ...) DbgPrint(Format, __VA_ARGS__)
#define DETOUR_BREAK() __debugbreak()
#else
#define DETOUR_TRACE(Format, ...)
#define DETOUR_BREAK()
#endif

#define MM_ALLOCATION_GRANULARITY 0x10000
