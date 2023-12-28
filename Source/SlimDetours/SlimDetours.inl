#pragma once

#include <Wintexports/Wintexports.h>

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
