/////////////////////////////////////////////////////////////////////////////
//
//  Core Detours Functionality (detours.h of detours.lib)
//
//  Microsoft Research Detours Package, Version 4.0.1
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//

#pragma once
#ifndef _DETOURS_H_
#define _DETOURS_H_

#define DETOURS_VERSION     0x4c0c1   // 0xMAJORcMINORcPATCH

//////////////////////////////////////////////////////////////////////////////
//

#ifdef DETOURS_INTERNAL

#define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS 1
#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1

// Suppress declspec(dllimport) for the sake of Detours
// users that provide kernel32 functionality themselves.
// This is ok in the mainstream case, it will just cost
// an extra instruction calling some functions, which
// LTCG optimizes away.
//
#define _KERNEL32_ 1
#define _USER32_ 1

#include <windows.h>
#include <strsafe.h>
#include <intsafe.h>
#include <crtdbg.h>

#endif // DETOURS_INTERNAL

//////////////////////////////////////////////////////////////////////////////
//

#undef DETOURS_X64
#undef DETOURS_X86
#undef DETOURS_ARM64
#undef DETOURS_BITS
#undef DETOURS_32BIT
#undef DETOURS_64BIT

#if defined(_X86_)
#define DETOURS_X86
#define DETOURS_OPTION_BITS 64

#elif defined(_AMD64_)
#define DETOURS_X64
#define DETOURS_OPTION_BITS 32

#elif defined(_ARM64_)
#define DETOURS_ARM64

#else
#error Unknown architecture (x86, amd64, arm64)
#endif

#ifdef _WIN64
#undef DETOURS_32BIT
#define DETOURS_64BIT 1
#define DETOURS_BITS 64
// If all 64bit kernels can run one and only one 32bit architecture.
//#define DETOURS_OPTION_BITS 32
#else
#define DETOURS_32BIT 1
#undef DETOURS_64BIT
#define DETOURS_BITS 32
// If all 64bit kernels can run one and only one 32bit architecture.
//#define DETOURS_OPTION_BITS 32
#endif

/////////////////////////////////////////////////////////////// Helper Macros.
//
#define DETOURS_STRINGIFY_(x)    #x
#define DETOURS_STRINGIFY(x)    DETOURS_STRINGIFY_(x)

#define VER_DETOURS_BITS    DETOURS_STRINGIFY(DETOURS_BITS)

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/////////////////////////////////////////////////// Instruction Target Macros.
//
#define DETOUR_INSTRUCTION_TARGET_NONE          ((PVOID)0)
#define DETOUR_INSTRUCTION_TARGET_DYNAMIC       ((PVOID)(LONG_PTR)-1)

typedef struct _DETOUR_TRAMPOLINE DETOUR_TRAMPOLINE, *PDETOUR_TRAMPOLINE;

//////////////////////////////////////////////////////////// Transaction APIs.
//
LONG WINAPI DetourTransactionBegin(VOID);
LONG WINAPI DetourTransactionAbort(VOID);
LONG WINAPI DetourTransactionCommit(VOID);
LONG WINAPI DetourTransactionCommitEx(_Out_opt_ PVOID **pppFailedPointer);

LONG WINAPI DetourUpdateThread(_In_ HANDLE hThread);

LONG WINAPI DetourAttach(_Inout_ PVOID *ppPointer,
                         _In_ PVOID pDetour);

LONG WINAPI DetourAttachEx(_Inout_ PVOID *ppPointer,
                           _In_ PVOID pDetour,
                           _Out_opt_ PDETOUR_TRAMPOLINE *ppRealTrampoline,
                           _Out_opt_ PVOID *ppRealTarget,
                           _Out_opt_ PVOID *ppRealDetour);

LONG WINAPI DetourDetach(_Inout_ PVOID *ppPointer,
                         _In_ PVOID pDetour);

////////////////////////////////////////////////////////////// Code Functions.
//
PVOID WINAPI DetourCodeFromPointer(_In_ PVOID pPointer,
                                   _Out_opt_ PVOID *ppGlobals);
PVOID WINAPI DetourCopyInstruction(_In_opt_ PVOID pDst,
                                   _Inout_opt_ PVOID *ppDstPool,
                                   _In_ PVOID pSrc,
                                   _Out_opt_ PVOID *ppTarget,
                                   _Out_opt_ LONG *plExtra);

//
//////////////////////////////////////////////////////////////////////////////
#ifdef __cplusplus
}
#endif // __cplusplus

/////////////////////////////////////////////////// Type-safe overloads for C++
//
#if __cplusplus >= 201103L || _MSVC_LANG >= 201103L
#include <type_traits>

template<typename T>
struct DetoursIsFunctionPointer : std::false_type {};

template<typename T>
struct DetoursIsFunctionPointer<T*> : std::is_function<typename std::remove_pointer<T>::type> {};

template<
    typename T,
    typename std::enable_if<DetoursIsFunctionPointer<T>::value, int>::type = 0>
LONG DetourAttach(_Inout_ T *ppPointer,
                  _In_ T pDetour) noexcept
{
    return DetourAttach(
        reinterpret_cast<void**>(ppPointer),
        reinterpret_cast<void*>(pDetour));
}

template<
    typename T,
    typename std::enable_if<DetoursIsFunctionPointer<T>::value, int>::type = 0>
LONG DetourAttachEx(_Inout_ T *ppPointer,
                    _In_ T pDetour,
                    _Out_opt_ PDETOUR_TRAMPOLINE *ppRealTrampoline,
                    _Out_opt_ T *ppRealTarget,
                    _Out_opt_ T *ppRealDetour) noexcept
{
    return DetourAttachEx(
        reinterpret_cast<void**>(ppPointer),
        reinterpret_cast<void*>(pDetour),
        ppRealTrampoline,
        reinterpret_cast<void**>(ppRealTarget),
        reinterpret_cast<void**>(ppRealDetour));
}

template<
    typename T,
    typename std::enable_if<DetoursIsFunctionPointer<T>::value, int>::type = 0>
LONG DetourDetach(_Inout_ T *ppPointer,
                  _In_ T pDetour) noexcept
{
    return DetourDetach(
        reinterpret_cast<void**>(ppPointer),
        reinterpret_cast<void*>(pDetour));
}

#endif // __cplusplus >= 201103L || _MSVC_LANG >= 201103L
//
//////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////////////// Detours Internal Definitions.
//
#ifdef __cplusplus
#ifdef DETOURS_INTERNAL

#define NOTHROW
// #define NOTHROW (nothrow)

#if defined(_INC_STDIO) && !defined(_CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS)
#error detours.h must be included before stdio.h (or at least define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS earlier)
#endif
#define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS 1

#ifdef _DEBUG

int Detour_AssertExprWithFunctionName(int reportType, const char* filename, int linenumber, const char* FunctionName, const char* msg);

#define DETOUR_ASSERT_EXPR_WITH_FUNCTION(expr, msg) \
    (void) ((expr) || \
    (1 != Detour_AssertExprWithFunctionName(_CRT_ASSERT, __FILE__, __LINE__,__FUNCTION__, msg)) || \
    (_CrtDbgBreak(), 0))

#define DETOUR_ASSERT(expr) DETOUR_ASSERT_EXPR_WITH_FUNCTION((expr), #expr)

#else// _DEBUG
#define DETOUR_ASSERT(expr)
#endif// _DEBUG

#ifndef DETOUR_TRACE
#if DETOUR_DEBUG
#define DETOUR_TRACE(x) printf x
#define DETOUR_BREAK()  __debugbreak()
#include <stdio.h>
#include <limits.h>
#else
#define DETOUR_TRACE(x)
#define DETOUR_BREAK()
#endif
#endif

//////////////////////////////////////////////////////////////////////////////

#define MM_ALLOCATION_GRANULARITY 0x10000

//////////////////////////////////////////////////////////////////////////////

#endif // DETOURS_INTERNAL
#endif // __cplusplus

#endif // _DETOURS_H_
//
////////////////////////////////////////////////////////////////  End of File.
