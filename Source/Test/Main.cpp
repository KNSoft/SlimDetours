#include <KNSoft/NDK/NDK.h>

#include "../SlimDetours/SlimDetours.h"

#pragma comment(lib, "SlimDetours.lib")

typedef
int
WINAPI
FN_MessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType);

static UNICODE_STRING g_usUser32 = RTL_CONSTANT_STRING(L"User32.dll");
static ANSI_STRING g_asMessageBoxW = RTL_CONSTANT_STRING("MessageBoxW");
static FN_MessageBoxW* g_pfnMessageBoxW = NULL;

static
int
WINAPI
Hooked_MessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    DbgPrint("Hooked_MessageBoxW(0x%p, L\"%ls\", L\"%ls\", %lu)\n", hWnd, lpText, lpCaption, uType);

    return g_pfnMessageBoxW(hWnd, L"Hooked Text", L"Hooked Caption", uType);
}

static VOID CALLBACK Delay_attach_proc(
    _In_ NTSTATUS Status,
    _In_ PVOID* ppPointer,
    _In_ PCWSTR DllName,
    _In_ PCSTR Function,
    _In_opt_ PVOID Context)
{
    if ((ULONG_PTR)Function <= MAXUSHORT)
    {
        DbgPrint("Delay attached to %ls!#%lu with result 0x%08lX\n", DllName, (ULONG)(ULONG_PTR)Function, Status);
    } else
    {
        DbgPrint("Delay attached to %ls!%hs with result 0x%08lX\n", DllName, Function, Status);
    }
}

int wmain()
{
    NTSTATUS Status;
    PVOID User32Base;

#if 1 // Test delay attach
    FN_MessageBoxW* pfnMessageBoxW;

    Status = SlimDetoursDelayAttach((PVOID*)&g_pfnMessageBoxW,
                                    Hooked_MessageBoxW,
                                    g_usUser32.Buffer,
                                    g_asMessageBoxW.Buffer,
                                    Delay_attach_proc,
                                    NULL);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (!NT_SUCCESS(LdrLoadDll(NULL, NULL, &g_usUser32, &User32Base)) ||
        !NT_SUCCESS(LdrGetProcedureAddress(User32Base, &g_asMessageBoxW, 0, (PVOID*)&pfnMessageBoxW)))
    {
        return STATUS_PROCEDURE_NOT_FOUND;
    }
    
    pfnMessageBoxW(NULL, L"Text", L"Caption", MB_ICONINFORMATION);

    Status = STATUS_SUCCESS;
    
#else // Test traditional usage

    if (!NT_SUCCESS(LdrLoadDll(NULL, NULL, &g_usUser32, &User32Base)) ||
        !NT_SUCCESS(LdrGetProcedureAddress(User32Base, &g_asMessageBoxW, 0, (PVOID*)&g_pfnMessageBoxW)))
    {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    Status = SlimDetoursTransactionBegin();
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }
    Status = SlimDetoursAttach((PVOID*)&g_pfnMessageBoxW, Hooked_MessageBoxW);
    if (!NT_SUCCESS(Status))
    {
        SlimDetoursTransactionAbort();
        return Status;
    }
    Status = SlimDetoursTransactionCommit();
    
    MessageBoxW(NULL, L"Text", L"Caption", MB_ICONINFORMATION);

#endif
    return Status;
}
