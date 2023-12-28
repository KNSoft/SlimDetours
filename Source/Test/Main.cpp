#include <Wintexports/Wintexports.h>

#pragma comment(lib, "ntdll.lib")

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

int WINAPI wWinMain(
    _In_     HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_     LPWSTR    lpCmdLine,
    _In_     int       nShowCmd)
{
    PVOID User32Base;

    if (!NT_SUCCESS(LdrLoadDll(NULL, NULL, &g_usUser32, &User32Base)) ||
        !NT_SUCCESS(LdrGetProcedureAddress(User32Base, &g_asMessageBoxW, 0, (PVOID*)&g_pfnMessageBoxW)))
    {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    if (!NT_SUCCESS(SlimDetoursTransactionBegin()) ||
        !NT_SUCCESS(SlimDetoursAttach((PVOID*)&g_pfnMessageBoxW, Hooked_MessageBoxW)) ||
        !NT_SUCCESS(SlimDetoursTransactionCommit()))
    {
        return STATUS_UNSUCCESSFUL;
    }

    MessageBoxW(NULL, L"Text", L"Caption", MB_OK);

    return STATUS_SUCCESS;
}
