/*
 * KNSoft SlimDetours (https://github.com/KNSoft/SlimDetours) Core Functionality
 * Copyright (c) KNSoft.org (https://github.com/KNSoft). All rights reserved.
 * Licensed under the MPL-2.0 license.
 *
 * Source base on Microsoft Detours:
 *
 * Microsoft Research Detours Package, Version 4.0.1
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT license.
 */

#include "pch.h"
#include "detours.h"

struct _DETOUR_ALIGN
{
    BYTE obTarget : 3;
    BYTE obTrampoline : 5;
};

static_assert(sizeof(_DETOUR_ALIGN) == 1);

//////////////////////////////////////////////////////////////////////////////
//
// Region reserved for system DLLs, which cannot be used for trampolines.
//
static PVOID s_pSystemRegionLowerBound = (PVOID)(ULONG_PTR)0x70000000;
static PVOID s_pSystemRegionUpperBound = (PVOID)(ULONG_PTR)0x80000000;

//////////////////////////////////////////////////////////////////////////////
//
static bool detour_is_imported(PBYTE pbCode, PBYTE pbAddress)
{
    NTSTATUS Status;
    MEMORY_BASIC_INFORMATION mbi;
    PIMAGE_DOS_HEADER pDosHeader;
    PIMAGE_NT_HEADERS pNtHeader;
    PVOID pEndOfMem;
    WORD wNtMagic;

    Status = NtQueryVirtualMemory(NtCurrentProcess(), (PVOID)pbCode, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
    if (!NT_SUCCESS(Status))
    {
        return false;
    }

    /* Type should be MEM_IMAGE */
    if (mbi.Type != MEM_IMAGE)
    {
        return false;
    }

    /* Cannot be uncommitted regions or guard pages */
    if ((mbi.State != MEM_COMMIT) || ((mbi.Protect & 0xFF) == PAGE_NOACCESS) || (mbi.Protect & PAGE_GUARD))
    {
        return false;
    }

    /*
     * pBase should >= MM_ALLOCATION_GRANULARITY and sSize should >= PAGE_SIZE,
     * PAGE_SIZE always >= sizeof(IMAGE_DOS_HEADER) so we can access IMAGE_DOS_HEADER safely without boundary check.
     */
    if ((ULONG_PTR)mbi.AllocationBase < MM_ALLOCATION_GRANULARITY || mbi.RegionSize < PAGE_SIZE)
    {
        return false;
    }
    static_assert(PAGE_SIZE >= sizeof(IMAGE_DOS_HEADER));

    /* Check IMAGE_DOS_HEADER */
    pDosHeader = (PIMAGE_DOS_HEADER)mbi.AllocationBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return false;
    }
    if (pDosHeader->e_lfanew < sizeof(*pDosHeader) || (ULONG)pDosHeader->e_lfanew > mbi.RegionSize)
    {
        return false;
    }

    /* Now we need perform boundary check in every single step */
    pEndOfMem = Add2Ptr(mbi.AllocationBase, mbi.RegionSize);

    /*
     * Step forward to IMAGE_NT_HEADERS and check IMAGE_NT_SIGNATURE,
     * check FileHeader.SizeOfOptionalHeader == 0 seems pointless
     * unless compare it with sizeof(IMAGE_OPTIONAL_HEADER) explicitly.
     */
    pNtHeader = (PIMAGE_NT_HEADERS)Add2Ptr(pDosHeader, pDosHeader->e_lfanew);
    if (Add2Ptr(pNtHeader, sizeof(*pNtHeader)) > pEndOfMem)
    {
        return false;
    }
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        return false;
    }

    /* Step forward to IMAGE_OPTIONAL_HEADER and check magic */
    static_assert(UFIELD_OFFSET(IMAGE_OPTIONAL_HEADER, Magic) == 0);
    wNtMagic = pNtHeader->OptionalHeader.Magic;
    if ((wNtMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
         pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER64)) &&
        (wNtMagic != IMAGE_NT_OPTIONAL_HDR32_MAGIC ||
         pNtHeader->FileHeader.SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER32)))
    {
        return false;
    }

    if (pbAddress < Add2Ptr(mbi.AllocationBase,
                            pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress) ||
        pbAddress >= Add2Ptr(mbi.AllocationBase,
                             pNtHeader->OptionalHeader
                             .DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress +
                             pNtHeader->OptionalHeader
                             .DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size))
    {
        return false;
    }

    return true;
}

inline ULONG_PTR detour_2gb_below(ULONG_PTR address)
{
    return address > (ULONG_PTR)0x7ff80000 ? address - 0x7ff80000 : 0x80000;
}

inline ULONG_PTR detour_2gb_above(ULONG_PTR address)
{
#if defined(_WIN64)
    return address < (ULONG_PTR)0xffffffff80000000 ? address + 0x7ff80000 : (ULONG_PTR)0xfffffffffff80000;
#else
    return address < (ULONG_PTR)0x80000000 ? address + 0x7ff80000 : (ULONG_PTR)0xfff80000;
#endif
}

#if defined(_M_IX86)

struct _DETOUR_TRAMPOLINE
{
    BYTE            rbCode[30];     // target code + jmp to pbRemain
    BYTE            cbCode;         // size of moved target code.
    BYTE            cbCodeBreak;    // padding to make debugging easier.
    BYTE            rbRestore[22];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            cbRestoreBreak; // padding to make debugging easier.
    _DETOUR_ALIGN   rAlign[8];      // instruction alignment array.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 72);

enum
{
    SIZE_OF_JMP = 5
};

inline PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xe9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_gen_jmp_indirect(PBYTE pbCode, PBYTE* ppbJmpVal)
{
    *pbCode++ = 0xff;   // jmp [+imm32]
    *pbCode++ = 0x25;
    *((INT32*&)pbCode)++ = (INT32)((PBYTE)ppbJmpVal);
    return pbCode;
}

inline PBYTE detour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit)
    {
        *pbCode++ = 0xcc;   // brk;
    }
    return pbCode;
}

inline PBYTE detour_skip_jmp(PBYTE pbCode, PVOID* ppGlobals)
{
    if (pbCode == NULL)
    {
        return NULL;
    }
    if (ppGlobals != NULL)
    {
        *ppGlobals = NULL;
    }

    // First, skip over the import vector if there is one.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25)
    {
        // jmp [imm32]
        // Looks like an import alias jump, then get the code it points to.
        PBYTE pbTarget = *(UNALIGNED PBYTE*) & pbCode[2];
        if (detour_is_imported(pbCode, pbTarget))
        {
            PBYTE pbNew = *(UNALIGNED PBYTE*)pbTarget;
            DETOUR_TRACE("%p->%p: skipped over import table.\n", pbCode, pbNew);
            pbCode = pbNew;
        }
    }

    // Then, skip over a patch jump
    if (pbCode[0] == 0xeb)
    {
        // jmp +imm8
        PBYTE pbNew = pbCode + 2 + *(CHAR*)&pbCode[1];
        DETOUR_TRACE("%p->%p: skipped over short jump.\n", pbCode, pbNew);
        pbCode = pbNew;

        // First, skip over the import vector if there is one.
        if (pbCode[0] == 0xff && pbCode[1] == 0x25)
        {
            // jmp [imm32]
            // Looks like an import alias jump, then get the code it points to.
            PBYTE pbTarget = *(UNALIGNED PBYTE*) & pbCode[2];
            if (detour_is_imported(pbCode, pbTarget))
            {
                pbNew = *(UNALIGNED PBYTE*)pbTarget;
                DETOUR_TRACE("%p->%p: skipped over import table.\n", pbCode, pbNew);
                pbCode = pbNew;
            }
        }
        // Finally, skip over a long jump if it is the target of the patch jump.
        else if (pbCode[0] == 0xe9)
        {
            // jmp +imm32
            pbNew = pbCode + 5 + *(UNALIGNED INT32*) & pbCode[1];
            DETOUR_TRACE("%p->%p: skipped over long jump.\n", pbCode, pbNew);
            pbCode = pbNew;
        }
    }
    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode, PDETOUR_TRAMPOLINE* ppLower, PDETOUR_TRAMPOLINE* ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);
    DETOUR_TRACE("[%p..%p..%p]\n", (PVOID)lo, pbCode, (PVOID)hi);

    // And, within +/- 2GB of relative jmp targets.
    if (pbCode[0] == 0xe9)
    {
        // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32*) & pbCode[1];

        if (pbNew < pbCode)
        {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        } else
        {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
        DETOUR_TRACE("[%p..%p..%p] +imm32\n", (PVOID)lo, pbCode, (PVOID)hi);
    }

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    if (pbCode[0] == 0xeb ||    // jmp +imm8
        pbCode[0] == 0xe9 ||    // jmp +imm32
        pbCode[0] == 0xe0 ||    // jmp eax
        pbCode[0] == 0xc2 ||    // ret +imm8
        pbCode[0] == 0xc3 ||    // ret
        pbCode[0] == 0xcc)
    {
        // brk
        return TRUE;
    } else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3)
    {
        // rep ret
        return TRUE;
    } else if (pbCode[0] == 0xff && pbCode[1] == 0x25)
    {
        // jmp [+imm32]
        return TRUE;
    } else if ((pbCode[0] == 0x26 ||      // jmp es:
                pbCode[0] == 0x2e ||      // jmp cs:
                pbCode[0] == 0x36 ||      // jmp ss:
                pbCode[0] == 0x3e ||      // jmp ds:
                pbCode[0] == 0x64 ||      // jmp fs:
                pbCode[0] == 0x65) &&     // jmp gs:
               pbCode[1] == 0xff &&       // jmp [+imm32]
               pbCode[2] == 0x25)
    {
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    // 1-byte through 11-byte NOPs.
    if (pbCode[0] == 0x90)
    {
        return 1;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x90)
    {
        return 2;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00)
    {
        return 3;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 && pbCode[3] == 0x00)
    {
        return 4;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 && pbCode[3] == 0x00 && pbCode[4] == 0x00)
    {
        return 5;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F && pbCode[3] == 0x44 && pbCode[4] == 0x00 &&
        pbCode[5] == 0x00)
    {
        return 6;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 && pbCode[3] == 0x00 && pbCode[4] == 0x00 &&
        pbCode[5] == 0x00 && pbCode[6] == 0x00)
    {
        return 7;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 && pbCode[3] == 0x00 && pbCode[4] == 0x00 &&
        pbCode[5] == 0x00 && pbCode[6] == 0x00 && pbCode[7] == 0x00)
    {
        return 8;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F && pbCode[3] == 0x84 && pbCode[4] == 0x00 &&
        pbCode[5] == 0x00 && pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00)
    {
        return 9;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F && pbCode[3] == 0x1F && pbCode[4] == 0x84 &&
        pbCode[5] == 0x00 && pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 && pbCode[9] == 0x00)
    {
        return 10;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 && pbCode[3] == 0x0F && pbCode[4] == 0x1F &&
        pbCode[5] == 0x84 && pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 && pbCode[9] == 0x00 &&
        pbCode[10] == 0x00)
    {
        return 11;
    }

    // int 3.
    if (pbCode[0] == 0xCC)
    {
        return 1;
    }
    return 0;
}

#endif // defined(_M_IX86)

#if defined(_M_X64)

struct _DETOUR_TRAMPOLINE
{
    // An X64 instuction can be 15 bytes long.
    // In practice 11 seems to be the limit.
    BYTE            rbCode[30];     // target code + jmp to pbRemain.
    BYTE            cbCode;         // size of moved target code.
    BYTE            cbCodeBreak;    // padding to make debugging easier.
    BYTE            rbRestore[30];  // original target code.
    BYTE            cbRestore;      // size of original target code.
    BYTE            cbRestoreBreak; // padding to make debugging easier.
    _DETOUR_ALIGN   rAlign[8];      // instruction alignment array.
    PBYTE           pbRemain;       // first instruction after moved code. [free list]
    PBYTE           pbDetour;       // first instruction of detour function.
    BYTE            rbCodeIn[8];    // jmp [pbDetour]
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 96);

enum
{
    SIZE_OF_JMP = 5
};

inline PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE pbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 5;
    *pbCode++ = 0xe9;   // jmp +imm32
    *((INT32*&)pbCode)++ = (INT32)(pbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_gen_jmp_indirect(PBYTE pbCode, PBYTE* ppbJmpVal)
{
    PBYTE pbJmpSrc = pbCode + 6;
    *pbCode++ = 0xff;   // jmp [+imm32]
    *pbCode++ = 0x25;
    *((INT32*&)pbCode)++ = (INT32)((PBYTE)ppbJmpVal - pbJmpSrc);
    return pbCode;
}

inline PBYTE detour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit)
    {
        *pbCode++ = 0xcc;   // brk;
    }
    return pbCode;
}

inline PBYTE detour_skip_jmp(PBYTE pbCode, PVOID* ppGlobals)
{
    if (pbCode == NULL)
    {
        return NULL;
    }
    if (ppGlobals != NULL)
    {
        *ppGlobals = NULL;
    }

    // First, skip over the import vector if there is one.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25)
    {
        // jmp [+imm32]
        // Looks like an import alias jump, then get the code it points to.
        PBYTE pbTarget = pbCode + 6 + *(UNALIGNED INT32*) & pbCode[2];
        if (detour_is_imported(pbCode, pbTarget))
        {
            PBYTE pbNew = *(UNALIGNED PBYTE*)pbTarget;
            DETOUR_TRACE("%p->%p: skipped over import table.\n", pbCode, pbNew);
            pbCode = pbNew;
        }
    }

    // Then, skip over a patch jump
    if (pbCode[0] == 0xeb)
    {
        // jmp +imm8
        PBYTE pbNew = pbCode + 2 + *(CHAR*)&pbCode[1];
        DETOUR_TRACE("%p->%p: skipped over short jump.\n", pbCode, pbNew);
        pbCode = pbNew;

        // First, skip over the import vector if there is one.
        if (pbCode[0] == 0xff && pbCode[1] == 0x25)
        {
            // jmp [+imm32]
            // Looks like an import alias jump, then get the code it points to.
            PBYTE pbTarget = pbCode + 6 + *(UNALIGNED INT32*) & pbCode[2];
            if (detour_is_imported(pbCode, pbTarget))
            {
                pbNew = *(UNALIGNED PBYTE*)pbTarget;
                DETOUR_TRACE("%p->%p: skipped over import table.\n", pbCode, pbNew);
                pbCode = pbNew;
            }
        }
        // Finally, skip over a long jump if it is the target of the patch jump.
        else if (pbCode[0] == 0xe9)
        {
            // jmp +imm32
            pbNew = pbCode + 5 + *(UNALIGNED INT32*) & pbCode[1];
            DETOUR_TRACE("%p->%p: skipped over long jump.\n", pbCode, pbNew);
            pbCode = pbNew;
        }
    }
    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode, PDETOUR_TRAMPOLINE* ppLower, PDETOUR_TRAMPOLINE* ppUpper)
{
    // We have to place trampolines within +/- 2GB of code.
    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);
    DETOUR_TRACE("[%p..%p..%p]\n", (PVOID)lo, pbCode, (PVOID)hi);

    // And, within +/- 2GB of relative jmp vectors.
    if (pbCode[0] == 0xff && pbCode[1] == 0x25)
    {
        // jmp [+imm32]
        PBYTE pbNew = pbCode + 6 + *(UNALIGNED INT32*) & pbCode[2];

        if (pbNew < pbCode)
        {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        } else
        {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
        DETOUR_TRACE("[%p..%p..%p] [+imm32]\n", (PVOID)lo, pbCode, (PVOID)hi);
    }
    // And, within +/- 2GB of relative jmp targets.
    else if (pbCode[0] == 0xe9)
    {
        // jmp +imm32
        PBYTE pbNew = pbCode + 5 + *(UNALIGNED INT32*) & pbCode[1];

        if (pbNew < pbCode)
        {
            hi = detour_2gb_above((ULONG_PTR)pbNew);
        } else
        {
            lo = detour_2gb_below((ULONG_PTR)pbNew);
        }
        DETOUR_TRACE("[%p..%p..%p] +imm32\n", (PVOID)lo, pbCode, (PVOID)hi);
    }

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    if (pbCode[0] == 0xeb ||    // jmp +imm8
        pbCode[0] == 0xe9 ||    // jmp +imm32
        pbCode[0] == 0xe0 ||    // jmp eax
        pbCode[0] == 0xc2 ||    // ret +imm8
        pbCode[0] == 0xc3 ||    // ret
        pbCode[0] == 0xcc)
    {
        // brk
        return TRUE;
    } else if (pbCode[0] == 0xf3 && pbCode[1] == 0xc3)
    {
        // rep ret
        return TRUE;
    } else if (pbCode[0] == 0xff && pbCode[1] == 0x25)
    {
        // jmp [+imm32]
        return TRUE;
    } else if ((pbCode[0] == 0x26 ||      // jmp es:
                pbCode[0] == 0x2e ||      // jmp cs:
                pbCode[0] == 0x36 ||      // jmp ss:
                pbCode[0] == 0x3e ||      // jmp ds:
                pbCode[0] == 0x64 ||      // jmp fs:
                pbCode[0] == 0x65) &&     // jmp gs:
               pbCode[1] == 0xff &&       // jmp [+imm32]
               pbCode[2] == 0x25)
    {
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    // 1-byte through 11-byte NOPs.
    if (pbCode[0] == 0x90)
    {
        return 1;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x90)
    {
        return 2;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x00)
    {
        return 3;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x40 && pbCode[3] == 0x00)
    {
        return 4;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x44 && pbCode[3] == 0x00 && pbCode[4] == 0x00)
    {
        return 5;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F && pbCode[3] == 0x44 && pbCode[4] == 0x00 &&
        pbCode[5] == 0x00)
    {
        return 6;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x80 && pbCode[3] == 0x00 && pbCode[4] == 0x00 &&
        pbCode[5] == 0x00 && pbCode[6] == 0x00)
    {
        return 7;
    }
    if (pbCode[0] == 0x0F && pbCode[1] == 0x1F && pbCode[2] == 0x84 && pbCode[3] == 0x00 && pbCode[4] == 0x00 &&
        pbCode[5] == 0x00 && pbCode[6] == 0x00 && pbCode[7] == 0x00)
    {
        return 8;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x0F && pbCode[2] == 0x1F && pbCode[3] == 0x84 && pbCode[4] == 0x00 &&
        pbCode[5] == 0x00 && pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00)
    {
        return 9;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x0F && pbCode[3] == 0x1F && pbCode[4] == 0x84 &&
        pbCode[5] == 0x00 && pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 && pbCode[9] == 0x00)
    {
        return 10;
    }
    if (pbCode[0] == 0x66 && pbCode[1] == 0x66 && pbCode[2] == 0x66 && pbCode[3] == 0x0F && pbCode[4] == 0x1F &&
        pbCode[5] == 0x84 && pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 && pbCode[9] == 0x00 &&
        pbCode[10] == 0x00)
    {
        return 11;
    }

    // int 3.
    if (pbCode[0] == 0xCC)
    {
        return 1;
    }
    return 0;
}

#endif // defined(_M_X64)

#if defined(_M_ARM64)

struct _DETOUR_TRAMPOLINE
{
    // An ARM64 instruction is 4 bytes long.
    //
    // The overwrite is always composed of 3 instructions (12 bytes) which perform an indirect jump
    // using _DETOUR_TRAMPOLINE::pbDetour as the address holding the target location.
    //
    // Copied instructions can expand.
    //
    // The scheme using MovImmediate can cause an instruction
    // to grow as much as 6 times.
    // That would be Bcc or Tbz with a large address space:
    //   4 instructions to form immediate
    //   inverted tbz/bcc
    //   br
    //
    // An expansion of 4 is not uncommon -- bl/blr and small address space:
    //   3 instructions to form immediate
    //   br or brl
    //
    // A theoretical maximum for rbCode is thefore 4*4*6 + 16 = 112 (another 16 for jmp to pbRemain).
    //
    // With literals, the maximum expansion is 5, including the literals: 4*4*5 + 16 = 96.
    //
    // The number is rounded up to 128. m_rbScratchDst should match this.
    //
    BYTE            rbCode[128];        // target code + jmp to pbRemain
    BYTE            cbCode;             // size of moved target code.
    BYTE            cbCodeBreak[3];     // padding to make debugging easier.
    BYTE            rbRestore[24];      // original target code.
    BYTE            cbRestore;          // size of original target code.
    BYTE            cbRestoreBreak[3];  // padding to make debugging easier.
    _DETOUR_ALIGN   rAlign[8];          // instruction alignment array.
    PBYTE           pbRemain;           // first instruction after moved code. [free list]
    PBYTE           pbDetour;           // first instruction of detour function.
};

static_assert(sizeof(_DETOUR_TRAMPOLINE) == 184);

enum
{
    SIZE_OF_JMP = 12
};

inline ULONG fetch_opcode(PBYTE pbCode)
{
    return *(ULONG*)pbCode;
}

inline void write_opcode(PBYTE& pbCode, ULONG Opcode)
{
    *(ULONG*)pbCode = Opcode;
    pbCode += 4;
}

struct ARM64_INDIRECT_JMP
{
    struct
    {
        ULONG Rd : 5;
        ULONG immhi : 19;
        ULONG iop : 5;
        ULONG immlo : 2;
        ULONG op : 1;
    } ardp;

    struct
    {
        ULONG Rt : 5;
        ULONG Rn : 5;
        ULONG imm : 12;
        ULONG opc : 2;
        ULONG iop1 : 2;
        ULONG V : 1;
        ULONG iop2 : 3;
        ULONG size : 2;
    } ldr;

    ULONG br;
};

union ARM64_INDIRECT_IMM
{
    struct
    {
        ULONG64 pad : 12;
        ULONG64 adrp_immlo : 2;
        ULONG64 adrp_immhi : 19;
    };

    LONG64 value;
};

PBYTE detour_gen_jmp_indirect(BYTE* pbCode, ULONG64* pbJmpVal)
{
    // adrp x17, [jmpval]
    // ldr x17, [x17, jmpval]
    // br x17

    struct ARM64_INDIRECT_JMP* pIndJmp;
    union ARM64_INDIRECT_IMM jmpIndAddr;

    jmpIndAddr.value = (((LONG64)pbJmpVal) & 0xFFFFFFFFFFFFF000) -
        (((LONG64)pbCode) & 0xFFFFFFFFFFFFF000);

    pIndJmp = (struct ARM64_INDIRECT_JMP*)pbCode;
    pbCode = (BYTE*)(pIndJmp + 1);

    pIndJmp->ardp.Rd = 17;
    pIndJmp->ardp.immhi = jmpIndAddr.adrp_immhi;
    pIndJmp->ardp.iop = 0x10;
    pIndJmp->ardp.immlo = jmpIndAddr.adrp_immlo;
    pIndJmp->ardp.op = 1;

    pIndJmp->ldr.Rt = 17;
    pIndJmp->ldr.Rn = 17;
    pIndJmp->ldr.imm = (((ULONG64)pbJmpVal) & 0xFFF) / 8;
    pIndJmp->ldr.opc = 1;
    pIndJmp->ldr.iop1 = 1;
    pIndJmp->ldr.V = 0;
    pIndJmp->ldr.iop2 = 7;
    pIndJmp->ldr.size = 3;

    pIndJmp->br = 0xD61F0220;

    return pbCode;
}

PBYTE detour_gen_jmp_immediate(PBYTE pbCode, PBYTE* ppPool, PBYTE pbJmpVal)
{
    PBYTE pbLiteral;
    if (ppPool != NULL)
    {
        *ppPool = *ppPool - 8;
        pbLiteral = *ppPool;
    } else
    {
        pbLiteral = pbCode + 8;
    }

    *((PBYTE*&)pbLiteral) = pbJmpVal;
    LONG delta = (LONG)(pbLiteral - pbCode);

    write_opcode(pbCode, 0x58000011 | ((delta / 4) << 5));  // LDR X17,[PC+n]
    write_opcode(pbCode, 0xd61f0000 | (17 << 5));           // BR X17

    if (ppPool == NULL)
    {
        pbCode += 8;
    }
    return pbCode;
}

inline PBYTE detour_gen_brk(PBYTE pbCode, PBYTE pbLimit)
{
    while (pbCode < pbLimit)
    {
        write_opcode(pbCode, 0xd4100000 | (0xf000 << 5));
    }
    return pbCode;
}

inline INT64 detour_sign_extend(UINT64 value, UINT bits)
{
    const UINT left = 64 - bits;
    const INT64 m1 = -1;
    const INT64 wide = (INT64)(value << left);
    const INT64 sign = (wide < 0) ? (m1 << left) : 0;
    return value | sign;
}

inline PBYTE detour_skip_jmp(PBYTE pbCode, PVOID* ppGlobals)
{
    if (pbCode == NULL)
    {
        return NULL;
    }
    if (ppGlobals != NULL)
    {
        *ppGlobals = NULL;
    }

    // Skip over the import jump if there is one.
    pbCode = (PBYTE)pbCode;
    ULONG Opcode = fetch_opcode(pbCode);

    if ((Opcode & 0x9f00001f) == 0x90000010)
    {
        // adrp  x16, IAT
        ULONG Opcode2 = fetch_opcode(pbCode + 4);

        if ((Opcode2 & 0xffe003ff) == 0xf9400210)
        {
            // ldr   x16, [x16, IAT]
            ULONG Opcode3 = fetch_opcode(pbCode + 8);

            if (Opcode3 == 0xd61f0200)
            {
                // br    x16

/* https://static.docs.arm.com/ddi0487/bb/DDI0487B_b_armv8_arm.pdf
    The ADRP instruction shifts a signed, 21-bit immediate left by 12 bits, adds it to the value of the program counter with
    the bottom 12 bits cleared to zero, and then writes the result to a general-purpose register. This permits the
    calculation of the address at a 4KB aligned memory region. In conjunction with an ADD (immediate) instruction, or
    a Load/Store instruction with a 12-bit immediate offset, this allows for the calculation of, or access to, any address
    within +/- 4GB of the current PC.

PC-rel. addressing
    This section describes the encoding of the PC-rel. addressing instruction class. The encodings in this section are
    decoded from Data Processing -- Immediate on page C4-226.
    Add/subtract (immediate)
    This section describes the encoding of the Add/subtract (immediate) instruction class. The encodings in this section
    are decoded from Data Processing -- Immediate on page C4-226.
    Decode fields
    Instruction page
    op
    0 ADR
    1 ADRP

C6.2.10 ADRP
    Form PC-relative address to 4KB page adds an immediate value that is shifted left by 12 bits, to the PC value to
    form a PC-relative address, with the bottom 12 bits masked out, and writes the result to the destination register.
    ADRP <Xd>, <label>
    imm = SignExtend(immhi:immlo:Zeros(12), 64);

    31  30 29 28 27 26 25 24 23 5    4 0
    1   immlo  1  0  0  0  0  immhi  Rd
         9             0

Rd is hardcoded as 0x10 above.
Immediate is 21 signed bits split into 2 bits and 19 bits, and is scaled by 4K.
*/
                UINT64 const pageLow2 = (Opcode >> 29) & 3;
                UINT64 const pageHigh19 = (Opcode >> 5) & ~(~0ui64 << 19);
                INT64 const page = detour_sign_extend((pageHigh19 << 2) | pageLow2, 21) << 12;

/* https://static.docs.arm.com/ddi0487/bb/DDI0487B_b_armv8_arm.pdf

    C6.2.101 LDR (immediate)
    Load Register (immediate) loads a word or doubleword from memory and writes it to a register. The address that is
    used for the load is calculated from a base register and an immediate offset.
    The Unsigned offset variant scales the immediate offset value by the size of the value accessed before adding it
    to the base register value.

Unsigned offset
64-bit variant Applies when size == 11.
    31 30 29 28  27 26 25 24  23 22  21   10   9 5   4 0
     1  x  1  1   1  0  0  1   0  1  imm12      Rn    Rt
         F             9        4              200    10

That is, two low 5 bit fields are registers, hardcoded as 0x10 and 0x10 << 5 above,
then unsigned size-unscaled (8) 12-bit offset, then opcode bits 0xF94.
*/
                UINT64 const offset = ((Opcode2 >> 10) & ~(~0ui64 << 12)) << 3;

                PBYTE const pbTarget = (PBYTE)((ULONG64)pbCode & 0xfffffffffffff000ULL) + page + offset;

                if (detour_is_imported(pbCode, pbTarget))
                {
                    PBYTE pbNew = *(PBYTE*)pbTarget;
                    DETOUR_TRACE("%p->%p: skipped over import table.\n", pbCode, pbNew);
                    return pbNew;
                }
            }
        }
    }
    return pbCode;
}

inline void detour_find_jmp_bounds(PBYTE pbCode, PDETOUR_TRAMPOLINE* ppLower, PDETOUR_TRAMPOLINE* ppUpper)
{
    // The encoding used by detour_gen_jmp_indirect actually enables a
    // displacement of +/- 4GiB. In the future, this could be changed to
    // reflect that. For now, just reuse the x86 logic which is plenty.

    ULONG_PTR lo = detour_2gb_below((ULONG_PTR)pbCode);
    ULONG_PTR hi = detour_2gb_above((ULONG_PTR)pbCode);
    DETOUR_TRACE("[%p..%p..%p]\n", (PVOID)lo, pbCode, (PVOID)hi);

    *ppLower = (PDETOUR_TRAMPOLINE)lo;
    *ppUpper = (PDETOUR_TRAMPOLINE)hi;
}

inline BOOL detour_does_code_end_function(PBYTE pbCode)
{
    ULONG Opcode = fetch_opcode(pbCode);
    if ((Opcode & 0xfffffc1f) == 0xd65f0000 ||  // br <reg>
        (Opcode & 0xfc000000) == 0x14000000)
    {
        // b <imm26>
        return TRUE;
    }
    return FALSE;
}

inline ULONG detour_is_code_filler(PBYTE pbCode)
{
    if (*(ULONG*)pbCode == 0xd503201f)
    {
        // nop.
        return 4;
    }
    if (*(ULONG*)pbCode == 0x00000000)
    {
        // zero-filled padding.
        return 4;
    }
    return 0;
}

#endif // defined(_M_ARM64)

//////////////////////////////////////////////// Trampoline Memory Management.
//
struct DETOUR_REGION
{
    ULONG dwSignature;
    DETOUR_REGION* pNext;       // Next region in list of regions.
    DETOUR_TRAMPOLINE* pFree;   // List of free trampolines in this region.
};
typedef DETOUR_REGION* PDETOUR_REGION;

const ULONG DETOUR_REGION_SIGNATURE = 'Rrtd';
const ULONG DETOUR_REGION_SIZE = 0x10000;
const ULONG DETOUR_TRAMPOLINES_PER_REGION = (DETOUR_REGION_SIZE / sizeof(DETOUR_TRAMPOLINE)) - 1;
static PDETOUR_REGION s_pRegions = NULL; // List of all regions.
static PDETOUR_REGION s_pRegion = NULL; // Default region.

static NTSTATUS detour_writable_trampoline_regions()
{
    NTSTATUS Status;
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    // Mark all of the regions as writable.
    sMem = DETOUR_REGION_SIZE;
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext)
    {
        pMem = pRegion;
        Status = NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, PAGE_EXECUTE_READWRITE, &dwOld);
        if (!NT_SUCCESS(Status))
        {
            return Status;
        }
    }
    return STATUS_SUCCESS;
}

static void detour_runnable_trampoline_regions()
{
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    // Mark all of the regions as executable.
    sMem = DETOUR_REGION_SIZE;
    for (PDETOUR_REGION pRegion = s_pRegions; pRegion != NULL; pRegion = pRegion->pNext)
    {
        pMem = pRegion;
        NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, PAGE_EXECUTE_READ, &dwOld);
        NtFlushInstructionCache(NtCurrentProcess(), pRegion, DETOUR_REGION_SIZE);
    }
}

static PBYTE detour_alloc_round_down_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0)
    {
        pbTry -= extra;
    }
    return pbTry;
}

static PBYTE detour_alloc_round_up_to_region(PBYTE pbTry)
{
    // WinXP64 returns free areas that aren't REGION aligned to 32-bit applications.
    ULONG_PTR extra = ((ULONG_PTR)pbTry) & (DETOUR_REGION_SIZE - 1);
    if (extra != 0)
    {
        ULONG_PTR adjust = DETOUR_REGION_SIZE - extra;
        pbTry += adjust;
    }
    return pbTry;
}

// Starting at pbLo, try to allocate a memory region, continue until pbHi.

static PVOID detour_alloc_region_from_lo(PBYTE pbLo, PBYTE pbHi)
{
    NTSTATUS Status;
    PVOID pMem;
    SIZE_T sMem;
    MEMORY_BASIC_INFORMATION mbi;

    PBYTE pbTry = detour_alloc_round_up_to_region(pbLo);

    DETOUR_TRACE(" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry);

    while (pbTry < pbHi)
    {
        if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound)
        {
            // Skip region reserved for system DLLs, but preserve address space entropy.
            pbTry += 0x08000000;
            continue;
        }

        if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),
                                             pbTry,
                                             MemoryBasicInformation,
                                             &mbi,
                                             sizeof(mbi),
                                             NULL)))
        {
            break;
        }

        DETOUR_TRACE("  Try %p => %p..%p %6lx\n",
                     pbTry,
                     mbi.BaseAddress,
                     Add2Ptr(mbi.BaseAddress, mbi.RegionSize - 1),
                     mbi.State);

        if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE)
        {
            pMem = pbTry;
            sMem = DETOUR_REGION_SIZE;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                             &pMem,
                                             0,
                                             &sMem,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
            if (NT_SUCCESS(Status))
            {
                return pMem;
            } else if (Status == STATUS_DYNAMIC_CODE_BLOCKED)
            {
                return NULL;
            }
            pbTry += DETOUR_REGION_SIZE;
        } else
        {
            pbTry = detour_alloc_round_up_to_region((PBYTE)mbi.BaseAddress + mbi.RegionSize);
        }
    }
    return NULL;
}

// Starting at pbHi, try to allocate a memory region, continue until pbLo.

static PVOID detour_alloc_region_from_hi(PBYTE pbLo, PBYTE pbHi)
{
    NTSTATUS Status;
    PVOID pMem;
    SIZE_T sMem;
    MEMORY_BASIC_INFORMATION mbi;

    PBYTE pbTry = detour_alloc_round_down_to_region(pbHi - DETOUR_REGION_SIZE);

    DETOUR_TRACE(" Looking for free region in %p..%p from %p:\n", pbLo, pbHi, pbTry);

    while (pbTry > pbLo)
    {
        DETOUR_TRACE("  Try %p\n", pbTry);
        if (pbTry >= s_pSystemRegionLowerBound && pbTry <= s_pSystemRegionUpperBound)
        {
            // Skip region reserved for system DLLs, but preserve address space entropy.
            pbTry -= 0x08000000;
            continue;
        }

        if (!NT_SUCCESS(NtQueryVirtualMemory(NtCurrentProcess(),
                                             pbTry,
                                             MemoryBasicInformation,
                                             &mbi,
                                             sizeof(mbi),
                                             NULL)))
        {
            break;
        }

        DETOUR_TRACE("  Try %p => %p..%p %6lx\n",
                     pbTry,
                     mbi.BaseAddress,
                     Add2Ptr(mbi.BaseAddress, mbi.RegionSize - 1),
                     mbi.State);

        if (mbi.State == MEM_FREE && mbi.RegionSize >= DETOUR_REGION_SIZE)
        {
            pMem = pbTry;
            sMem = DETOUR_REGION_SIZE;
            Status = NtAllocateVirtualMemory(NtCurrentProcess(),
                                             &pMem,
                                             0,
                                             &sMem,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_EXECUTE_READWRITE);
            if (NT_SUCCESS(Status))
            {
                return pMem;
            } else if (Status == STATUS_DYNAMIC_CODE_BLOCKED)
            {
                return NULL;
            }
            pbTry -= DETOUR_REGION_SIZE;
        } else
        {
            pbTry = detour_alloc_round_down_to_region((PBYTE)mbi.AllocationBase - DETOUR_REGION_SIZE);
        }
    }
    return NULL;
}

static PVOID detour_alloc_trampoline_allocate_new(PBYTE pbTarget, PDETOUR_TRAMPOLINE pLo, PDETOUR_TRAMPOLINE pHi)
{
    PVOID pbTry = NULL;

    // NB: We must always also start the search at an offset from pbTarget
    //     in order to maintain ASLR entropy.

#if defined(_WIN64)
    // Try looking 1GB below or lower.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000)
    {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget - 0x40000000);
    }
    // Try looking 1GB above or higher.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget + 0x40000000, (PBYTE)pHi);
    }
    // Try looking 1GB below or higher.
    if (pbTry == NULL && pbTarget > (PBYTE)0x40000000)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget - 0x40000000, pbTarget);
    }
    // Try looking 1GB above or lower.
    if (pbTry == NULL && pbTarget < (PBYTE)0xffffffff40000000)
    {
        pbTry = detour_alloc_region_from_hi(pbTarget, pbTarget + 0x40000000);
    }
#endif

    // Try anything below.
    if (pbTry == NULL)
    {
        pbTry = detour_alloc_region_from_hi((PBYTE)pLo, pbTarget);
    }
    // try anything above.
    if (pbTry == NULL)
    {
        pbTry = detour_alloc_region_from_lo(pbTarget, (PBYTE)pHi);
    }

    return pbTry;
}

static PDETOUR_TRAMPOLINE detour_alloc_trampoline(PBYTE pbTarget)
{
    // We have to place trampolines within +/- 2GB of target.

    PDETOUR_TRAMPOLINE pLo;
    PDETOUR_TRAMPOLINE pHi;

    detour_find_jmp_bounds(pbTarget, &pLo, &pHi);

    PDETOUR_TRAMPOLINE pTrampoline = NULL;

    // Insure that there is a default region.
    if (s_pRegion == NULL && s_pRegions != NULL)
    {
        s_pRegion = s_pRegions;
    }

    // First check the default region for an valid free block.
    if (s_pRegion != NULL && s_pRegion->pFree != NULL &&
        s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi)
    {

found_region:
        pTrampoline = s_pRegion->pFree;
        // do a last sanity check on region.
        if (pTrampoline < pLo || pTrampoline > pHi)
        {
            return NULL;
        }
        s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pTrampoline->pbRemain;
        RtlFillMemory(pTrampoline, sizeof(*pTrampoline), 0xcc);
        return pTrampoline;
    }

    // Then check the existing regions for a valid free block.
    for (s_pRegion = s_pRegions; s_pRegion != NULL; s_pRegion = s_pRegion->pNext)
    {
        if (s_pRegion != NULL && s_pRegion->pFree != NULL && s_pRegion->pFree >= pLo && s_pRegion->pFree <= pHi)
        {
            goto found_region;
        }
    }

    // We need to allocate a new region.

    // Round pbTarget down to 64KB block.
    // /RTCc RuntimeChecks breaks PtrToUlong.
    pbTarget = pbTarget - (ULONG)((ULONG_PTR)pbTarget & 0xffff);

    PVOID pbNewlyAllocated = detour_alloc_trampoline_allocate_new(pbTarget, pLo, pHi);
    if (pbNewlyAllocated != NULL)
    {
        s_pRegion = (DETOUR_REGION*)pbNewlyAllocated;
        s_pRegion->dwSignature = DETOUR_REGION_SIGNATURE;
        s_pRegion->pFree = NULL;
        s_pRegion->pNext = s_pRegions;
        s_pRegions = s_pRegion;
        DETOUR_TRACE("  Allocated region %p..%p\n\n", s_pRegion, Add2Ptr(s_pRegion, DETOUR_REGION_SIZE - 1));

        // Put everything but the first trampoline on the free list.
        PBYTE pFree = NULL;
        pTrampoline = ((PDETOUR_TRAMPOLINE)s_pRegion) + 1;
        for (int i = DETOUR_TRAMPOLINES_PER_REGION - 1; i > 1; i--)
        {
            pTrampoline[i].pbRemain = pFree;
            pFree = (PBYTE)&pTrampoline[i];
        }
        s_pRegion->pFree = (PDETOUR_TRAMPOLINE)pFree;
        goto found_region;
    }

    DETOUR_TRACE("Couldn't find available memory region!\n");
    return NULL;
}

static void detour_free_trampoline(PDETOUR_TRAMPOLINE pTrampoline)
{
    PDETOUR_REGION pRegion = (PDETOUR_REGION)((ULONG_PTR)pTrampoline & ~(ULONG_PTR)0xffff);

    RtlZeroMemory(pTrampoline, sizeof(*pTrampoline));
    pTrampoline->pbRemain = (PBYTE)pRegion->pFree;
    pRegion->pFree = pTrampoline;
}

static BOOL detour_is_region_empty(PDETOUR_REGION pRegion)
{
    // Stop if the region isn't a region (this would be bad).
    if (pRegion->dwSignature != DETOUR_REGION_SIGNATURE)
    {
        return FALSE;
    }

    PBYTE pbRegionBeg = (PBYTE)pRegion;
    PBYTE pbRegionLim = pbRegionBeg + DETOUR_REGION_SIZE;

    // Stop if any of the trampolines aren't free.
    PDETOUR_TRAMPOLINE pTrampoline = ((PDETOUR_TRAMPOLINE)pRegion) + 1;
    for (int i = 0; i < DETOUR_TRAMPOLINES_PER_REGION; i++)
    {
        if (pTrampoline[i].pbRemain != NULL &&
            (pTrampoline[i].pbRemain < pbRegionBeg ||
             pTrampoline[i].pbRemain >= pbRegionLim))
        {
            return FALSE;
        }
    }

    // OK, the region is empty.
    return TRUE;
}

static void detour_free_unused_trampoline_regions()
{
    PVOID pMem;
    SIZE_T sMem;

    PDETOUR_REGION* ppRegionBase = &s_pRegions;
    PDETOUR_REGION pRegion = s_pRegions;

    while (pRegion != NULL)
    {
        if (detour_is_region_empty(pRegion))
        {
            *ppRegionBase = pRegion->pNext;

            pMem = pRegion;
            sMem = 0;
            NtFreeVirtualMemory(NtCurrentProcess(), &pMem, &sMem, MEM_RELEASE);
            s_pRegion = NULL;
        } else
        {
            ppRegionBase = &pRegion->pNext;
        }
        pRegion = *ppRegionBase;
    }
}

///////////////////////////////////////////////////////// Transaction Structs.
//
struct DetourThread
{
    DetourThread* pNext;
    HANDLE hThread;
};

struct DetourOperation
{
    DetourOperation* pNext;
    BOOL fIsRemove;
    PBYTE* ppbPointer;
    PBYTE pbTarget;
    PDETOUR_TRAMPOLINE pTrampoline;
    ULONG dwPerm;
};

static BOOL s_fIgnoreTooSmall = FALSE;
static BOOL s_fRetainRegions = FALSE;

static ULONG s_nPendingThreadId = 0; // Thread owning pending transaction.
static NTSTATUS s_nPendingError = STATUS_SUCCESS;
static PVOID* s_ppPendingError = NULL;
static DetourThread* s_pPendingThreads = NULL;
static DetourOperation* s_pPendingOperations = NULL;

//////////////////////////////////////////////////////////////////////////////
//
PVOID NTAPI DetourCodeFromPointer(_In_ PVOID pPointer, _Out_opt_ PVOID* ppGlobals)
{
    return detour_skip_jmp((PBYTE)pPointer, ppGlobals);
}

//////////////////////////////////////////////////////////// Transaction APIs.
//
NTSTATUS NTAPI DetourTransactionBegin()
{
    // Only one transaction is allowed at a time.
    _Benign_race_begin_
        if (s_nPendingThreadId != 0)
        {
            return STATUS_TRANSACTIONAL_CONFLICT;
        }
    _Benign_race_end_

        // Make sure only one thread can start a transaction.
        if (_InterlockedCompareExchange(&s_nPendingThreadId, CURRENT_THREAD_ID, 0) != 0)
        {
            return STATUS_TRANSACTIONAL_CONFLICT;
        }

    s_pPendingOperations = NULL;
    s_pPendingThreads = NULL;
    s_ppPendingError = NULL;

    // Make sure the trampoline pages are writable.
    s_nPendingError = detour_writable_trampoline_regions();

    return s_nPendingError;
}

NTSTATUS NTAPI DetourTransactionAbort()
{
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    if (s_nPendingThreadId != CURRENT_THREAD_ID)
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    // Restore all of the page permissions.
    for (DetourOperation* o = s_pPendingOperations; o != NULL;)
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

        DetourOperation* n = o->pNext;
        delete o;
        o = n;
    }
    s_pPendingOperations = NULL;

    // Make sure the trampoline pages are no longer writable.
    detour_runnable_trampoline_regions();

    // Resume any suspended threads.
    for (DetourThread* t = s_pPendingThreads; t != NULL;)
    {
        // There is nothing we can do if this fails.
        NtResumeThread(t->hThread, NULL);

        DetourThread* n = t->pNext;
        delete t;
        t = n;
    }
    s_pPendingThreads = NULL;
    s_nPendingThreadId = 0;

    return STATUS_SUCCESS;
}

NTSTATUS NTAPI DetourTransactionCommit()
{
    return DetourTransactionCommitEx(NULL);
}

static BYTE detour_align_from_trampoline(PDETOUR_TRAMPOLINE pTrampoline, BYTE obTrampoline)
{
    for (LONG n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++)
    {
        if (pTrampoline->rAlign[n].obTrampoline == obTrampoline)
        {
            return pTrampoline->rAlign[n].obTarget;
        }
    }
    return 0;
}

static LONG detour_align_from_target(PDETOUR_TRAMPOLINE pTrampoline, LONG obTarget)
{
    for (LONG n = 0; n < ARRAYSIZE(pTrampoline->rAlign); n++)
    {
        if (pTrampoline->rAlign[n].obTarget == obTarget)
        {
            return pTrampoline->rAlign[n].obTrampoline;
        }
    }
    return 0;
}

NTSTATUS NTAPI DetourTransactionCommitEx(_Out_opt_ PVOID** pppFailedPointer)
{
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    // Common variables.
    DetourOperation* o;
    DetourThread* t;
    BOOL freed = FALSE;

    if (pppFailedPointer != NULL)
    {
        // Used to get the last error.
        *pppFailedPointer = s_ppPendingError;
    }
    if (s_nPendingThreadId != CURRENT_THREAD_ID)
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    // If any of the pending operations failed, then we abort the whole transaction.
    if (s_nPendingError != STATUS_SUCCESS)
    {
        DETOUR_BREAK();
        DetourTransactionAbort();
        return s_nPendingError;
    }

    // Insert or remove each of the detours.
    for (o = s_pPendingOperations; o != NULL; o = o->pNext)
    {
        if (o->fIsRemove)
        {
            RtlCopyMemory(o->pbTarget, o->pTrampoline->rbRestore, o->pTrampoline->cbRestore);
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
            detour_gen_jmp_indirect(o->pTrampoline->rbCodeIn, &o->pTrampoline->pbDetour);
            PBYTE pbCode = detour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->rbCodeIn);
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#elif defined(_M_IX86)
            PBYTE pbCode = detour_gen_jmp_immediate(o->pbTarget, o->pTrampoline->pbDetour);
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#elif defined(_M_ARM64)
            PBYTE pbCode = detour_gen_jmp_indirect(o->pbTarget, (ULONG64*)&(o->pTrampoline->pbDetour));
            pbCode = detour_gen_brk(pbCode, o->pTrampoline->pbRemain);
            *o->ppbPointer = o->pTrampoline->rbCode;
            UNREFERENCED_PARAMETER(pbCode);
#endif

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
    }

    // Update any suspended threads.
    for (t = s_pPendingThreads; t != NULL; t = t->pNext)
    {
        CONTEXT cxt;
        cxt.ContextFlags = CONTEXT_CONTROL;

#undef DETOURS_EIP

#if defined(_M_IX86)
#define DETOURS_EIP Eip
#elif defined(_M_X64)
#define DETOURS_EIP Rip
#elif defined(_M_ARM64)
#define DETOURS_EIP Pc
#endif

        if (NT_SUCCESS(NtGetContextThread(t->hThread, &cxt)))
        {
            for (o = s_pPendingOperations; o != NULL; o = o->pNext)
            {
                if (o->fIsRemove)
                {
                    if (cxt.DETOURS_EIP >= (ULONG_PTR)o->pTrampoline &&
                        cxt.DETOURS_EIP < ((ULONG_PTR)o->pTrampoline + sizeof(o->pTrampoline)))
                    {

                        cxt.DETOURS_EIP = (ULONG_PTR)o->pbTarget +
                            detour_align_from_trampoline(o->pTrampoline,
                                                         (BYTE)(cxt.DETOURS_EIP - (ULONG_PTR)o->pTrampoline));

                        NtSetContextThread(t->hThread, &cxt);
                    }
                } else
                {
                    if (cxt.DETOURS_EIP >= (ULONG_PTR)o->pbTarget &&
                        cxt.DETOURS_EIP < ((ULONG_PTR)o->pbTarget + o->pTrampoline->cbRestore))
                    {

                        cxt.DETOURS_EIP = (ULONG_PTR)o->pTrampoline +
                            detour_align_from_target(o->pTrampoline, (BYTE)(cxt.DETOURS_EIP - (ULONG_PTR)o->pbTarget));

                        NtSetContextThread(t->hThread, &cxt);
                    }
                }
            }
        }
#undef DETOURS_EIP
    }

    // Restore all of the page permissions and flush the icache.
    for (o = s_pPendingOperations; o != NULL;)
    {
        // We don't care if this fails, because the code is still accessible.
        pMem = o->pbTarget;
        sMem = o->pTrampoline->cbRestore;
        NtProtectVirtualMemory(NtCurrentProcess(), &pMem, &sMem, o->dwPerm, &dwOld);
        NtFlushInstructionCache(NtCurrentProcess(), o->pbTarget, o->pTrampoline->cbRestore);

        if (o->fIsRemove && o->pTrampoline)
        {
            detour_free_trampoline(o->pTrampoline);
            o->pTrampoline = NULL;
            freed = true;
        }

        DetourOperation* n = o->pNext;
        delete o;
        o = n;
    }
    s_pPendingOperations = NULL;

    // Free any trampoline regions that are now unused.
    if (freed && !s_fRetainRegions)
    {
        detour_free_unused_trampoline_regions();
    }

    // Make sure the trampoline pages are no longer writable.
    detour_runnable_trampoline_regions();

    // Resume any suspended threads.
    for (t = s_pPendingThreads; t != NULL;)
    {
        // There is nothing we can do if this fails.
        NtResumeThread(t->hThread, NULL);

        DetourThread* n = t->pNext;
        delete t;
        t = n;
    }
    s_pPendingThreads = NULL;
    s_nPendingThreadId = 0;

    if (pppFailedPointer != NULL)
    {
        *pppFailedPointer = s_ppPendingError;
    }

    return s_nPendingError;
}

NTSTATUS NTAPI DetourUpdateThread(_In_ HANDLE hThread)
{
    NTSTATUS Status;

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != STATUS_SUCCESS)
    {
        return s_nPendingError;
    }

    // Silently (and safely) drop any attempt to suspend our own thread.
    if (hThread == NtCurrentThread())
    {
        return STATUS_SUCCESS;
    }

    DetourThread* t = new(std::nothrow) DetourThread;
    if (t == NULL)
    {
        Status = STATUS_NO_MEMORY;
fail:
        if (t != NULL)
        {
            delete t;
            t = NULL;
        }
        s_nPendingError = Status;
        s_ppPendingError = NULL;
        DETOUR_BREAK();
        return Status;
    }

    Status = NtSuspendThread(hThread, NULL);
    if (!NT_SUCCESS(Status))
    {
        DETOUR_BREAK();
        goto fail;
    }

    t->hThread = hThread;
    t->pNext = s_pPendingThreads;
    s_pPendingThreads = t;

    return STATUS_SUCCESS;
}

///////////////////////////////////////////////////////////// Transacted APIs.
//
NTSTATUS NTAPI DetourAttach(_Inout_ PVOID* ppPointer, _In_ PVOID pDetour)
{
    return DetourAttachEx(ppPointer, pDetour, NULL, NULL, NULL);
}

NTSTATUS NTAPI DetourAttachEx(
    _Inout_ PVOID* ppPointer,
    _In_ PVOID pDetour,
    _Out_opt_ PDETOUR_TRAMPOLINE* ppRealTrampoline,
    _Out_opt_ PVOID* ppRealTarget,
    _Out_opt_ PVOID* ppRealDetour)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    if (ppRealTrampoline != NULL)
    {
        *ppRealTrampoline = NULL;
    }
    if (ppRealTarget != NULL)
    {
        *ppRealTarget = NULL;
    }
    if (ppRealDetour != NULL)
    {
        *ppRealDetour = NULL;
    }
    if (pDetour == NULL)
    {
        DETOUR_TRACE("empty detour\n");
        return STATUS_INVALID_PARAMETER;
    }

    if (s_nPendingThreadId != CURRENT_THREAD_ID)
    {
        DETOUR_TRACE("transaction conflict with thread id=%lu\n", s_nPendingThreadId);
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != STATUS_SUCCESS)
    {
        DETOUR_TRACE("pending transaction error=%ld\n", s_nPendingError);
        return s_nPendingError;
    }

    if (ppPointer == NULL)
    {
        DETOUR_TRACE("ppPointer is null\n");
        return STATUS_INVALID_HANDLE;
    }
    if (*ppPointer == NULL)
    {
        Status = STATUS_INVALID_HANDLE;
        s_nPendingError = Status;
        s_ppPendingError = ppPointer;
        DETOUR_TRACE("*ppPointer is null (ppPointer=%p)\n", ppPointer);
        DETOUR_BREAK();
        return Status;
    }

    PBYTE pbTarget = (PBYTE)*ppPointer;
    PDETOUR_TRAMPOLINE pTrampoline = NULL;
    DetourOperation* o = NULL;

    pbTarget = (PBYTE)DetourCodeFromPointer(pbTarget, NULL);
    pDetour = DetourCodeFromPointer(pDetour, NULL);

    // Don't follow a jump if its destination is the target function.
    // This happens when the detour does nothing other than call the target.
    if (pDetour == (PVOID)pbTarget)
    {
        if (s_fIgnoreTooSmall)
        {
            goto stop;
        } else
        {
            DETOUR_BREAK();
            goto fail;
        }
    }

    if (ppRealTarget != NULL)
    {
        *ppRealTarget = pbTarget;
    }
    if (ppRealDetour != NULL)
    {
        *ppRealDetour = pDetour;
    }

    o = new(std::nothrow) DetourOperation;
    if (o == NULL)
    {
        Status = STATUS_NO_MEMORY;
fail:
        s_nPendingError = Status;
        DETOUR_BREAK();
stop:
        if (pTrampoline != NULL)
        {
            detour_free_trampoline(pTrampoline);
            pTrampoline = NULL;
            if (ppRealTrampoline != NULL)
            {
                *ppRealTrampoline = NULL;
            }
        }
        if (o != NULL)
        {
            delete o;
            o = NULL;
        }
        if (ppRealDetour != NULL)
        {
            *ppRealDetour = NULL;
        }
        if (ppRealTarget != NULL)
        {
            *ppRealTarget = NULL;
        }
        s_ppPendingError = ppPointer;
        return Status;
    }

    pTrampoline = detour_alloc_trampoline(pbTarget);
    if (pTrampoline == NULL)
    {
        Status = STATUS_NO_MEMORY;
        DETOUR_BREAK();
        goto fail;
    }

    if (ppRealTrampoline != NULL)
    {
        *ppRealTrampoline = pTrampoline;
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

        DETOUR_TRACE(" DetourCopyInstruction(%p,%p)\n", pbTrampoline, pbSrc);
        pbSrc = (PBYTE)DetourCopyInstruction(pbTrampoline, (PVOID*)&pbPool, pbSrc, NULL, &lExtra);
        DETOUR_TRACE(" DetourCopyInstruction() = %p (%d bytes)\n", pbSrc, (int)(pbSrc - pbOp));
        pbTrampoline += (pbSrc - pbOp) + lExtra;
        cbTarget = PtrOffset(pbTarget, pbSrc);
        pTrampoline->rAlign[nAlign].obTarget = cbTarget;
        pTrampoline->rAlign[nAlign].obTrampoline = pbTrampoline - pTrampoline->rbCode;
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
        if (s_fIgnoreTooSmall)
        {
            goto stop;
        } else
        {
            DETOUR_BREAK();
            goto fail;
        }
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
    pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);
#elif defined(_M_IX86)
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline, pTrampoline->pbRemain);
    pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);
#elif defined(_M_ARM64)
    pbTrampoline = detour_gen_jmp_immediate(pbTrampoline, &pbPool, pTrampoline->pbRemain);
    pbTrampoline = detour_gen_brk(pbTrampoline, pbPool);
#endif

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

NTSTATUS NTAPI DetourDetach(_Inout_ PVOID* ppPointer, _In_ PVOID pDetour)
{
    NTSTATUS Status = STATUS_SUCCESS;
    PVOID pMem;
    SIZE_T sMem;
    DWORD dwOld;

    if (s_nPendingThreadId != CURRENT_THREAD_ID)
    {
        return STATUS_TRANSACTIONAL_CONFLICT;
    }

    // If any of the pending operations failed, then we don't need to do this.
    if (s_nPendingError != STATUS_SUCCESS)
    {
        return s_nPendingError;
    }

    if (pDetour == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }
    if (ppPointer == NULL)
    {
        return STATUS_INVALID_HANDLE;
    }
    if (*ppPointer == NULL)
    {
        Status = STATUS_INVALID_HANDLE;
        s_nPendingError = Status;
        s_ppPendingError = ppPointer;
        DETOUR_BREAK();
        return Status;
    }

    DetourOperation* o = new(std::nothrow) DetourOperation;
    if (o == NULL)
    {
        Status = STATUS_NO_MEMORY;
fail:
        s_nPendingError = Status;
        DETOUR_BREAK();
stop:
        if (o != NULL)
        {
            delete o;
            o = NULL;
        }
        s_ppPendingError = ppPointer;
        return Status;
    }

    PDETOUR_TRAMPOLINE pTrampoline = (PDETOUR_TRAMPOLINE)DetourCodeFromPointer(*ppPointer, NULL);
    pDetour = DetourCodeFromPointer(pDetour, NULL);

    ////////////////////////////////////// Verify that Trampoline is in place.
    //
    LONG cbTarget = pTrampoline->cbRestore;
    PBYTE pbTarget = pTrampoline->pbRemain - cbTarget;
    if (cbTarget == 0 || cbTarget > sizeof(pTrampoline->rbCode))
    {
        Status = STATUS_INVALID_BLOCK_LENGTH;
        if (s_fIgnoreTooSmall)
        {
            goto stop;
        } else
        {
            DETOUR_BREAK();
            goto fail;
        }
    }

    if (pTrampoline->pbDetour != pDetour)
    {
        Status = STATUS_INVALID_BLOCK_LENGTH;
        if (s_fIgnoreTooSmall)
        {
            goto stop;
        } else
        {
            DETOUR_BREAK();
            goto fail;
        }
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
