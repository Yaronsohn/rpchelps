/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#if defined(_M_IA64) || defined(_M_AMD64)
#ifdef DEBUG
#include "debug\x64\rpchelp_h.h"
#else
#include "release\x64\rpchelp_h.h"
#endif
#else
#ifdef DEBUG
#include "debug\Win32\rpchelp_h.h"
#else
#include "release\Win32\rpchelp_h.h"
#endif
#endif

/* FUNCTIONS ******************************************************************/ 

static
SIZE_T
FORCEINLINE
MultiStrSizeW(
    _In_ LPCWSTR str
    )
{
    SIZE_T size = 0;

    do
    {
        do
        {
            size++;
        } while (*str++);

        size++;

    } while (*str++);

    return (size + 1) * sizeof(WCHAR);
}

void
__RPC_USER
LPMULTIWSTR_to_xmit(
    _In_ LPMULTIWSTR *MultiString,
    _Out_ XMIT_TYPE **Xmit
    )
{
    SIZE_T size = *MultiString ? MultiStrSizeW(*MultiString) : 0;

    if (size > MAXDWORD)
    {
        RaiseNonContinuableException(RPC_S_STRING_TOO_LONG);
    }

    *Xmit = XMITTYPE_TypeToXmit(0, *MultiString, (ULONG)size);
}

VOID
WINAPI
LPMULTIWSTR_from_xmit(
    _In_ PXMIT_TYPE Xmit,
    _Out_ LPMULTIWSTR *Type
    )
{
    XMITTYPE_XmitToType(Xmit, (PVOID *)Type);
}

VOID
WINAPI
LPMULTIWSTR_free_inst(
    _In_opt_ LPMULTIWSTR *Type
    )
{
    XMITTYPE_FreeType((PVOID *)Type);
}

VOID
WINAPI
LPMULTIWSTR_free_xmit(
    _In_opt_ XMIT_TYPE *Xmit
    )
{
    XMITTYPE_FreeXmit(Xmit);
}

static
SIZE_T
FORCEINLINE
MultiStrSizeA(
    _In_ LPCSTR str
    )
{
    SIZE_T size = 0;

    do
    {
        do
        {
            size++;
        } while (*str++);

        size++;

    } while (*str++);

    return size + 1;
}

void
__RPC_USER
LPMULTISTR_to_xmit(
    _In_ LPMULTISTR *MultiString,
    _Out_ XMIT_TYPE **Xmit
    )
{
    SIZE_T size = *MultiString ? MultiStrSizeA(*MultiString) : 0;

    if (size > MAXDWORD)
    {
        RaiseNonContinuableException(RPC_S_STRING_TOO_LONG);
    }

    *Xmit = XMITTYPE_TypeToXmit(0, *MultiString, (ULONG)size);
}

VOID
WINAPI
LPMULTISTR_from_xmit(
    _In_ PXMIT_TYPE Xmit,
    _Out_ LPMULTISTR *Type
    )
{
    XMITTYPE_XmitToType(Xmit, (PVOID *)Type);
}

VOID
WINAPI
LPMULTISTR_free_inst(
    _In_opt_ LPMULTISTR *Type
    )
{
    XMITTYPE_FreeType((PVOID *)Type);
}

VOID
WINAPI
LPMULTISTR_free_xmit(
    _In_opt_ XMIT_TYPE *Xmit
    )
{
    XMITTYPE_FreeXmit(Xmit);
}