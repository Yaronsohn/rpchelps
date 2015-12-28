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

#pragma intrinsic(strlen)
#pragma intrinsic(wcslen)

void
__RPC_USER
LPCONFIDENTIALWSTR_to_xmit(
    _In_ LPCONFIDENTIALWSTR *String,
    _Out_ XMIT_TYPE **Xmit
    )
{
    SIZE_T size = *String ? (wcslen(*String) + 1) * sizeof(WCHAR) : 0;

    if (size > MAXDWORD)
    {
        RaiseNonContinuableException(RPC_S_STRING_TOO_LONG);
    }

    *Xmit = XMITTYPE_TypeToXmit(XTO_ENCRYPTE, *String, (ULONG)size);
    if (*Xmit == NULL)
    {
        RaiseNonContinuableException(RPC_S_OUT_OF_MEMORY);
    }
}

VOID
WINAPI
LPCONFIDENTIALWSTR_from_xmit(
    _In_ PXMIT_TYPE Xmit,
    _Out_ LPCONFIDENTIALWSTR *Type
    )
{
    XMITTYPE_XmitToType(Xmit, (PVOID *)Type);
}

VOID
WINAPI
LPCONFIDENTIALWSTR_free_inst(
    _In_opt_ LPCONFIDENTIALWSTR *Type
    )
{
    XMITTYPE_FreeType((PVOID *)Type);
}

VOID
WINAPI
LPCONFIDENTIALWSTR_free_xmit(
    _In_opt_ XMIT_TYPE *Xmit
    )
{
    XMITTYPE_FreeXmit(Xmit);
}

void
__RPC_USER
LPCONFIDENTIALSTR_to_xmit(
    LPCONFIDENTIALSTR *String,
    XMIT_TYPE **Xmit
    )
{
    SIZE_T size = *String ? (strlen(*String) + 1) : 0;

    if (size > MAXDWORD)
    {
        RaiseNonContinuableException(RPC_S_STRING_TOO_LONG);
    }

    *Xmit = XMITTYPE_TypeToXmit(XTO_ENCRYPTE, *String, (ULONG)size);
    if (*Xmit == NULL)
    {
        RaiseNonContinuableException(RPC_S_OUT_OF_MEMORY);
    }
}

VOID
WINAPI
LPCONFIDENTIALSTR_from_xmit(
    _In_ PXMIT_TYPE Xmit,
    _Out_ LPCONFIDENTIALSTR *Type
    )
{
    XMITTYPE_XmitToType(Xmit, (PVOID *)Type);
}

VOID
WINAPI
LPCONFIDENTIALSTR_free_inst(
    _In_opt_ LPCONFIDENTIALSTR *Type
    )
{
    XMITTYPE_FreeType((PVOID *)Type);
}

VOID
WINAPI
LPCONFIDENTIALSTR_free_xmit(
    _In_opt_ XMIT_TYPE *Xmit
    )
{
    XMITTYPE_FreeXmit(Xmit);
}
