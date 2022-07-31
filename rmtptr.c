/* %%COPYRIGHT%% */

#if !defined(_WIN32)
#error ERROR! Platform not supported!
#endif

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

/* GLOBALS ********************************************************************/

ULONG_PTR PointerSalt = 0;

/* FUNCTIONS ******************************************************************/

void
__RPC_USER
LPREMOTE_POINTER_to_xmit(
    _In_ LPREMOTE_POINTER *RemotePointer,
    _Out_ XMIT_TYPE **Xmit
    )
{
    ULONG size = 0;
    ULONG_PTR ptr = 0;

    if (*RemotePointer)
    {
        ptr = ((ULONG_PTR)*RemotePointer) ^ PointerSalt;

#ifdef _WIN64
        if (ptr & 0xFFFFFFFF00000000)
        {
            size = sizeof(ULONG64);
        }
        else
        {
#endif
            size = sizeof(ULONG);
#ifdef _WIN64
        }
#endif
    }

    *Xmit = XMITTYPE_TypeToXmit(0, &ptr, size);
}

void
__RPC_USER
LPREMOTE_POINTER_from_xmit(
    _In_ XMIT_TYPE *Xmit,
    _Out_ LPREMOTE_POINTER *RemotePointer
    )
{
    switch (Xmit->Size)
    {
    case 0: *RemotePointer = NULL; break;
    case sizeof(ULONG): *RemotePointer = (PVOID)(((ULONG_PTR)*((PULONG)Xmit->Data)) ^ PointerSalt); break;
#ifdef _WIN64
    case sizeof(ULONG64): *RemotePointer = (PVOID)(*((PULONG64)Xmit->Data) ^ PointerSalt); break;
#endif
    default:
        RaiseNonContinuableException(ERROR_NOT_SUPPORTED);
    }
}

void
__RPC_USER
LPREMOTE_POINTER_free_inst(
    _Inout_ LPREMOTE_POINTER *RemotePointer
    )
{
}

void
__RPC_USER
LPREMOTE_POINTER_free_xmit(
    _In_ XMIT_TYPE  *Xmit
    )
{
    XMITTYPE_FreeXmit(Xmit);
}