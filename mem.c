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

void __RPC_FAR *
__RPC_USER
MIDL_user_allocate(size_t cBytes)
{
    return HeapAlloc(GetProcessHeap(), 0, cBytes);
}

void
__RPC_USER
MIDL_user_free(void * pBuffer)
{
    HeapFree(GetProcessHeap(), 0, pBuffer);
}
