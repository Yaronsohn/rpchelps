/* %%COPYRIGHT%% */

/* INCLUDES *******************************************************************/

#define INITGUID

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

static const GUID Key = 
{ 0x79cfd1bb, 0x5ce5, 0x4f09, { 0x9b, 0x70, 0xd5, 0xa6, 0x3f, 0xc, 0xda, 0x92 } };

/* FUNCTIONS ******************************************************************/ 

static
BOOL
FORCEINLINE
EncodeData(
    _Inout_opt_ PVOID Data,
    _Inout_ PDWORD DataLength
    )
{
    BOOL success = FALSE;
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hSessionKey;

    if (!CryptAcquireContextW(&hProv,
                              NULL,
                              MS_DEF_PROV_W,
                              PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
        goto leave0;

    if (!CryptHashData(hHash, (CONST BYTE *)&Key, sizeof(Key), 0))
        goto leave1;

    if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hSessionKey))
        goto leave1;

    /* Calculate the size of the cipher text */
    success = CryptEncrypt(hSessionKey,
                           0,
                           TRUE,
                           0,
                           (PBYTE)Data,
                           DataLength,
                           *DataLength);

    CryptDestroyKey(hSessionKey);
leave1:
    CryptDestroyHash(hHash);
leave0:
    CryptReleaseContext(hProv, 0);
    return success;
}

static
BOOL
FORCEINLINE
DecodeData(
    _In_ PBYTE CipherText,
    _Inout_ PDWORD TextLen
    )
{
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hSessionKey;
    BOOL success = FALSE;

    if (!CryptAcquireContextW(&hProv,
                              NULL,
                              MS_DEF_PROV_W,
                              PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
    {
        return FALSE;
    }

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
        goto leave0;

    if (!CryptHashData(hHash, (const BYTE *)&Key, sizeof(Key), 0))
        goto leave1;

    if (!CryptDeriveKey(hProv, CALG_RC4, hHash, 0, &hSessionKey))
        goto leave1;

    success = CryptDecrypt(hSessionKey,
                           0,
                           TRUE,
                           0,
                           CipherText,
                           TextLen);

    CryptDestroyKey(hSessionKey);
leave1:
    CryptDestroyHash(hHash);
leave0:
    CryptReleaseContext(hProv, 0);
    return success;
}

PXMIT_TYPE
WINAPI
XMITTYPE_TypeToXmit(
    _In_ ULONG Options,
    _In_opt_ CONST VOID *TypeData,
    _In_ ULONG Size
    )
{
    PXMIT_TYPE Xmit;
    ULONG XmitDataSize;

    /* Check how much data we actually have */
    if (TypeData)
    {
        XmitDataSize = Size;
    }
    else
    {
        XmitDataSize = 0;
    }

    /* We don't need to cypher zero-length buffers */
    if (!XmitDataSize)
    {
        Options &= ~XTO_ENCRYPTE;
    }

    if (Options & XTO_ENCRYPTE)
    {
        /* Get the cyphered data length */
        if (!EncodeData(NULL, &XmitDataSize))
        {
            RaiseNonContinuableException(GetLastError());
        }
    }

    Xmit = HeapAlloc(GetProcessHeap(), 0, sizeof(XMIT_TYPE) + XmitDataSize);
    if (!Xmit)
    {
        RaiseNonContinuableException(GetLastError());
    }

    Xmit->Options = 0;
    Xmit->Size = XmitDataSize;

    /* We need to copy the data - we will later encrypt it in place if needed */
    RtlCopyMemory(Xmit->Data, TypeData, min(Size, XmitDataSize));

    if (Options & XTO_ENCRYPTE)
    {
        Xmit->Options |= XTO_ENCRYPTE;

        if (!EncodeData(Xmit->Data, &Size))
        {
            HeapFree(GetProcessHeap(), 0, Xmit);
            RaiseNonContinuableException(GetLastError());
        }
    }

    return Xmit;
}

VOID
WINAPI
XMITTYPE_XmitToType(
    _In_ PXMIT_TYPE Xmit,
    _Out_ PVOID *Type
    )
{
    if (Xmit->Size)
    {
        *Type = HeapAlloc(GetProcessHeap(), 0, Xmit->Size);
        if (*Type == NULL)
        {
            RaiseNonContinuableException(GetLastError());
        }

        RtlCopyMemory(*Type, Xmit->Data, Xmit->Size);

        if (Xmit->Options & XTO_ENCRYPTE)
        {
            if (!DecodeData(*Type, &Xmit->Size))
            {
                HeapFree(GetProcessHeap(), 0, *Type);
                RaiseNonContinuableException(GetLastError());
            }
        }
    }
    else
    {
        *Type = NULL;
    }
}

VOID
WINAPI
XMITTYPE_FreeType(
    _In_opt_ PVOID *Type
    )
{
    if (*Type)
    {
        HeapFree(GetProcessHeap(), 0, *Type);
    }
}

VOID
WINAPI
XMITTYPE_FreeXmit(
    _In_opt_ XMIT_TYPE *Xmit
    )
{
    if (Xmit)
    {
        HeapFree(GetProcessHeap(), 0, Xmit);
    }
}
