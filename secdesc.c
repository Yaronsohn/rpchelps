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

/* FUNCTIONS ******************************************************************/

void
__RPC_USER
SECURITY_DESCRIPTOR_to_xmit(
    _In_ SECURITY_DESCRIPTOR *SecurityDescriptor,
    _Out_ XMIT_TYPE **Xmit
    )
{
    ULONG size = 0;
    PISECURITY_DESCRIPTOR RelativeSD = NULL;

    if (SecurityDescriptor)
    {
        /* Calculate the size of a relative SD version */
        if (!MakeSelfRelativeSD(SecurityDescriptor, NULL, &size))
        {
            RaiseNonContinuableException(GetLastError());
        }

        RelativeSD = MIDL_user_allocate(size);
        if (!RelativeSD)
        {
            RaiseNonContinuableException(RPC_S_OUT_OF_MEMORY);
        }

        if (!MakeSelfRelativeSD(SecurityDescriptor, RelativeSD, &size))
        {
            MIDL_user_free(RelativeSD);
            RaiseNonContinuableException(RPC_S_OUT_OF_MEMORY);
        }
    }

    __try
    {
        *Xmit = XMITTYPE_TypeToXmit(0, RelativeSD, (ULONG)size);
    }
    __finally
    {
        MIDL_user_free(RelativeSD);
    }
}

void
__RPC_USER
SECURITY_DESCRIPTOR_from_xmit(
    _In_ XMIT_TYPE *Xmit,
    _Out_ SECURITY_DESCRIPTOR *SecurityDescriptor
    )
{
    PSECURITY_DESCRIPTOR SelfRelative = (PSECURITY_DESCRIPTOR)Xmit->Data;
    ULONG AbsoluteSDSize;
    ULONG DaclSize;
    ULONG SaclSize;
    ULONG OwnerSize;
    ULONG PrimaryGroupSize;
    PACL Dacl = NULL;
    PACL Sacl = NULL;
    PSID Owner = NULL;
    PSID PrimaryGroup = NULL;

    if (!IsValidSecurityDescriptor(SelfRelative))
    {
        RaiseNonContinuableException(ERROR_INVALID_SECURITY_DESCR);
    }

    AbsoluteSDSize = sizeof(SECURITY_DESCRIPTOR);
    DaclSize = 0;
    SaclSize = 0;
    OwnerSize = 0;
    PrimaryGroupSize = 0;
    if (!MakeAbsoluteSD(SelfRelative,
                        NULL,
                        &AbsoluteSDSize,
                        NULL,
                        &DaclSize,
                        NULL,
                        &SaclSize,
                        NULL,
                        &OwnerSize,
                        NULL,
                        &PrimaryGroupSize))
    {
        DWORD ret = GetLastError();

        if (ret != ERROR_INSUFFICIENT_BUFFER)
        {
            RaiseNonContinuableException(ret);
        }
    }

    if (DaclSize)
    {
        Dacl = MIDL_user_allocate(DaclSize);
        if (!Dacl)
            goto OutOfMemory;
    }

    if (SaclSize)
    {
        Sacl = MIDL_user_allocate(SaclSize);
        if (!Sacl)
            goto OutOfMemory;
    }

    if (OwnerSize)
    {
        Owner = MIDL_user_allocate(OwnerSize);
        if (!Owner)
            goto OutOfMemory;
    }

    if (PrimaryGroupSize)
    {
        PrimaryGroup = MIDL_user_allocate(PrimaryGroupSize);
        if (!PrimaryGroup)
            goto OutOfMemory;
    }

    MakeAbsoluteSD(SelfRelative,
                   SecurityDescriptor,
                   &AbsoluteSDSize,
                   Dacl,
                   &DaclSize,
                   Sacl,
                   &SaclSize,
                   Owner,
                   &OwnerSize,
                   PrimaryGroup,
                   &PrimaryGroupSize);
    return;

OutOfMemory:
    if (Dacl)
    {
        MIDL_user_free(Dacl);
    }

    if (Sacl)
    {
        MIDL_user_free(Sacl);
    }

    if (Owner)
    {
        MIDL_user_free(Owner);
    }

    if (PrimaryGroup)
    {
        MIDL_user_free(PrimaryGroup);
    }

    RaiseNonContinuableException(ERROR_OUTOFMEMORY);
}

void
__RPC_USER
SECURITY_DESCRIPTOR_free_inst(
    _Inout_ SECURITY_DESCRIPTOR *SecurityDescriptor
    )
{
    BOOL Present;
    BOOL Defaulted;
    PACL Acl;
    PSID Sid;
    BOOL Success;

    Success = GetSecurityDescriptorDacl(SecurityDescriptor,
                                        &Present,
                                        &Acl,
                                        &Defaulted);
    if (Success && Present && Acl)
    {
        MIDL_user_free(Acl);
    }

    Success = GetSecurityDescriptorSacl(SecurityDescriptor,
                                        &Present,
                                        &Acl,
                                        &Defaulted);
    if (Success && Present && Acl)
    {
        MIDL_user_free(Acl);
    }

    Success = GetSecurityDescriptorOwner(SecurityDescriptor, &Sid, &Defaulted);
    if (Success && Sid)
    {
        MIDL_user_free(Sid);
    }

    Success = GetSecurityDescriptorGroup(SecurityDescriptor, &Sid, &Defaulted);
    if (Success && Sid)
    {
        MIDL_user_free(Sid);
    }
}

void
__RPC_USER
SECURITY_DESCRIPTOR_free_xmit(
    _In_ XMIT_TYPE  *Xmit
    )
{
    XMITTYPE_FreeXmit(Xmit);
}
