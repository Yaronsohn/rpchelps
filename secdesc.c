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
        SECURITY_DESCRIPTOR_CONTROL Control;
        DWORD dwRevision;

        //
        // Make sure we've dealing with a valid descriptor.
        //
        if (!IsValidSecurityDescriptor(SecurityDescriptor))
        {
            RaiseNonContinuableException(ERROR_INVALID_SECURITY_DESCR);
        }

        if (!GetSecurityDescriptorControl(SecurityDescriptor, &Control, &dwRevision))
        {
            RaiseNonContinuableException(GetLastError());
        }

        //
        // If the descriptor is already in a self-relative form, simply pass the original
        // pointer.
        //
        if ((Control & SE_SELF_RELATIVE) == 0)
        {
            /* Calculate the size of a relative SD version */
            if (!MakeSelfRelativeSD(SecurityDescriptor, NULL, &size)
                &&
                GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            {
                RaiseNonContinuableException(GetLastError());
            }

            RelativeSD = MIDL_user_allocate(size);
            if (!RelativeSD)
            {
                RaiseNonContinuableException(GetLastError());
            }

            if (!MakeSelfRelativeSD(SecurityDescriptor, RelativeSD, &size))
            {
                MIDL_user_free(RelativeSD);
                RaiseNonContinuableException(GetLastError());
            }
        }
        else
        {
            size = GetSecurityDescriptorLength(SecurityDescriptor);
            RelativeSD = SecurityDescriptor;
        }
    }

    __try
    {
        *Xmit = XMITTYPE_TypeToXmit(0, RelativeSD, (ULONG)size);
    }
    __finally
    {
        if (RelativeSD && RelativeSD != SecurityDescriptor)
        {
            MIDL_user_free(RelativeSD);
        }
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
        if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            RaiseNonContinuableException(GetLastError());
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
