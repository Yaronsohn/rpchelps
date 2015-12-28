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

typedef struct _XMIT_OBJECT_ATTRIBUTES {
    ULONG Length;
    ULONG RootDirectory;
    ULONG ObjectName;
    ULONG Attributes;
    ULONG SecurityDescriptor;
    ULONG SecurityQualityOfService;
} XMIT_OBJECT_ATTRIBUTES, *PXMIT_OBJECT_ATTRIBUTES;

void
__RPC_USER
OBJECT_ATTRIBUTES_to_xmit(
    _In_ OBJECT_ATTRIBUTES *ObjectAttributes,
    _Out_ XMIT_TYPE **Xmit
    )
{
    ULONG TotalSize = 0;
    PUNICODE_STRING Name = NULL;
    ULONG NameLength = 0;
    PSECURITY_DESCRIPTOR SecDesc = NULL;
    ULONG SecDescLength = 0;
    PSECURITY_QUALITY_OF_SERVICE SecQos = NULL;
    ULONG SecQosLength = 0;
    PXMIT_OBJECT_ATTRIBUTES XmitOA = NULL;
    PVOID ptr;

    if (ObjectAttributes->Length != sizeof(OBJECT_ATTRIBUTES))
    {
        RaiseNonContinuableException(ERROR_INVALID_PARAMETER);
    }

    Name = ObjectAttributes->ObjectName;
    if (Name)
    {
        NameLength = Name->Length;
    }

    SecDesc = ObjectAttributes->SecurityDescriptor;
    if (SecDesc)
    {
        if (!MakeSelfRelativeSD(SecDesc, NULL, &SecDescLength))
        {
            RaiseNonContinuableException(GetLastError());
        }
    }

    SecQos = ObjectAttributes->SecurityQualityOfService;
    if (SecQos)
    {
        SecQosLength = SecQos->Length;
    }

    TotalSize = sizeof(XMIT_OBJECT_ATTRIBUTES) +
        NameLength +
        SecDescLength +
        SecQosLength;
    XmitOA = MIDL_user_allocate(TotalSize);
    if (!XmitOA)
    {
        RaiseNonContinuableException(GetLastError());
    }

    ptr = RtlOffsetToPointer(XmitOA, sizeof(XMIT_OBJECT_ATTRIBUTES));

    XmitOA->Length = ObjectAttributes->Length;
    XmitOA->RootDirectory = (ULONG)ObjectAttributes->RootDirectory;
    if (Name)
    {
        XmitOA->ObjectName = RtlPointerToOffset(XmitOA, ptr);
        RtlCopyMemory(ptr, Name->Buffer, NameLength);
        ptr = RtlOffsetToPointer(ptr, NameLength);
    }
    else
    {
        XmitOA->ObjectName = -1;
    }

    XmitOA->Attributes = ObjectAttributes->Attributes;

    if (SecDesc)
    {
        XmitOA->SecurityDescriptor = RtlPointerToOffset(XmitOA, ptr);
        MakeSelfRelativeSD(SecDesc,
                            ptr,
                            &SecDescLength);
        ptr = RtlOffsetToPointer(ptr, SecDescLength);
    }
    else
    {
        XmitOA->SecurityDescriptor = -1;
    }

    if (SecQos)
    {
        XmitOA->SecurityQualityOfService = RtlPointerToOffset(XmitOA, ptr);
        RtlCopyMemory(ptr, SecQos, SecQosLength);
        ptr = RtlOffsetToPointer(ptr, SecQosLength);
    }
    else
    {
        XmitOA->SecurityQualityOfService = -1;
    }

    __try
    {
        *Xmit = XMITTYPE_TypeToXmit(0, XmitOA, TotalSize);
    }
    __finally
    {
        MIDL_user_free(XmitOA);
    }
}

void
__RPC_USER
OBJECT_ATTRIBUTES_free_inst(
    _Inout_ OBJECT_ATTRIBUTES *ObjectAttributes
    )
{
    if (ObjectAttributes->ObjectName)
    {
        if (ObjectAttributes->ObjectName->Buffer)
        {
            RtlFreeUnicodeString(ObjectAttributes->ObjectName);
        }

        MIDL_user_free(ObjectAttributes->ObjectName);
    }

    if (ObjectAttributes->SecurityDescriptor)
    {
        MIDL_user_free(ObjectAttributes->SecurityDescriptor);
    }

    if (ObjectAttributes->SecurityQualityOfService)
    {
        MIDL_user_free(ObjectAttributes->SecurityQualityOfService);
    }
}

void
__RPC_USER
OBJECT_ATTRIBUTES_from_xmit(
    _In_ XMIT_TYPE *Xmit,
    _Out_ OBJECT_ATTRIBUTES *ObjectAttributes
    )
{
    PXMIT_OBJECT_ATTRIBUTES XmitOA = (PXMIT_OBJECT_ATTRIBUTES)Xmit->Data;
    NTSTATUS Status;
    PVOID ptr = (XmitOA + 1);

    RtlZeroMemory(ObjectAttributes, sizeof(*ObjectAttributes));
    ObjectAttributes->Length = XmitOA->Length;
    ObjectAttributes->RootDirectory = (HANDLE)XmitOA->RootDirectory;

    if (XmitOA->ObjectName != -1)
    {
        PUNICODE_STRING NameString;

        NameString = MIDL_user_allocate(sizeof(UNICODE_STRING));
        if (!NameString)
        {
            OBJECT_ATTRIBUTES_free_inst(ObjectAttributes);
            RaiseNonContinuableException(GetLastError());
        }

        NameString->Buffer = NULL;

        ObjectAttributes->ObjectName = NameString;

        Status = RtlAllocateUnicodeString(NameString,
                                          XmitOA->ObjectName + sizeof(WCHAR),
                                          FALSE);
        if (!NT_SUCCESS(Status))
        {
            OBJECT_ATTRIBUTES_free_inst(ObjectAttributes);
            RaiseNonContinuableException(Status);
        }

        NameString->Length = (USHORT)XmitOA->ObjectName;
        RtlCopyMemory(NameString->Buffer, ptr, XmitOA->ObjectName);
        RtlTerminateUnicodeString(NameString);

        ptr = RtlOffsetToPointer(ptr, XmitOA->ObjectName);
    }
    else
    {
        ObjectAttributes->ObjectName = NULL;
    }

    ObjectAttributes->Attributes = XmitOA->Attributes;

    if (XmitOA->SecurityDescriptor != -1)
    {
        if (XmitOA->SecurityDescriptor < sizeof(SECURITY_DESCRIPTOR))
        {
            OBJECT_ATTRIBUTES_free_inst(ObjectAttributes);
            RaiseNonContinuableException(ERROR_INVALID_PARAMETER);
        }

        ObjectAttributes->SecurityDescriptor = MIDL_user_allocate(XmitOA->SecurityDescriptor);
        if (!ObjectAttributes->SecurityDescriptor)
        {
            OBJECT_ATTRIBUTES_free_inst(ObjectAttributes);
            RaiseNonContinuableException(GetLastError());
        }

        RtlCopyMemory(ObjectAttributes->SecurityDescriptor,
                      ptr,
                      XmitOA->SecurityDescriptor);
        if (!RtlValidSecurityDescriptor(ObjectAttributes->SecurityDescriptor))
        {
            OBJECT_ATTRIBUTES_free_inst(ObjectAttributes);
            RaiseNonContinuableException(STATUS_INVALID_SECURITY_DESCR);
        }

        ptr = RtlOffsetToPointer(ptr, XmitOA->SecurityDescriptor);
    }
    else
    {
        ObjectAttributes->SecurityDescriptor = NULL;
    }

    if (XmitOA->SecurityQualityOfService != -1)
    {
        if (XmitOA->SecurityQualityOfService < sizeof(SECURITY_QUALITY_OF_SERVICE))
        {
            OBJECT_ATTRIBUTES_free_inst(ObjectAttributes);
            RaiseNonContinuableException(ERROR_INVALID_PARAMETER);
        }

        ObjectAttributes->SecurityQualityOfService = MIDL_user_allocate(sizeof(SECURITY_QUALITY_OF_SERVICE));
        if (!ObjectAttributes->SecurityQualityOfService)
        {
            OBJECT_ATTRIBUTES_free_inst(ObjectAttributes);
            RaiseNonContinuableException(GetLastError());
        }

        RtlCopyMemory(ObjectAttributes->SecurityQualityOfService,
                      ptr,
                      XmitOA->SecurityQualityOfService);
    }
    else
    {
        ObjectAttributes->SecurityQualityOfService = NULL;
    }
}

VOID
WINAPI
OBJECT_ATTRIBUTES_free_xmit(
    _In_opt_ XMIT_TYPE *Xmit
    )
{
    XMITTYPE_FreeXmit(Xmit);
}
