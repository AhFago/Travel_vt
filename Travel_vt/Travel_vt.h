
#pragma once
#ifdef __cplusplus
extern "C" {
#endif



    // #include <ntddk.h>
#include <devioctl.h>
#include "common.h"



#define __CPLUSPLUS

    NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString);
    VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj);
    NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
    NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
    NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);


#ifdef ALLOC_PRAGMA
    // Allow the DriverEntry routine to be discarded once initialization is completed
#pragma alloc_text(INIT, DriverEntry)
    // 
#pragma alloc_text(PAGE, DriverUnload)
#pragma alloc_text(PAGE, DispatchCreate)
#pragma alloc_text(PAGE, DispatchClose)
#pragma alloc_text(PAGE, DispatchDeviceControl)

#endif // ALLOC_PRAGMA





























#ifdef __cplusplus
}
#endif
