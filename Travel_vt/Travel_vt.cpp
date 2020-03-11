#include "Travel_vt.h"

#include "vcpu.h"


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObj, IN PUNICODE_STRING pRegistryString)
{
	NTSTATUS		status = STATUS_SUCCESS;
	UNICODE_STRING  ustrLinkName;
	UNICODE_STRING  ustrDevName;
	PDEVICE_OBJECT  pDevObj;

	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;

	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;

	pDriverObj->DriverUnload = DriverUnload;

	RtlInitUnicodeString(&ustrDevName, NT_DEVICE_NAME);

	status = IoCreateDevice(pDriverObj,0,&ustrDevName,FILE_DEVICE_UNKNOWN,0,FALSE,&pDevObj);


	if (!NT_SUCCESS(status))
	{
		DebugPrintA("Error, IoCreateDevice = 0x%x\r\n", status);
		return status;
	}

	if (IoIsWdmVersionAvailable(1, 0x10))
	{
		RtlInitUnicodeString(&ustrLinkName, SYMBOLIC_LINK_GLOBAL_NAME);
	}
	else
	{
		RtlInitUnicodeString(&ustrLinkName, SYMBOLIC_LINK_NAME);
	}

	status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);

	if (!NT_SUCCESS(status))
	{
		DebugPrintA("Error, IoCreateSymbolicLink = 0x%x\r\n", status);

		IoDeleteDevice(pDevObj);
		return status;
	}

	vcpu_t vcpu;



//	vcpu.setup_host();
	vcpu.vmx_enter();

	DebugPrintA("Travel_vt DriverEntry Success \r\n");

	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriverObj)
{
	UNICODE_STRING strLink;

	RtlInitUnicodeString(&strLink, SYMBOLIC_LINK_NAME);
	IoDeleteSymbolicLink(&strLink);

	IoDeleteDevice(pDriverObj->DeviceObject);

	DebugPrintA("Unloaded Success\r\n");
 
	return;
}

NTSTATUS DispatchCreate(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}


NTSTATUS DispatchClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}



NTSTATUS DispatchDeviceControl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;	 // STATUS_UNSUCCESSFUL
	PIO_STACK_LOCATION pIrpStack = IoGetCurrentIrpStackLocation(pIrp);
	ULONG uIoControlCode = 0;
	PVOID pIoBuffer = NULL;
	ULONG uInSize = 0;
	ULONG uOutSize = 0;

	// Get the IoCtrl Code
	uIoControlCode = pIrpStack->Parameters.DeviceIoControl.IoControlCode;

	pIoBuffer = pIrp->AssociatedIrp.SystemBuffer;
	uInSize = pIrpStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutSize = pIrpStack->Parameters.DeviceIoControl.OutputBufferLength;

	switch (uIoControlCode)
	{
	case IOCTL_HELLO_WORLD:
	{
		DebugPrintA("IOCTL_HELLO_WORLD \r\n");
		status = STATUS_SUCCESS;
	}
	break;

	case IOCTRL_REC_FROM_APP:
	{
		DebugPrintA("IOCTRL_REC_FROM_APP \r\n");
		status = STATUS_SUCCESS;
	}
	break;

	case IOCTRL_SEND_TO_APP:
	{
		DebugPrintA("IOCTRL_SEND_TO_APP \r\n");
	}
	break;

	//
	// TODO: Add execute code here.
	//

	default:
	{
		// Invalid code sent
		DebugPrintA("Unknown IOCTL: 0x%X (%04X,%04X)\r\n",
			uIoControlCode,
			DEVICE_TYPE_FROM_CTL_CODE(uIoControlCode),
			IoGetFunctionCodeFromCtlCode(uIoControlCode));
		status = STATUS_INVALID_PARAMETER;
	}
	break;
	}

	if (status == STATUS_SUCCESS)
	{
		pIrp->IoStatus.Information = uOutSize;
	}
	else
	{
		pIrp->IoStatus.Information = 0;
	}

	// Complete the I/O Request
	pIrp->IoStatus.Status = status;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}
