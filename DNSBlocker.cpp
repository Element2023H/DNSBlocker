#include <ndis.h>
#include <ntddk.h>
#include "Lazy.hpp"
#include "Headers.h"
#include "Callouts.h"

LazyInstance<GlobalData> g_pGlobalData;

VOID
DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	LazyInstance<Callouts>::Dispose();

	UNICODE_STRING ustrSymbolicLink{};
	RtlInitUnicodeString(&ustrSymbolicLink, BLOCK_SYMLINK_NAME);

	IoDeleteSymbolicLink(&ustrSymbolicLink);
	if (g_pGlobalData->pDeviceObject)
	{
		IoDeleteDevice(g_pGlobalData->pDeviceObject);
	}

	LazyInstance<GlobalData>::Dispose();
}

VOID NTAPI
BfeStateCallback(
	IN OUT void* context,
	IN FWPM_SERVICE_STATE  newState)
{
	UNREFERENCED_PARAMETER(context);

	if (newState == FWPM_SERVICE_RUNNING)
	{
		NTSTATUS status = lazyCallouts->CalloutsInit(g_pGlobalData->pDeviceObject);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("bfeStateCallback callouts_init failed, status=%x\n", status));
		}
	}
}

EXTERN_C
NTSTATUS 
DriverEntry(
	IN PDRIVER_OBJECT DriverObject, 
	IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	// DbgBreakPoint();

	NTSTATUS status{ STATUS_SUCCESS };
	// initialize g_pGlobalData
	LazyInstance<GlobalData>::Force([DriverObject]() {
		auto data = new(NonPagedPoolNx) GlobalData{};

		if (!data)
		{
			return (GlobalData*)nullptr;
		}

		// set driver object
		data->pDriverObject = DriverObject;
		return data;
		});

	if (!g_pGlobalData)
	{
		DbgPrint("g_pGlobalData alloc failed\r\n");
		return STATUS_NO_MEMORY;
	}

	DriverObject->DriverUnload = DriverUnload;


	// create device 
	UNICODE_STRING ustrDeviceName{};
	RtlInitUnicodeString(&ustrDeviceName, BLOCK_DEVICE_NAME);
	UNICODE_STRING ustrSymbolicLink{};
	RtlInitUnicodeString(&ustrSymbolicLink, BLOCK_SYMLINK_NAME);

	status = IoCreateDevice(g_pGlobalData->pDriverObject,
							0,
							&ustrDeviceName,
							FILE_DEVICE_UNKNOWN,
							FILE_DEVICE_SECURE_OPEN,
							FALSE,
							&g_pGlobalData->pDeviceObject);
	if (NT_SUCCESS(status))
	{
		status = IoCreateSymbolicLink(&ustrSymbolicLink, &ustrDeviceName);
	}

	if (!NT_SUCCESS(status))
	{
#if DBG
		DbgBreakPoint();
#endif
	}


	if (FWPM_SERVICE_RUNNING == FwpmBfeStateGet())
	{
		status = lazyCallouts->CalloutsInit(g_pGlobalData->pDeviceObject);
	}
	else
	{
		status = FwpmBfeStateSubscribeChanges(g_pGlobalData->pDeviceObject,
											  BfeStateCallback,
											  NULL,
											  &g_pGlobalData->hBfeStateSubscribe);

	}

	return status;
}