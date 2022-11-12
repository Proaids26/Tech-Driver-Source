#include "IOCTL_Define.h"
#include "RemoveTrace.h"

PEPROCESS AttachedProcess;
NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);

EXTERN_C
NTSTATUS
NTAPI
PsAcquireProcessExitSynchronization(
	_In_ PEPROCESS Process
);

EXTERN_C
VOID
NTAPI
PsReleaseProcessExitSynchronization(
	_In_ PEPROCESS Process
);

NTKERNELAPI NTSTATUS NTAPI MmCopyVirtualMemory(
	IN PEPROCESS FromProcess,
	IN PVOID FromAddress,
	IN PEPROCESS ToProcess,
	OUT PVOID ToAddress,
	IN SIZE_T BufferSize,
	IN KPROCESSOR_MODE PreviousMode,
	OUT PSIZE_T NumberOfBytesCopied
);

NTSTATUS
ReadVirtualMemory(
	HANDLE ProcessId,
	ULONG_PTR Address,
	PVOID pBuffer,
	ULONG cbBuffer,
	PULONG pcbRead
)
{
	PEPROCESS pProcess = NULL;
	BOOLEAN fHasProcessReference = FALSE;
	BOOLEAN fHasProcessExitSynchronization = FALSE;
	KAPC_STATE ApcState;
	NTSTATUS ntstatus = STATUS_SUCCESS;

	if (ARGUMENT_PRESENT(pcbRead))
	{
		*pcbRead = 0;
	}

	if (Address + cbBuffer < Address ||
		Address + cbBuffer > (ULONG_PTR)MmHighestUserAddress ||
		Address + cbBuffer > (ULONG_PTR)MmHighestUserAddress)
	{
		ntstatus = STATUS_ACCESS_VIOLATION;
		goto exit;
	}

	ntstatus = PsLookupProcessByProcessId(ProcessId, &pProcess);
	if (!NT_SUCCESS(ntstatus))
	{
		goto exit;
	}

	fHasProcessReference = TRUE;

	ntstatus = PsAcquireProcessExitSynchronization(pProcess);
	if (!NT_SUCCESS(ntstatus))
	{
		goto exit;
	}

	fHasProcessExitSynchronization = TRUE;

	__try
	{
		__try
		{
			KeStackAttachProcess(pProcess, &ApcState);
			RtlCopyMemory(pBuffer, (PVOID)Address, cbBuffer);
		}
		__finally
		{
			KeUnstackDetachProcess(&ApcState);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ntstatus = STATUS_UNHANDLED_EXCEPTION;
		goto exit;
	}

	if (ARGUMENT_PRESENT(pcbRead))
	{
		*pcbRead = cbBuffer;
	}

exit:
	if (fHasProcessExitSynchronization)
	{
		PsReleaseProcessExitSynchronization(pProcess);
	}

	if (fHasProcessReference)
	{
		ObDereferenceObject(pProcess);
	}

	return ntstatus;
}

NTSTATUS MyReadMemory(IN PEPROCESS EProcess, IN PVOID BaseAddress, OUT PVOID Pbuff, IN ULONG BufferSize)
{
	KAPC_STATE	ApcState;
	PVOID		readbuffer = NULL;
	NTSTATUS	status = STATUS_SUCCESS;

	readbuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'Sys');

	if (readbuffer == NULL)
	{
		ObDereferenceObject(EProcess);
		ExFreePool(readbuffer);
		return(STATUS_UNSUCCESSFUL);
	}
	*(ULONG*)readbuffer = (ULONG)0x1;

	KeStackAttachProcess(EProcess, &ApcState);
	if (MmIsAddressValid(BaseAddress))
	{
		__try
		{
			ProbeForRead((CONST PVOID) BaseAddress, BufferSize, sizeof(CHAR));
			RtlCopyMemory(readbuffer, BaseAddress, BufferSize);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			status = STATUS_UNSUCCESSFUL;
		}
	}
	else {
		status = STATUS_UNSUCCESSFUL;
	}
	KeUnstackDetachProcess(&ApcState);

	if (NT_SUCCESS(status))
	{
		if (MmIsAddressValid(Pbuff))
		{
			__try
			{
				ProbeForWrite(Pbuff, BufferSize, sizeof(CHAR));
				RtlCopyMemory(Pbuff, readbuffer, BufferSize);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				status = STATUS_UNSUCCESSFUL;
			}
		}
		else {
			status = STATUS_UNSUCCESSFUL;
		}
	}

	ExFreePool(readbuffer);
	return(status);
}

NTSTATUS DriverCopy(IN PDRIVER_MANAGE_MEMORY copy) {
	NTSTATUS status = STATUS_SUCCESS;
	if (NT_SUCCESS(status)) {
		PEPROCESS sourceProcess, targetProcess;
		PVOID sourcePtr, targetPtr;
		if (copy->isWrite == FALSE) {
			sourceProcess = AttachedProcess;
			targetProcess = PsGetCurrentProcess();
			sourcePtr = (PVOID)copy->Dst;
			targetPtr = (PVOID)copy->Src;
		}
		else {
			sourceProcess = PsGetCurrentProcess();
			targetProcess = AttachedProcess;
			sourcePtr = (PVOID)copy->Src;
			targetPtr = (PVOID)copy->Dst;
		}
		ULONG bytes;
		if (copy->Dst < 0x7FFFFFFFFFFF)
		{
			if (copy->isIgnoreProtect)
			{
				PMDL mdl = IoAllocateMdl(targetPtr, copy->Size, FALSE, FALSE, NULL);

				MmProbeAndLockProcessPages(mdl, targetProcess, KernelMode, IoReadAccess);
				void* map = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
				MmProtectMdlSystemAddress(mdl, PAGE_READWRITE);

				RtlCopyMemory(map, sourcePtr, copy->Size);

				MmUnmapLockedPages(map, mdl);
				MmUnlockPages(mdl);
				IoFreeMdl(mdl);
			}
			else
				status = MyReadMemory(sourceProcess, sourcePtr, targetPtr, copy->Size);
		}
	}
	return status;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING dosDeviceName;
	RtlUnicodeStringInit(&dosDeviceName, DRIVER_DOS_DEVICE_NAME);
	IoDeleteSymbolicLink(&dosDeviceName);
	IoDeleteDevice(DriverObject->DeviceObject);
	CleanUnloadedDrivers();
}

PVOID GuardedRegionAddress = 0;

NTSTATUS
SetGuardedRegion(
)
{
	PSYSTEM_BIGPOOL_INFORMATION pPoolInfo = 0;
	NTSTATUS ntstatus = STATUS_SUCCESS;
	ULONG infoLen = 0;

	ntstatus = ZwQuerySystemInformation(SystemBigPoolInformation, &infoLen, 0, &infoLen);
	while (ntstatus == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (pPoolInfo)
			ExFreePool(pPoolInfo);

		pPoolInfo = (PSYSTEM_BIGPOOL_INFORMATION)ExAllocatePool(NonPagedPool, infoLen);
		ntstatus = ZwQuerySystemInformation(SystemBigPoolInformation, pPoolInfo, infoLen, &infoLen);
	}

	if (pPoolInfo)
	{
		for (ULONG i = 0; i < pPoolInfo->Count; ++i)
		{
			SYSTEM_BIGPOOL_ENTRY* Entry = &pPoolInfo->AllocatedInfo[i];
			PVOID VirtualAddress = (PVOID)((uintptr_t)Entry->VirtualAddress & ~1ull);
			SIZE_T SizeInBytes = Entry->SizeInBytes;
			BOOLEAN NonPaged = Entry->NonPaged;

			if (NonPaged && SizeInBytes == 0x200000)
			{
				ULONG Rsh_x24 = (*(uintptr_t*)((PBYTE)VirtualAddress + 0x50) >> 0x24);

				if (Rsh_x24 == 0x8 || Rsh_x24 == 0x10)
				{
					GuardedRegionAddress = VirtualAddress;
				}
			}
		}
	}

	if (!GuardedRegionAddress)
	{
		ntstatus = STATUS_UNSUCCESSFUL;
	}

exit:
	if (pPoolInfo)
	{
		ExFreePool(pPoolInfo);
	}

	return ntstatus;
}

NTSTATUS
ReadGuardedRegion(
	ULONG_PTR Displacement,
	PVOID pBuffer,
	ULONG cbBuffer,
	PULONG pcbRead,
	float X,
	float Y
)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	if (!GuardedRegionAddress)
	{
		ntstatus = STATUS_UNSUCCESSFUL;
		goto exit;
	}

	if (ARGUMENT_PRESENT(pcbRead))
	{
		*pcbRead = 0;
	}

	__try
	{
		RtlCopyMemory(pBuffer, (PVOID)((PBYTE)GuardedRegionAddress + Displacement), cbBuffer);

		if (X != 0.0f)
			*(float*)(PVOID)((PBYTE)GuardedRegionAddress + Displacement) = X;
		if (Y != 0.0f)
			*(float*)(PVOID)((PBYTE)GuardedRegionAddress + Displacement + 0x4) = Y;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ntstatus = STATUS_UNHANDLED_EXCEPTION;
		goto exit;
	}

	if (ARGUMENT_PRESENT(pcbRead))
	{
		*pcbRead = cbBuffer;
	}

exit:
	return ntstatus;
}

NTSTATUS DriverDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);
	PVOID ioBuffer = Irp->AssociatedIrp.SystemBuffer;
	ULONG inputLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG outbufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	if (irpStack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
		ULONG ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
		if (ioControlCode == IOCTL_DRIVER_INIT)
		{
			PDRIVER_INIT ReadInput = (PDRIVER_INIT)Irp->AssociatedIrp.SystemBuffer;
			PsLookupProcessByProcessId((HANDLE)ReadInput->ProcessId, &AttachedProcess);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		if (ioControlCode == IOCTL_DRIVER_MANAGE_MEMORY)
		{
			PKERNEL_READ_REQUEST pReadVirtualMemoryRequest = (PKERNEL_READ_REQUEST)Irp->AssociatedIrp.SystemBuffer;
			if (!pReadVirtualMemoryRequest)
			{
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				goto exits;
			}

			if (sizeof(*pReadVirtualMemoryRequest) != inputLength)
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
				goto exits;
			}

			Irp->IoStatus.Status = MyReadMemory(
				AttachedProcess,
				pReadVirtualMemoryRequest->TargetAddress,
				pReadVirtualMemoryRequest->ResponseAddress,
				pReadVirtualMemoryRequest->Size);

			if (!NT_SUCCESS(Irp->IoStatus.Status))
			{
				goto exits;
			}

		exits:
			Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		}
		if (ioControlCode == IOCTL_DRIVER_GET_BASE_ADDRESS)
		{
			PGET_BASE_ADDRESS ReadInput = (PGET_BASE_ADDRESS)Irp->AssociatedIrp.SystemBuffer;
			*ReadInput->Result = (ULONGLONG)PsGetProcessSectionBaseAddress(AttachedProcess);
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		if (ioControlCode == IOCTL_SET_GUARDED_REGION)
		{
			SetGuardedRegion();
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		if (ioControlCode == IOCTL_READ_GUARDED_REGION)
		{
			ULONG cbRead = 0;
			PREAD_GUARDED_REGION_REQUEST pReadGuardedRegionRequest = (PREAD_GUARDED_REGION_REQUEST)Irp->AssociatedIrp.SystemBuffer;

			if (!pReadGuardedRegionRequest)
			{
				Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
				goto exit;
			}

			if (sizeof(*pReadGuardedRegionRequest) != inputLength)
			{
				Irp->IoStatus.Status = STATUS_INFO_LENGTH_MISMATCH;
				goto exit;
			}

			Irp->IoStatus.Status = ReadGuardedRegion(
				pReadGuardedRegionRequest->Displacement,
				pReadGuardedRegionRequest->Buffer,
				pReadGuardedRegionRequest->Size,
				&cbRead,
				pReadGuardedRegionRequest->X,
				pReadGuardedRegionRequest->Y);

			if (!NT_SUCCESS(Irp->IoStatus.Status))
			{
				goto exit;
			}
		exit:
			Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
		}
	}
	NTSTATUS status = Irp->IoStatus.Status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath) {
	DestroyDriverInformation(DriverObject, NULL, (ULONG64)DriverUnload, FALSE);
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(RegistryPath);
	UNICODE_STRING deviceName;
	RtlUnicodeStringInit(&deviceName, DRIVER_DEVICE_NAME);
	PDEVICE_OBJECT deviceObject = NULL;
	status = IoCreateDevice(DriverObject, 0, &deviceName, DRIVER_DEVICE_TYPE, 0, FALSE, &deviceObject);
	if (!NT_SUCCESS(status)) {
		return status;
	}
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverDispatch;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
	DriverObject->DriverUnload = DriverUnload;
	UNICODE_STRING dosDeviceName;
	RtlUnicodeStringInit(&dosDeviceName, DRIVER_DOS_DEVICE_NAME);
	status = IoCreateSymbolicLink(&dosDeviceName, &deviceName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(deviceObject);
	}
	return status;
}