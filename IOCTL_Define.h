#pragma once
#include <ntifs.h>
#include <ntstrsafe.h>

#define DRIVER_NAME L"HONGZ"
#define DRIVER_DEVICE_NAME     L"\\Device\\HONGZ"
#define DRIVER_DOS_DEVICE_NAME L"\\DosDevices\\HONGZ"
#define DRIVER_DEVICE_PATH  L"\\\\.\\HONGZ"
#define DRIVER_DEVICE_TYPE 0x00000022

#define IOCTL_DRIVER_INIT ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 4100, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS))
#define IOCTL_DRIVER_GET_BASE_ADDRESS ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 4200, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS))
#define IOCTL_DRIVER_MANAGE_MEMORY ((ULONG)CTL_CODE(DRIVER_DEVICE_TYPE, 4300, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS))

typedef struct _DRIVER_INIT {
	ULONG ProcessId;
} DRIVER_INIT, *PDRIVER_INIT;

typedef struct _DRIVER_MANAGE_MEMORY {
	ULONGLONG Src;
	ULONGLONG Dst;
	ULONGLONG Size;
	BOOLEAN isWrite;
	BOOLEAN isIgnoreProtect;
} DRIVER_MANAGE_MEMORY, *PDRIVER_MANAGE_MEMORY;

typedef struct _GET_BASE_ADDRESS
{
	ULONGLONG *Result;
} GET_BASE_ADDRESS, *PGET_BASE_ADDRESS;

#define IOCTL_SET_GUARDED_REGION            \
    CTL_CODE(                               \
        DRIVER_DEVICE_TYPE,                 \
        4400,                               \
        METHOD_BUFFERED,                    \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

#define IOCTL_READ_GUARDED_REGION           \
    CTL_CODE(                               \
        DRIVER_DEVICE_TYPE,                 \
        4500,                               \
        METHOD_BUFFERED,                    \
        FILE_READ_ACCESS | FILE_WRITE_ACCESS)

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
    union {
        PVOID VirtualAddress;
        ULONG_PTR NonPaged : 1;
    };
    ULONG_PTR SizeInBytes;
    union {
        UCHAR Tag[4];
        ULONG TagUlong;
    };
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

#ifdef __cplusplus
extern "C" {
#endif
    int _fltused = 0; // it should be a single underscore since the double one is the mangled name
#ifdef __cplusplus
}
#endif

typedef struct _READ_GUARDED_REGION_REQUEST {
	ULONG_PTR Displacement;
	PVOID Buffer;
	ULONG Size;
    float X;
    float Y;
} READ_GUARDED_REGION_REQUEST, * PREAD_GUARDED_REGION_REQUEST;

typedef struct _KERNEL_READ_REQUEST
{
    DWORD_PTR TargetAddress;
    DWORD_PTR ResponseAddress;
    ULONG Size;
} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _READ_VIRTUAL_MEMORY_REQUEST {
    ULONG_PTR Address;
    ULONG Size;
} READ_VIRTUAL_MEMORY_REQUEST, * PREAD_VIRTUAL_MEMORY_REQUEST;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
    ULONG Count;
    SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;