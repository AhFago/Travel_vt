#pragma once
/**************************************************************************************
* AUTHOR : EasySys
* DATE   : 2020-2-24
* MODULE : common.h
*
* Command:
*	IOCTRL Common Header
*
* Description:
*	Common data for the IoCtrl driver and application
*
****************************************************************************************
* Copyright (C) 2010 EasySys.
****************************************************************************************/



#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include <initguid.h>

// NTOS headers
#include <ntifs.h>
#include <ntddk.h>

#ifndef FAR
#define FAR
#endif

// Windows headers
#include <windef.h>
#include <winerror.h>

// Windows GDI headers
//#include <wingdi.h>

// Windows DDI headers
//#include <winddi.h>
#include <ntddvdeo.h>

// #include <d3dkmddi.h>
// #include <d3dkmthk.h>

#include <ntstrsafe.h>
#include <ntintsafe.h>

#include <dispmprt.h>


#if DBG
#define DebugPrintA DbgPrint
#else
#define dprintf
#endif



//不支持符号链接用户相关性
#define NT_DEVICE_NAME                  L"\\Device\\devTravel_vt"             // Driver Name
#define SYMBOLIC_LINK_NAME           L"\\DosDevices\\Travel_vt"            // Symbolic Link Name
#define WIN32_LINK_NAME              "\\\\.\\Travel_vt"                    // Win32 Link Name

//支持符号链接用户相关性
#define SYMBOLIC_LINK_GLOBAL_NAME    L"\\DosDevices\\Global\\Travel_vt"    // Symbolic Link Name


//
// Device IO Control Codes
//
#define IOCTL_BASE          0x800
#define MY_CTL_CODE(i)        \
    CTL_CODE                  \
    (                         \
        FILE_DEVICE_UNKNOWN,  \
        IOCTL_BASE + i,       \
        METHOD_BUFFERED,      \
        FILE_ANY_ACCESS       \
    )

#define IOCTL_HELLO_WORLD            0
#define IOCTRL_REC_FROM_APP          1
#define IOCTRL_SEND_TO_APP           2

#define IOCTL_VIDEO_DDI_FUNC_REGISTER_X1 CTL_CODE( FILE_DEVICE_VIDEO, 0x0F, METHOD_NEITHER, FILE_ANY_ACCESS )
#define IOCTL_VIDEO_DDI_FUNC_REGISTER_X2 CTL_CODE( FILE_DEVICE_VIDEO, 0x10, METHOD_NEITHER, FILE_ANY_ACCESS )
#define IOCTL_VIDEO_DDI_FUNC_REGISTER_X3 CTL_CODE( FILE_DEVICE_VIDEO, 0x11, METHOD_NEITHER, FILE_ANY_ACCESS )


typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;


enum class status_code { // names for generic error codes
	success = 0,
	address_family_not_supported = 102, // EAFNOSUPPORT
	address_in_use = 100, // EADDRINUSE
	address_not_available = 101, // EADDRNOTAVAIL
	already_connected = 113, // EISCONN
	argument_list_too_long = 7, // E2BIG
	argument_out_of_domain = 33, // EDOM
	bad_address = 14, // EFAULT
	bad_file_descriptor = 9, // EBADF
	bad_message = 104, // EBADMSG
	broken_pipe = 32, // EPIPE
	connection_aborted = 106, // ECONNABORTED
	connection_already_in_progress = 103, // EALREADY
	connection_refused = 107, // ECONNREFUSED
	connection_reset = 108, // ECONNRESET
	cross_device_link = 18, // EXDEV
	destination_address_required = 109, // EDESTADDRREQ
	device_or_resource_busy = 16, // EBUSY
	directory_not_empty = 41, // ENOTEMPTY
	executable_format_error = 8, // ENOEXEC
	file_exists = 17, // EEXIST
	file_too_large = 27, // EFBIG
	filename_too_long = 38, // ENAMETOOLONG
	function_not_supported = 40, // ENOSYS
	host_unreachable = 110, // EHOSTUNREACH
	identifier_removed = 111, // EIDRM
	illegal_byte_sequence = 42, // EILSEQ
	inappropriate_io_control_operation = 25, // ENOTTY
	interrupted = 4, // EINTR
	invalid_argument = 22, // EINVAL
	invalid_seek = 29, // ESPIPE
	io_error = 5, // EIO
	is_a_directory = 21, // EISDIR
	message_size = 115, // EMSGSIZE
	network_down = 116, // ENETDOWN
	network_reset = 117, // ENETRESET
	network_unreachable = 118, // ENETUNREACH
	no_buffer_space = 119, // ENOBUFS
	no_child_process = 10, // ECHILD
	no_link = 121, // ENOLINK
	no_lock_available = 39, // ENOLCK
	no_message_available = 120, // ENODATA
	no_message = 122, // ENOMSG
	no_protocol_option = 123, // ENOPROTOOPT
	no_space_on_device = 28, // ENOSPC
	no_stream_resources = 124, // ENOSR
	no_such_device_or_address = 6, // ENXIO
	no_such_device = 19, // ENODEV
	no_such_file_or_directory = 2, // ENOENT
	no_such_process = 3, // ESRCH
	not_a_directory = 20, // ENOTDIR
	not_a_socket = 128, // ENOTSOCK
	not_a_stream = 125, // ENOSTR
	not_connected = 126, // ENOTCONN
	not_enough_memory = 12, // ENOMEM
	not_supported = 129, // ENOTSUP
	operation_canceled = 105, // ECANCELED
	operation_in_progress = 112, // EINPROGRESS
	operation_not_permitted = 1, // EPERM
	operation_not_supported = 130, // EOPNOTSUPP
	operation_would_block = 140, // EWOULDBLOCK
	owner_dead = 133, // EOWNERDEAD
	permission_denied = 13, // EACCES
	protocol_error = 134, // EPROTO
	protocol_not_supported = 135, // EPROTONOSUPPORT
	read_only_file_system = 30, // EROFS
	resource_deadlock_would_occur = 36, // EDEADLK
	resource_unavailable_try_again = 11, // EAGAIN
	result_out_of_range = 34, // ERANGE
	state_not_recoverable = 127, // ENOTRECOVERABLE
	stream_timeout = 137, // ETIME
	text_file_busy = 139, // ETXTBSY
	timed_out = 138, // ETIMEDOUT
	too_many_files_open_in_system = 23, // ENFILE
	too_many_files_open = 24, // EMFILE
	too_many_links = 31, // EMLINK
	too_many_symbolic_link_levels = 114, // ELOOP
	value_too_large = 132, // EOVERFLOW
	wrong_protocol_type = 136 // EPROTOTYPE
};


