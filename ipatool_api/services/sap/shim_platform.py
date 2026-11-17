"""libSystem, CoreFoundation, IOKit, XPC and Mach services for the guest code.

Port of ipatool ``internal/sap/machine/shim_platform.go`` and ``ioaes.go``
(ipatool 2.8, MIT). Mixed into ``machine.Machine``; every handler reads its
arguments with the AAPCS64 helpers there and writes the result to x0.
"""
from __future__ import annotations

import hashlib
import os
import struct
import time

from unicorn import arm64_const as _arm

from .errors import SAPError

U64 = (1 << 64) - 1
U32 = (1 << 32) - 1

FAKE_HANDLE = U64
_CORE_FP_FILE = 3
_ADI_FILE = 5
_CORE_FP_PATH = "/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP"
_ICXS_PATH = "./../CoreFP.icxs"
_KEY_SERIAL = "IOPlatformSerialNumber"
_KEY_UUID = "IOPlatformUUID"
_KEY_BOARD = "board-id"
_KEYED_MESSAGE = "objectForKey:"
_ONCE_DONE = 0x4F4E4345
XPC_DICTIONARY_TYPE = 0xFFFF100000000001
ADI_STATE_PATH = "/var/db/fpsd/adi/adi.pb"
_MAX_MACH_MESSAGE = 1 << 20
_PROCESS_PATH = b"/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce\x00"
COMMERCE_AES_HANDLE = 0x89C


def _is_adi_state_path(path: str) -> bool:
    return path == ADI_STATE_PATH


class PlatformShims:
    """The shim handlers; ``self`` is a ``machine.Machine``."""

    def _register_platform_shims(self) -> None:
        zero = self._sh_return_zero
        fake = self._sh_return_fake_handle
        services = [
            (["_CFBundleGetMainBundle", "_CFDataGetBytePtr", "_CFDataGetLength", "_CFStringGetLength",
              "_CFStringGetMaximumSizeForEncoding", "_CFUUIDCreateString", "_IORegistryEntryFromPath",
              "_IORegistryEntrySearchCFProperty", "_getenv", "_pthread_self"], zero),
            (["_CFDictionaryGetValue", "_CFFileDescriptorCreate", "_CFFileDescriptorCreateRunLoopSource",
              "_CFMachPortCreateRunLoopSource", "_CFRunLoopGetCurrent", "_CFRunLoopGetMain",
              "_CFURLCreateFromFileSystemRepresentation", "_DADiskCopyDescription", "_DADiskCreateFromBSDName",
              "_DASessionCreate", "_IORegistryEntryCreateCFProperty", "_dispatch_get_global_queue",
              "_dispatch_queue_create", "_dispatch_queue_create_with_target", "_os_transaction_create",
              "_xpc_connection_create"], fake),
            (["_CFRelease", "_CFFileDescriptorEnableCallBacks", "_CFFileDescriptorInvalidate",
              "_CFFileSecuritySetMode", "_CFRunLoopAddSource", "_CFURLCopyResourcePropertyForKey",
              "_CFURLSetResourcePropertyForKey", "_CSBackupIsItemExcluded", "_CSBackupSetItemExcluded",
              "_IOObjectRelease", "_IOLockLock", "_IOLockUnlock", "_IOLockWakeup", "_IORWLockRead",
              "_IORWLockWrite", "_IORWLockUnlock", "_lck_mtx_lock", "_lck_mtx_unlock", "_lck_rw_lock_exclusive",
              "_lck_rw_unlock_exclusive", "_chmod", "_close", "_close$UNIX2003", "_fchmod", "_fcntl",
              "_fcntl$UNIX2003", "_kevent", "_lockf", "_mkdir", "_pthread_mutex_lock", "_pthread_mutex_unlock",
              "_pthread_rwlock_init", "_pthread_rwlock_init$UNIX2003", "_pthread_rwlock_destroy",
              "_pthread_rwlock_rdlock", "_pthread_rwlock_unlock", "_pthread_rwlock_unlock$UNIX2003",
              "_pthread_rwlock_wrlock", "_pthread_rwlock_wrlock$UNIX2003", "_pthread_set_qos_class_self_np",
              "_CFRunLoopStop", "_getpid", "_getuid", "_notify_post", "_ptrace", "_sched_yield", "_signal",
              "_umask", "_os_release", "_xpc_connection_activate", "_xpc_connection_cancel",
              "_xpc_connection_resume", "_xpc_connection_set_target_queue", "_xpc_dictionary_set_bool",
              "_xpc_dictionary_set_int64", "_xpc_dictionary_set_string", "_xpc_dictionary_set_uint64",
              "_xpc_dictionary_set_value", "_xpc_release", "_xpc_retain", "_xpc_transaction_begin",
              "_xpc_transaction_end"], zero),
            (["_IOLog", "_IOLogv"], zero),
            (["_notify_register_check"], self._sh_notify_register_check),
            (["_notify_check"], self._sh_notify_check),
            (["_notify_get_state"], self._sh_notify_get_state),
            (["_notify_cancel"], zero),
            (["_atexit"], zero),
            (["_CFRunLoopRun"], self._sh_cf_run_loop_run),
            (["_CFMachPortCreateWithPort"], self._sh_cf_mach_port_create_with_port),
            (["_CFMachPortGetPort"], self._sh_return_one),
            (["_SecTaskCreateWithAuditToken", "_SecTaskCopyValueForEntitlement"], fake),
            (["_CFStringCreateWithCString"], self._sh_cfstring_create),
            (["_CFStringCreateWithCStringNoCopy"], self._sh_cfstring_create_no_copy),
            (["_CFStringGetCString"], self._sh_cfstring_get_cstring),
            (["_CFGetTypeID", "_CFNumberGetTypeID"], self._sh_return_one),
            (["_CFStringGetTypeID"], self._sh_return_two),
            (["_CFDictionaryGetTypeID"], self._sh_return_three),
            (["_CFNumberGetValue"], self._sh_cfnumber_get_value),
            (["___chkstk_darwin", "____chkstk_darwin"], self._sh_return_unchanged),
            (["__ZN9IOService15serviceMatchingEPKcP12OSDictionary"], self._sh_return_unchanged),
            (["__ZN9IOService14waitForServiceEP12OSDictionaryP13mach_timespec"], self._sh_wait_for_kernel_service),
            (["__ZN24IOBufferMemoryDescriptor17inTaskWithOptionsEP4taskjmm"], self._sh_new_kernel_buffer_descriptor),
            (["__ZN18IOMemoryDescriptor16withAddressRangeEyyjP4task"], self._sh_new_kernel_buffer_descriptor_at),
            (["_IOIteratorNext"], self._sh_io_iterator_next),
            (["_IOConnectCallStructMethod"], self._sh_io_connect_call_struct_method),
            (["_IORegistryEntryGetParentEntry"], self._sh_io_registry_parent),
            (["_IOServiceGetMatchingServices"], self._sh_io_matching_services),
            (["_IOServiceGetMatchingService"], self._sh_return_one),
            (["_IOServiceMatching"], fake),
            (["_IOMainPort"], self._sh_io_main_port),
            (["_IOServiceOpen"], self._sh_io_service_open),
            (["_OSAtomicCompareAndSwap32Barrier"], self._sh_cas32),
            (["___error"], self._sh_error_pointer),
            (["_abort", "___stack_chk_fail", "dyld_stub_binder"], self._sh_abort),
            (["_arc4random"], self._sh_arc4random),
            (["_random"], self._sh_random31),
            (["_arc4random_uniform"], self._sh_arc4random_uniform),
            (["_read_random", "_kernel_read_random"], self._sh_read_random),
            (["_audit_token_to_au32"], self._sh_audit_token_to_au32),
            (["_audit_token_to_euid"], zero),
            (["_basename"], self._sh_basename),
            (["_bootstrap_look_up"], self._sh_bootstrap_look_up),
            (["_bootstrap_check_in"], self._sh_bootstrap_check_in),
            (["_mach_msg_rpc_from_kernel_proper"], self._sh_mach_msg_rpc_from_kernel),
            (["_mach_msg", "_mach_msg2_internal"], self._sh_mach_msg),
            (["_mach_msg_destroy", "_mach_msg_destroy_from_kernel_proper", "_mach_port_deallocate",
              "_mig_dealloc_reply_port", "_mig_deallocate", "_mig_put_reply_port"], zero),
            (["_mig_get_reply_port"], self._sh_return_one),
            (["_dispatch_once"], self._sh_dispatch_once),
            (["_dlopen"], self._sh_dlopen),
            (["_dlsym"], self._sh_dlsym),
            (["_statfs", "_statfs$INODE64"], self._sh_return_minus_one),
            (["_fstat"], self._sh_fstat),
            (["_ftruncate"], self._sh_ftruncate),
            (["_gettimeofday"], self._sh_gettimeofday),
            (["_clock_get_calendar_microtime"], self._sh_clock_get_calendar_microtime),
            (["_time"], self._sh_current_time),
            (["_gethostuuid"], self._sh_gethostuuid),
            (["_objc_msgSend"], self._sh_objc_msg_send),
            (["_open", "_open$UNIX2003"], self._sh_open),
            (["_lstat", "_lstat$INODE64", "_stat", "_stat$INODE64"], self._sh_lstat),
            (["_pthread_once"], self._sh_pthread_once),
            (["_proc_pidpath"], self._sh_proc_pid_path),
            (["_read", "_read$UNIX2003"], self._sh_read),
            (["_write"], self._sh_write),
            (["_unlink"], self._sh_unlink),
            (["_sysctl"], self._sh_return_minus_one),
            (["_sysctlbyname"], self._sh_sysctlbyname),
            (["_sysconf"], self._sh_sysconf),
            (["_xpc_dictionary_get_data"], self._sh_xpc_dictionary_get_data),
            (["_xpc_dictionary_set_data"], self._sh_xpc_dictionary_set_data),
            (["_xpc_connection_create_mach_service"], self._sh_xpc_create_object),
            (["_xpc_connection_send_message_with_reply_sync"], self._sh_xpc_send_message_with_reply_sync),
            (["_xpc_connection_set_event_handler"], self._sh_xpc_set_event_handler),
            (["_xpc_dictionary_create_empty"], self._sh_xpc_create_object),
            (["_xpc_dictionary_create_reply"], self._sh_xpc_create_object),
            (["_xpc_dictionary_get_audit_token"], self._sh_xpc_get_audit_token),
            (["_xpc_dictionary_send_reply"], self._sh_xpc_send_reply),
            (["_xpc_get_type"], self._sh_xpc_get_type),
            (["_kqueue"], self._sh_kqueue),
            (["_os_log_type_enabled"], self._sh_return_one),
            (["_os_log_impl", "__os_log_impl"], zero),
        ]
        for names, handler in services:
            self._alias(names, handler)

        self._errno_addr = self._add_data("guest.errno", b"\x00" * 8)
        self._add_data("___stack_chk_guard", bytes([0xA5, 0x71, 0x3C, 0xD9, 0x86, 0x42, 0xEF, 0x10]))
        for name in ("_NDR_record", "_kCFAllocatorDefault", "_kCFAllocatorNull",
                     "_kDADiskDescriptionVolumeUUIDKey", "_kIOMasterPortDefault"):
            self._add_data(name, b"\x00" * 8)
        for name, value in (
            ("_kCFBooleanFalse", FAKE_HANDLE),
            ("_kCFBooleanTrue", FAKE_HANDLE),
            ("__xpc_type_dictionary", XPC_DICTIONARY_TYPE),
            ("__xpc_type_error", XPC_DICTIONARY_TYPE + 1),
            ("__xpc_error_connection_invalid", XPC_DICTIONARY_TYPE + 2),
        ):
            self._add_data(name, struct.pack("<Q", value))
        self._add_function("callback.complete", self._sh_callback_complete)

    # -- simple results ---------------------------------------------------

    def _sh_return_zero(self) -> None:
        self._set_result(0)

    def _sh_return_one(self) -> None:
        self._set_result(1)

    def _sh_return_two(self) -> None:
        self._set_result(2)

    def _sh_return_three(self) -> None:
        self._set_result(3)

    def _sh_return_unchanged(self) -> None:
        pass

    def _sh_return_fake_handle(self) -> None:
        self._set_result(FAKE_HANDLE)

    def _sh_return_minus_one(self) -> None:
        self._set_result(U64)

    # -- Mach -------------------------------------------------------------

    def _sh_mach_msg_rpc_from_kernel(self) -> None:
        message = self._argument(0)
        send_size = self._argument(1)
        receive_size = self._argument(2)
        if send_size == 0 or send_size > _MAX_MACH_MESSAGE or receive_size > _MAX_MACH_MESSAGE:
            raise SAPError("kernel Mach RPC size is invalid")
        request = self.mem_read(message, send_size)
        if self.mach_rpc_handler is None:
            raise SAPError("kernel Mach RPC handler is unavailable")
        reply = self.mach_rpc_handler(request, receive_size)
        if not reply or len(reply) > receive_size:
            raise SAPError("kernel Mach RPC reply is invalid")
        self.mem_write(message, reply)
        self._set_result(0)

    def _sh_mach_msg(self) -> None:
        message = self._argument(0)
        send_size = self._argument(2)
        if send_size == 0 or send_size > _MAX_MACH_MESSAGE:
            self._set_result(0)
            return
        self.mach_message_reply = self.mem_read(message, send_size)
        self._set_result(0)

    def _sh_kqueue(self) -> None:
        self._set_result(6)

    def _sh_cf_run_loop_run(self) -> None:
        if not self._pause_run_loop:
            self._set_result(0)
            return
        self._uc.emu_stop()

    def _sh_cf_mach_port_create_with_port(self) -> None:
        callback = self._argument(2)
        context = self._argument(3)
        self.mach_port_callback = callback
        self.mach_port_context = context
        if context:
            try:
                self.mach_port_info = self.read_u64(context + 8)
            except Exception:  # noqa: BLE001 - as upstream: an unreadable context gives no info
                self.mach_port_info = 0
        should_free_info = self._argument(4)
        if should_free_info:
            self.mem_write(should_free_info, b"\x00")
        self._set_result(FAKE_HANDLE)

    # -- XPC --------------------------------------------------------------

    def _sh_xpc_send_message_with_reply_sync(self) -> None:
        self._set_result(self.new_xpc_object(self.xpc_sync_reply))

    def _sh_xpc_create_object(self) -> None:
        self._set_result(self.new_xpc_object(None))

    def _sh_xpc_set_event_handler(self) -> None:
        block = self._argument(1)
        copy_address = self.allocate(64)
        self.mem_write(copy_address, self.mem_read(block, 64))
        self.xpc_event_handler = copy_address
        self._set_result(0)

    def _sh_xpc_get_audit_token(self) -> None:
        token = self._argument(1)
        if token:
            value = bytearray(32)
            struct.pack_into("<I", value, 0, U32)
            struct.pack_into("<I", value, 20, 123)
            struct.pack_into("<I", value, 24, 100000)
            struct.pack_into("<I", value, 28, 1)
            self.mem_write(token, bytes(value))
        self._set_result(0)

    def _sh_xpc_send_reply(self) -> None:
        value = self.xpc_objects.get(self._argument(0))
        if value is not None:
            self.xpc_reply = value.data
        self.xpc_replied = True
        self._set_result(0)

    def _sh_xpc_get_type(self) -> None:
        if self.xpc_objects.get(self._argument(0)) is not None:
            self._set_result(self._shim_symbols["__xpc_type_dictionary"])
            return
        self._set_result(0)

    def _sh_xpc_dictionary_set_data(self) -> None:
        obj = self._argument(0)
        address = self._argument(2)
        length = self._argument(3)
        if length > _MAX_MACH_MESSAGE:
            raise SAPError("XPC data exceeds guest limit")
        self.xpc_data = self.mem_read(address, length)
        value = self.xpc_objects.get(obj)
        if value is not None:
            value.data = self.xpc_data
            value.has_data = True
        self._set_result(0)

    def _sh_xpc_dictionary_get_data(self) -> None:
        obj = self._argument(0)
        length = self._argument(2)
        value = self.xpc_objects.get(obj)
        if value is None or not value.has_data:
            if length:
                self.write_u64(length, 0)
            self._set_result(0)
            return
        if value.data_address == 0:
            value.data_address = self.allocate(max(len(value.data), 1))
            self.mem_write(value.data_address, value.data)
        if length:
            self.write_u64(length, len(value.data))
        self._set_result(value.data_address)

    # -- CoreFoundation ---------------------------------------------------

    def _sh_cfstring_create(self) -> None:
        value = self._read_text(self._argument(1))
        self._set_result(FAKE_HANDLE if value in (_KEY_SERIAL, _KEY_UUID, _KEY_BOARD) else 0)

    def _sh_cfnumber_get_value(self) -> None:
        address = self._argument(2)
        if address:
            self.write_u32(address, 3184554750)
        self._set_result(1)

    def _sh_cfstring_create_no_copy(self) -> None:
        self._set_result(self._argument(1))

    def _sh_cfstring_get_cstring(self) -> None:
        value_address = self._argument(0)
        buffer = self._argument(1)
        capacity = self._argument(2)
        if buffer == 0 or capacity == 0:
            self._set_result(0)
            return
        value = b""
        if value_address not in (0, FAKE_HANDLE):
            try:
                value = self._read_cstring(value_address)
            except Exception:  # noqa: BLE001 - as upstream: an unreadable string is empty
                value = b""
        encoded = value + b"\x00"
        if len(encoded) > capacity:
            self._set_result(0)
            return
        self.mem_write(buffer, encoded)
        self._set_result(1)

    # -- IOKit ------------------------------------------------------------

    def _sh_io_iterator_next(self) -> None:
        self._iterator = (self._iterator + 1) & U32
        self._set_result(self._iterator % 2)

    def _sh_io_connect_call_struct_method(self) -> None:
        selector = self._argument(1)
        input_size = self._argument(3)
        output_size_address = self._argument(5)
        output_size = 0
        if output_size_address:
            try:
                output_size = self.read_u64(output_size_address)
            except Exception:  # noqa: BLE001 - as upstream: unreadable means zero
                output_size = 0
        if input_size > _MAX_MACH_MESSAGE or output_size > _MAX_MACH_MESSAGE:
            raise SAPError("FairPlay IOKit buffer exceeds guest limit")
        input_address = self._argument(2)
        data = self.mem_read(input_address, input_size)
        indirect = b""
        indirect_address = 0
        if selector == 26 and len(data) == 16:
            indirect_address, indirect_size = struct.unpack("<QQ", data)
            if indirect_size == 0 or indirect_size > _MAX_MACH_MESSAGE:
                raise SAPError("FairPlay IOKit indirect buffer is invalid")
            indirect = self.mem_read(indirect_address, indirect_size)
        if self.fairplay_handler is None:
            raise SAPError("emulated FairPlay IOKit handler is unavailable")
        output, indirect_output, code = self.fairplay_handler(data, indirect, output_size)
        if code != 0 and selector == 26 and len(indirect) >= 16 and len(data) == output_size:
            updated = bytearray(indirect)
            digest = hashlib.sha256(bytes(updated[:-16])).digest()
            updated[-16:] = digest[:16]
            indirect_output = bytes(updated)
            output = data
            code = 0
        output = bytearray(output)
        if indirect_output:
            self.mem_write(indirect_address, indirect_output)
            if len(output) >= 8:
                struct.pack_into("<Q", output, 0, indirect_address)
        output_address = self._argument(4)
        if output:
            self.mem_write(output_address, bytes(output))
        if output_size_address:
            self.write_u64(output_size_address, len(output))
        self._set_result(code & U32)

    def _sh_io_main_port(self) -> None:
        port = self._argument(1)
        if port:
            self.write_u32(port, 1)
        self._set_result(0)

    def _sh_wait_for_kernel_service(self) -> None:
        name = self._read_text(self._argument(0))
        if name != "IOAESAccelerator":
            self._set_result(0)
            return
        if self._aes_service:
            self._set_result(self._aes_service)
            return
        unhandled = self._add_function("$IOAESAccelerator.unhandled", self._sh_return_zero)
        retain = self._add_function("$IOAESAccelerator.retain", self._sh_return_unchanged)
        perform = self._add_function("$IOAESAccelerator.performAES", self._sh_io_aes_perform)
        vtable = bytearray(struct.pack("<Q", unhandled) * (0x900 // 8))
        struct.pack_into("<Q", vtable, 0x20, retain)
        struct.pack_into("<Q", vtable, 0x550, perform)
        struct.pack_into("<Q", vtable, 0x890, perform)
        self._aes_vtable = self._add_data("kernel.ioaes.vtable", bytes(vtable))
        self._aes_service = self.allocate(16)
        self.write_u64(self._aes_service, self._aes_vtable)
        self._set_result(self._aes_service)

    def _sh_new_kernel_buffer_descriptor(self) -> None:
        capacity = self._argument(2)
        if capacity == 0 or capacity > self._max_transfer():
            self._set_result(0)
            return
        buffer = self.allocate_aligned(capacity, 16)
        self.mem_write(buffer, b"\x00" * capacity)
        self._create_kernel_buffer_descriptor(buffer, capacity)

    def _sh_new_kernel_buffer_descriptor_at(self) -> None:
        buffer = self._argument(0)
        capacity = self._argument(1)
        if buffer == 0 or capacity == 0 or capacity > self._max_transfer():
            self._set_result(0)
            return
        self._create_kernel_buffer_descriptor(buffer, capacity)

    def _create_kernel_buffer_descriptor(self, buffer: int, capacity: int) -> None:
        if self._buffer_vtable == 0:
            unhandled = self._add_function("$IOBufferMemoryDescriptor.unhandled", self._sh_unsupported_kernel_buffer_method)
            prepare = self._add_function("$IOBufferMemoryDescriptor.prepare", self._sh_kernel_buffer_prepare)
            complete = self._add_function("$IOBufferMemoryDescriptor.complete", self._sh_return_zero)
            address = self._add_function("$IOBufferMemoryDescriptor.getVirtualAddress", self._sh_kernel_buffer_address)
            read = self._add_function("$IOMemoryDescriptor.readBytes", self._sh_kernel_buffer_read)
            write = self._add_function("$IOMemoryDescriptor.writeBytes", self._sh_kernel_buffer_write)
            release = self._add_function("$IOBufferMemoryDescriptor.release", self._sh_return_zero)
            vtable = bytearray(struct.pack("<Q", unhandled) * (0x1000 // 8))
            for offset, target in ((0x28, release), (0xC8, read), (0xD0, write), (0xD8, prepare), (0xE0, complete),
                                   (0x148, address), (0x218, prepare), (0x220, complete), (0x308, address)):
                struct.pack_into("<Q", vtable, offset, target)
            self._buffer_vtable = self._add_data("kernel.iobuffer.vtable", bytes(vtable))
        descriptor = self.allocate(24)
        self.write_u64(descriptor, self._buffer_vtable)
        self.write_u64(descriptor + 8, buffer)
        self.write_u64(descriptor + 16, capacity)
        self._set_result(descriptor)

    def _sh_unsupported_kernel_buffer_method(self) -> None:
        caller = self._uc.reg_read(_arm.UC_ARM64_REG_LR)
        raise SAPError(f"unsupported IOMemoryDescriptor virtual method from {caller:#x}")

    def _sh_kernel_buffer_prepare(self) -> None:
        descriptor = self._argument(0)
        buffer = self.read_u64(descriptor + 8)
        capacity = self.read_u64(descriptor + 16)
        if buffer == 0 or capacity == 0 or capacity > self._max_transfer():
            self._set_result(3)
            return
        self._set_result(0)

    def _sh_kernel_buffer_address(self) -> None:
        self._set_result(self.read_u64(self._argument(0) + 8))

    def _sh_kernel_buffer_read(self) -> None:
        self._transfer_kernel_buffer(False)

    def _sh_kernel_buffer_write(self) -> None:
        self._transfer_kernel_buffer(True)

    def _transfer_kernel_buffer(self, write: bool) -> None:
        descriptor = self._argument(0)
        offset = self._argument(1)
        address = self._argument(2)
        length = self._argument(3)
        buffer = self.read_u64(descriptor + 8)
        capacity = self.read_u64(descriptor + 16)
        if offset > capacity or length > capacity - offset or length > self._max_transfer():
            self._set_result(0)
            return
        source, destination = buffer + offset, address
        if write:
            source, destination = address, buffer + offset
        self.mem_write(destination, self.mem_read(source, length))
        self._set_result(length)

    def _sh_io_aes_perform(self) -> None:
        arguments = [self._argument(index) for index in range(8)]
        length = arguments[3]
        if length == 0 or length > self._max_transfer() or length % 16:
            self._set_result(3)
            return
        source_base = self.read_u64(arguments[1] + 8)
        source_capacity = self.read_u64(arguments[1] + 16)
        destination_base = self.read_u64(arguments[2] + 8)
        destination_capacity = self.read_u64(arguments[2] + 16)
        destination_offset = self._argument(8)
        if (arguments[7] > source_capacity or length > source_capacity - arguments[7]
                or destination_offset > destination_capacity or length > destination_capacity - destination_offset):
            self._set_result(3)
            return
        source = self.mem_read(source_base + arguments[7], length)
        iv = self.mem_read(arguments[4], 16)
        key = self.mem_read(arguments[6], 40)
        destination, output_iv = emulate_ioaes(source, iv, arguments[5] & U32, key)
        if len(destination) != len(source) or len(output_iv) != 16:
            raise SAPError("emulated IOAES returned invalid output")
        self.mem_write(destination_base + destination_offset, destination)
        self.mem_write(arguments[4], output_iv)
        self._set_result(0)

    def _sh_io_service_open(self) -> None:
        connection = self._argument(3)
        if connection:
            self.write_u32(connection, 7)
        self._set_result(0)

    def _sh_io_registry_parent(self) -> None:
        parent = self._argument(2)
        if parent == 0:
            raise SAPError("parent registry entry output is null")
        self.write_u32(parent, U32)
        self._set_result(0)

    def _sh_io_matching_services(self) -> None:
        iterator = self._argument(2)
        if iterator == 0:
            raise SAPError("matching services iterator output is null")
        self._iterator = 0
        self.write_u32(iterator, U32)
        self._set_result(0)

    # -- libSystem --------------------------------------------------------

    def _sh_cas32(self) -> None:
        old = self._argument(0) & U32
        new = self._argument(1) & U32
        address = self._argument(2)
        if self.read_u32(address) != old:
            self._set_result(0)
            return
        self.write_u32(address, new)
        self._set_result(1)

    def _sh_error_pointer(self) -> None:
        self._set_result(self._errno_addr)

    def _sh_abort(self) -> None:
        raise SAPError("guest aborted")

    def _sh_arc4random(self) -> None:
        self._set_result(struct.unpack("<I", os.urandom(4))[0])

    def _sh_random31(self) -> None:
        self._set_result(struct.unpack("<I", os.urandom(4))[0] & 0x7FFFFFFF)

    def _sh_arc4random_uniform(self) -> None:
        upper = self._argument(0)
        if upper < 2:
            self._set_result(0)
            return
        limit = (1 << 32) - ((1 << 32) % upper)
        while True:
            value = struct.unpack("<I", os.urandom(4))[0]
            if value < limit:
                self._set_result(value % upper)
                return

    def _sh_read_random(self) -> None:
        address = self._argument(0)
        length = self._argument(1)
        if length > self._max_transfer():
            raise SAPError(f"random request size {length} exceeds limit")
        self.mem_write(address, os.urandom(length))
        self._set_result(0)

    def _sh_notify_register_check(self) -> None:
        token = self._argument(1)
        if token:
            self.write_u32(token, 1)
        self._set_result(0)

    def _sh_notify_check(self) -> None:
        changed = self._argument(1)
        if changed:
            self.write_u32(changed, 0)
        self._set_result(0)

    def _sh_notify_get_state(self) -> None:
        state = self._argument(1)
        if state:
            self.write_u64(state, 0)
        self._set_result(0)

    def _sh_audit_token_to_au32(self) -> None:
        for index, value in enumerate((0, 0, 0, 0, 0, 123, 100000, 1)):
            address = self._argument(index + 1)
            if address:
                self.write_u32(address, value)
        self._set_result(0)

    def _sh_basename(self) -> None:
        address = self._argument(0)
        value = self._read_cstring(address).rstrip(b"/")
        index = value.rfind(b"/")
        self._set_result(address + index + 1 if index >= 0 else address)

    def _sh_lstat(self) -> None:
        path = self._read_text(self._argument(0))
        is_directory = path in ("/var/db/fpsd/adi", "/var/db", "/var/setup")
        is_file = path in self.adi_files
        if not is_directory and not (_is_adi_state_path(path) and is_file):
            self._sh_return_minus_one()
            return
        result = self._argument(1)
        # Darwin's stat structure stores st_mode at byte offset four.
        self.mem_write(result + 4, b"\x80\x81" if is_file else b"\xed\x41")
        self._set_result(0)

    def _sh_bootstrap_look_up(self) -> None:
        service = self._argument(2)
        if service:
            self.write_u32(service, 0)
        self._set_result(5)  # KERN_FAILURE

    def _sh_bootstrap_check_in(self) -> None:
        port = self._argument(2)
        if port:
            self.write_u32(port, 1)
        self._set_result(0)

    def _sh_dlopen(self) -> None:
        path = self._read_text(self._argument(0))
        self._set_result(FAKE_HANDLE if path == _CORE_FP_PATH else 0)

    def _sh_dlsym(self) -> None:
        name = self._read_text(self._argument(1))
        self._set_result(self._core_exports.get("_" + name, 0))

    def _sh_current_time(self) -> None:
        address = self._argument(0)
        seconds = int(time.time())
        if address:
            self.write_u64(address, seconds)
        self._set_result(seconds)

    def _sh_clock_get_calendar_microtime(self) -> None:
        seconds_address = self._argument(0)
        microseconds_address = self._argument(1)
        now = time.time_ns()
        self.write_u32(seconds_address, now // 1_000_000_000)
        self.write_u32(microseconds_address, (now % 1_000_000_000) // 1000)
        self._set_result(0)

    def _sh_gettimeofday(self) -> None:
        time_addr = self._argument(0)
        zone_addr = self._argument(1)
        now = time.time_ns()
        if time_addr:
            self.mem_write(time_addr, struct.pack("<QI", now // 1_000_000_000, (now % 1_000_000_000) // 1000) + b"\x00" * 4)
        if zone_addr:
            self.mem_write(zone_addr, b"\x00" * 8)
        self._set_result(0)

    def _sh_gethostuuid(self) -> None:
        if self.host_uuid == bytes(16):
            raise SAPError("guest host UUID is unavailable")
        address = self._argument(0)
        if address:
            self.mem_write(address, self.host_uuid)
        self._set_result(0)

    def _sh_objc_msg_send(self) -> None:
        selector = self._read_text(self._argument(1))
        self._set_result(FAKE_HANDLE if selector == _KEYED_MESSAGE else 0)

    def _sh_open(self) -> None:
        path = self._read_text(self._argument(0))
        flags = self._argument(1)
        if path in ("/var/db", "/var/setup"):
            self._set_result(4)
            return
        if _is_adi_state_path(path):
            if path not in self.adi_files:
                if not flags & 0x200:  # O_CREAT
                    self._sh_return_minus_one()
                    return
                self.adi_files[path] = b""
            self._adi_path = path
            self._adi_offset = 0
            self._set_result(_ADI_FILE)
            return
        if path == _ICXS_PATH:
            self._icxs_offset = 0
            self._set_result(_CORE_FP_FILE)
            return
        self._sh_return_minus_one()

    def _sh_fstat(self) -> None:
        if self._argument(0) != _ADI_FILE:
            self._sh_return_minus_one()
            return
        result = self._argument(1)
        self.mem_write(result, b"\x00" * 144)
        self.mem_write(result + 4, b"\x80\x81")
        self.write_u64(result + 96, len(self.adi_files.get(self._adi_path, b"")))
        self._set_result(0)

    def _sh_ftruncate(self) -> None:
        if self._argument(0) != _ADI_FILE:
            self._sh_return_minus_one()
            return
        length = self._argument(1)
        if length > _MAX_MACH_MESSAGE:
            self._sh_return_minus_one()
            return
        data = self.adi_files.get(self._adi_path, b"")
        data = data[:length] if length <= len(data) else data + b"\x00" * (length - len(data))
        self.adi_files[self._adi_path] = data
        if self._adi_offset > len(data):
            self._adi_offset = len(data)
        self._set_result(0)

    def _sh_pthread_once(self) -> None:
        control = self._argument(0)
        initializer = self._argument(1)
        value = self.read_u64(control)
        if value in (0, _ONCE_DONE):
            self._set_result(0)
            return
        self.write_u64(control, _ONCE_DONE)
        self._invoke_callback(initializer)

    def _sh_proc_pid_path(self) -> None:
        buffer = self._argument(1)
        size = self._argument(2)
        if buffer == 0 or size < len(_PROCESS_PATH):
            self._sh_return_minus_one()
            return
        self.mem_write(buffer, _PROCESS_PATH)
        self._set_result(len(_PROCESS_PATH) - 1)

    def _sh_dispatch_once(self) -> None:
        predicate = self._argument(0)
        block = self._argument(1)
        if self.read_u64(predicate) == U64:
            self._set_result(0)
            return
        self.write_u64(predicate, U64)
        initializer = self.read_u64(block + 16)
        self._uc.reg_write(_arm.UC_ARM64_REG_X0, block)
        self._invoke_callback(initializer)

    def _invoke_callback(self, initializer: int) -> None:
        """Run a guest callback, then return to the shim's caller: the
        callback "returns" into callback.complete, which restores LR."""
        self._callback_returns.append(self._uc.reg_read(_arm.UC_ARM64_REG_LR))
        self._uc.reg_write(_arm.UC_ARM64_REG_LR, self._shim_symbols["callback.complete"])
        self._uc.reg_write(_arm.UC_ARM64_REG_PC, initializer)

    def _sh_callback_complete(self) -> None:
        if not self._callback_returns:
            raise SAPError("guest callback completion has no return address")
        self._uc.reg_write(_arm.UC_ARM64_REG_LR, self._callback_returns.pop())
        self._set_result(0)

    def _sh_read(self) -> None:
        descriptor = self._argument(0)
        buffer = self._argument(1)
        requested = self._argument(2)
        if descriptor == _ADI_FILE:
            size = self._checked_size(requested)
            data = self.adi_files.get(self._adi_path, b"")
            size = min(size, len(data) - self._adi_offset)
            if size > 0:
                self.mem_write(buffer, data[self._adi_offset : self._adi_offset + size])
                self._adi_offset += size
            self._set_result(max(size, 0))
            return
        if descriptor != _CORE_FP_FILE:
            self._sh_return_minus_one()
            return
        size = self._checked_size(requested)
        size = min(size, len(self._icxs) - self._icxs_offset)
        if size:
            self.mem_write(buffer, self._icxs[self._icxs_offset : self._icxs_offset + size])
            self._icxs_offset += size
        self._set_result(size)

    def _sh_write(self) -> None:
        if self._argument(0) != _ADI_FILE:
            self._sh_return_minus_one()
            return
        buffer = self._argument(1)
        size = self._checked_size(self._argument(2))
        data = self.mem_read(buffer, size)
        state = bytearray(self.adi_files.get(self._adi_path, b""))
        end = self._adi_offset + size
        if end > len(state):
            state.extend(b"\x00" * (end - len(state)))
        state[self._adi_offset : end] = data
        self.adi_files[self._adi_path] = bytes(state)
        self._adi_offset = end
        self._set_result(size)

    def _sh_unlink(self) -> None:
        path = self._read_text(self._argument(0))
        if _is_adi_state_path(path):
            self.adi_files.pop(path, None)
            self._adi_offset = 0
            self._set_result(0)
            return
        self._sh_return_minus_one()

    def _sh_sysctlbyname(self) -> None:
        name = self._read_text(self._argument(0))
        output = self._argument(1)
        length_address = self._argument(2)
        if name in ("kern.monotonicclock", "hw.ncpu", "hw.logicalcpu", "hw.physicalcpu", "hw.optional.arm64"):
            value = struct.pack("<I", 1)
        elif name == "hw.memsize":
            value = struct.pack("<Q", 8 << 30)
        elif name == "hw.machine":
            value = b"arm64\x00"
        elif name == "hw.model":
            value = b"MacBookPro13,3\x00"
        elif name == "kern.osversion":
            value = b"16G29\x00"
        else:
            self._sh_return_minus_one()
            return
        if length_address:
            requested = self.read_u64(length_address)
            if output and requested < len(value):
                self._sh_return_minus_one()
                return
            if output:
                self.mem_write(output, value)
            self.write_u64(length_address, len(value))
        self._set_result(0)

    def _sh_sysconf(self) -> None:
        from .machine import HEAP_SIZE, PAGE_SIZE

        name = self._argument(0)
        if name == 29:  # _SC_PAGESIZE
            self._set_result(PAGE_SIZE)
        elif name in (57, 58):  # _SC_NPROCESSORS_CONF / _ONLN
            self._set_result(1)
        elif name == 200:  # _SC_PHYS_PAGES
            self._set_result(HEAP_SIZE // PAGE_SIZE)
        else:
            self._sh_return_minus_one()

    def _max_transfer(self) -> int:
        from .machine import MAX_GUEST_TRANSFER

        return MAX_GUEST_TRANSFER


def emulate_ioaes(source: bytes, iv: bytes, operation: int, key_data: bytes):
    """ioaes.go: the device-key handle the pinned FairPlay runtime uses,
    evaluated without the host operating system (AES-CBC, zero key)."""
    from .aecrypto import aes_cbc_decrypt, aes_cbc_encrypt

    if not source or len(source) % 16 or len(iv) != 16 or len(key_data) != 40:
        raise SAPError("invalid IOAES parameters")
    handle = struct.unpack_from("<I", key_data, 36)[0]
    if handle != COMMERCE_AES_HANDLE:
        raise SAPError(f"unsupported IOAES key handle {handle:#x}")
    key = bytes(16)
    if operation == 0:
        destination = aes_cbc_encrypt(key, iv, source)
        return destination, destination[-16:]
    if operation == 1:
        return aes_cbc_decrypt(key, iv, source), source[-16:]
    raise SAPError(f"unsupported IOAES operation {operation:#x}")
