"""Foundation, libdispatch, Objective-C runtime and libSystem services.

Port of ipatool ``internal/store/emulator`` bridge.go, notifications.go,
accounts.go, compression.go, delegate.go and the message half of network.go
(ipatool 2.8, MIT). Mixed into ``runtime.Runtime``. The Store's network
requests are made by this project's own client, so a guest attempt to run
an NSURLSession data task is refused instead of being executed.
"""
from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import plistlib
import struct
import time
import unicodedata
import zlib
from typing import Any, Callable, Dict, List

from .gotypes import GoTime, go_sprint, parse_http_date
from .goutil import (
    GoURL,
    canonical_header_key,
    glen,
    path_base,
    path_ext,
    path_join,
    path_unescape,
    query_escape,
    query_unescape,
    url_join_path,
    utf16_decode,
    utf16_length,
    utf16_units,
)

U64 = (1 << 64) - 1
_NOT_FOUND = 0x7FFFFFFFFFFFFFFF


def bool_value(value: bool) -> int:
    return 1 if value else 0


def _is_int(value: Any) -> bool:
    return type(value) is int


def _is_bool(value: Any) -> bool:
    return type(value) is bool


def _setter_key(selector: str) -> str:
    key = selector[3:-1]
    if len(key) < 2 or not ("A" <= key[1] <= "Z"):
        key = key[:1].lower() + key[1:]
    return key


def _is_setter(selector: str) -> bool:
    return selector.startswith("set") and selector.endswith(":") and selector.count(":") == 1


def _to_signed(value: int) -> int:
    value &= U64
    return value - (1 << 64) if value >> 63 else value


def _f64(bits: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", bits & U64))[0]


def _bits(value: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", value))[0]


def _f32_bits(value: float) -> int:
    try:
        return struct.unpack("<I", struct.pack("<f", value))[0]
    except OverflowError:
        return struct.unpack("<I", struct.pack("<f", math.copysign(math.inf, value)))[0]


def _compare(a: str, b: str) -> int:
    x, y = a.encode("utf-8", "surrogateescape"), b.encode("utf-8", "surrogateescape")
    return (x > y) - (x < y)


class _Cookie:
    __slots__ = ("name", "value", "domain", "path", "secure", "http_only", "expires")

    def __init__(self, name="", value="", domain="", path="", secure=False, http_only=False, expires=None):
        self.name, self.value, self.domain, self.path = name, value, domain, path
        self.secure, self.http_only, self.expires = secure, http_only, expires


class _Inflate:
    __slots__ = ("bits", "input", "output", "position", "decoded")

    def __init__(self, bits: int) -> None:
        self.bits = bits
        self.input = bytearray()
        self.output = b""
        self.position = 0
        self.decoded = False


class BridgeMixin:
    # -- typed access to host objects -----------------------------------------

    def obj(self, address: int):
        from .runtime import GuestPanic

        value = self.objects.get(address)
        if value is None:
            raise GuestPanic(f"unknown guest object {address:#x}")
        return value

    def dict_of(self, address: int) -> Dict[str, int]:
        from .runtime import GuestPanic

        value = self.obj(address).value
        if not isinstance(value, dict):
            raise GuestPanic(f"object {self.obj(address).cls} is not a dictionary")
        return value

    def list_of(self, address: int) -> List[int]:
        from .runtime import GuestPanic

        value = self.obj(address).value
        if not isinstance(value, list):
            raise GuestPanic(f"object {self.obj(address).cls} is not an array")
        return value

    def bytes_of(self, address: int) -> bytes:
        from .runtime import GuestPanic

        value = self.obj(address).value
        if not isinstance(value, (bytes, bytearray)):
            raise GuestPanic(f"object {self.obj(address).cls} is not data")
        return bytes(value)

    def time_of(self, address: int) -> GoTime:
        from .runtime import GuestPanic

        value = self.obj(address).value
        if not isinstance(value, GoTime):
            raise GuestPanic(f"object {self.obj(address).cls} is not a date")
        return value

    def panic(self, message: str):
        from .runtime import GuestPanic

        raise GuestPanic(message)

    # -- imported functions (bridge.go symbol) ------------------------------

    def symbol(self, name: str) -> None:
        from .runtime import REG_LR, REG_X1

        if self.compression_symbol(name):
            return
        arg, sett = self.arg, self.set
        if name == "AMSError":
            # The plugin's factory for a server dialog when native presentation
            # is off: kept as an NSError so the request can finish.
            info: Dict[str, int] = {}
            if arg(1):
                info["NSLocalizedDescription"] = arg(1)
            if arg(2):
                info["NSLocalizedFailureReason"] = arg(2)
            if arg(3):
                info["NSUnderlyingError"] = arg(3)
            sett(self.new("NSError", {"domain": self.new("NSString", "AMSErrorDomain"),
                                      "code": self.new("NSNumber", _to_signed(arg(0))),
                                      "userInfo": self.new("NSDictionary", info)}))
        elif name == "xpc_get_type":
            value = self.objects.get(arg(0))
            sett(self.profile.metadata.symbols.get("__xpc_type_dictionary", 0)
                 if value is not None and value.cls == "HostXPCDictionary" else 0)
        elif name == "CC_SHA512":
            length = arg(1) & 0xFFFFFFFF
            if length > (64 << 20):
                self.panic("SHA-512 input exceeds runtime budget")
            digest = hashlib.sha512(self.mem_read(arg(0), length)).digest()
            output = arg(2) or self.alloc(64)
            self.mem_write(output, digest)
            sett(output)
        elif name == "strftime":
            out, limit, layout, tm = arg(0), arg(1), self.cstring(arg(2)), arg(3)
            if layout != "%a, %d %b %Y %H:%M:%S GMT":
                self.panic("unsupported date output format " + layout)
            fields = struct.unpack("<9i", self.mem_read(tm, 36))
            value = GoTime.date(fields[5] + 1900, fields[4] + 1, fields[3], fields[2], fields[1], fields[0]).http_date()
            if len(value) + 1 > limit:
                sett(0)
                return
            self.mem_write(out, value.encode("ascii") + b"\0")
            sett(len(value))
        elif name == "strptime":
            value, layout, out = self.cstring(arg(0)), self.cstring(arg(1)), arg(2)
            if layout not in ("%a, %d %b %Y %H:%M:%S GMT", "%a, %d %b %Y %H:%M:%S %Z"):
                self.panic("unsupported date format " + layout)
            try:
                date = parse_http_date(value)
            except ValueError:
                sett(0)
                return
            second, minute, hour, day, month, year, weekday, yearday = date.fields()
            for index, field in enumerate((second, minute, hour, day, month, year, weekday, yearday, 0)):
                self.write32(out + index * 4, field)
            sett(arg(0) + glen(value))
        elif name == "timegm":
            fields = struct.unpack("<9i", self.mem_read(arg(0), 36))
            sett(GoTime.date(fields[5] + 1900, fields[4] + 1, fields[3], fields[2], fields[1], fields[0]).seconds)
        elif name == "CFURLResponseCopyPeerAddress":
            sett(0)  # the portable response has no peer-address metadata
        elif name == "res_9_ndestroy":
            return
        elif name == "res_9_ninit":
            sett(0xFFFFFFFF)  # no resolver diagnostics
        elif name == "CRIsAutoSubmitEnabled":
            sett(0)
        elif name in ("NSUserName", "NSFullUserName"):
            sett(self.new("NSString", "ipatool"))
        elif name == "NSTemporaryDirectory":
            sett(self.new("NSString", "/ipatool/tmp/"))
        elif name in ("CPSharedResourcesDirectory", "NSHomeDirectory"):
            sett(self.new("NSString", "/ipatool"))
        elif name in ("getuid", "geteuid"):
            sett(501)
        elif name in ("getgid", "getegid"):
            sett(20)
        elif name == "NSSearchPathForDirectoriesInDomains":
            if arg(0) != 5 or arg(1) != 8:
                self.panic("unsupported virtual filesystem directory")
            sett(self.new("NSArray", [self.new("NSString", "/System/Library")]))
        elif name in ("MGCopyAnswerWithError", "MGCopyAnswer"):
            key = self.string(arg(0))
            values = {"BuildVersion": "26A434", "ProductVersion": "27.0.1", "DeviceClass": "Mac", "ProductType": "Mac14,2"}
            if key not in values:
                self.panic("unsupported device property " + key)
            if name == "MGCopyAnswerWithError" and arg(2):
                self.mem_write(arg(2), b"\0\0\0\0")
            sett(self.new("NSString", values[key]))
        elif name == "time":
            now = int(time.time())
            if arg(0):
                self.write64(arg(0), now)
            sett(now)
        elif name in ("localtime", "localtime_r", "gmtime_r"):
            now = GoTime(_to_signed(self.read64(arg(0))), 0)
            out = arg(1) if name != "localtime" else self.alloc(56)
            data = bytearray(56)
            second, minute, hour, day, month, year, weekday, yearday = now.fields()
            for index, field in enumerate((second, minute, hour, day, month, year, weekday, yearday, 0)):
                struct.pack_into("<I", data, index * 4, field & 0xFFFFFFFF)
            self.mem_write(out, bytes(data))
            sett(out)
        elif name == "objc_getAssociatedObject":
            sett(self.associations.get(arg(0), {}).get(arg(1), 0))
        elif name == "objc_setAssociatedObject":
            target, key, value, policy = arg(0), arg(1), arg(2), arg(3)
            table = self.associations.setdefault(target, {})

            def save(stored: int) -> None:
                table[key] = stored
                sett(0)

            if policy & 255 == 3:
                self.copy_value(value, save)
            else:
                save(value)
        elif name == "CFPreferencesGetAppIntegerValue":
            stored = self.objects.get(self.preferences.get(self.string(arg(1)) + "/" + self.string(arg(0)), 0))
            value, valid = 0, False
            if stored is not None and _is_int(stored.value):
                value, valid = stored.value, True
            if arg(2):
                self.mem_write(arg(2), bytes([bool_value(valid)]))
            sett(value)
        elif name == "CFPreferencesGetAppBooleanValue":
            stored = self.objects.get(self.preferences.get(self.string(arg(1)) + "/" + self.string(arg(0)), 0))
            value, valid = False, False
            if stored is not None:
                if _is_bool(stored.value):
                    value, valid = stored.value, True
                elif _is_int(stored.value):
                    value, valid = stored.value != 0, True
            if arg(2):
                self.mem_write(arg(2), bytes([bool_value(valid)]))
            sett(bool_value(value))
        elif name in ("CFPreferencesAppSynchronize", "CFPreferencesSynchronize"):
            sett(1)
        elif name in ("CFPreferencesCopyAppValue", "CFPreferencesCopyValue"):
            sett(self.preferences.get(self.string(arg(1)) + "/" + self.string(arg(0)), 0))
        elif name in ("CFPreferencesSetAppValue", "CFPreferencesSetValue"):
            self.preferences[self.string(arg(2)) + "/" + self.string(arg(0))] = arg(1)
            sett(0)
        elif name in ("objc_opt_self", "objc_unsafeClaimAutoreleasedReturnValue", "objc_retain",
                      "objc_retainAutoreleasedReturnValue", "objc_claimAutoreleasedReturnValue",
                      "objc_autoreleaseReturnValue", "objc_autorelease", "objc_retainAutoreleaseReturnValue",
                      "objc_retainAutorelease", "objc_release", "objc_autoreleasePoolPop"):
            return
        elif name == "objc_autoreleasePoolPush":
            sett(0)
        elif name == "objc_getProperty":
            sett(self.read64(arg(0) + arg(2)))
        elif name in ("objc_setProperty_nonatomic", "objc_setProperty_atomic"):
            self.write64(arg(0) + arg(3), arg(2))
        elif name in ("objc_setProperty_nonatomic_copy", "objc_setProperty_atomic_copy"):
            destination, value = arg(0) + arg(3), arg(2)

            def store(copied: int) -> None:
                self.write64(destination, copied)
                sett(0)

            self.copy_value(value, store)
        elif name in ("objc_storeStrong", "objc_storeWeak", "objc_initWeak"):
            self.write64(arg(0), arg(1))
            sett(arg(1))
        elif name == "objc_copyWeak":
            self.write64(arg(0), self.read64(arg(1)))
        elif name == "objc_moveWeak":
            self.write64(arg(0), self.read64(arg(1)))
            self.write64(arg(1), 0)
        elif name in ("objc_loadWeakRetained", "objc_loadWeak"):
            sett(self.read64(arg(0)))
        elif name == "objc_destroyWeak":
            self.write64(arg(0), 0)
        elif name in ("objc_alloc", "objc_allocWithZone", "objc_alloc_init", "objc_opt_new"):
            cls = self.class_names.get(arg(0), "")
            if not cls:
                self.panic(f"unknown allocated class {arg(0):#x}")
            created = self.new(cls, None)
            sett(created)
            if name not in ("objc_alloc", "objc_allocWithZone"):
                self.message(created, "init", False)
        elif name == "objc_opt_class":
            if arg(0) in self.class_names:
                return
            value = self.objects.get(arg(0))
            if value is None:
                self.panic(f"unknown object class {arg(0):#x}")
            description = self.classes.get(value.cls)
            if description is None:
                self.panic(f"unknown class {value.cls}")
            sett(description.address)
        elif name == "objc_opt_isKindOfClass":
            value = self.objects.get(arg(0))
            if value is None:
                sett(0)
                return
            sett(bool_value(self.kind_of(value.cls, self.class_names.get(arg(1), ""))))
        elif name == "objc_opt_respondsToSelector":
            sett(bool_value(self.responds(arg(0), self.cstring(arg(1)))))
        elif name == "objc_msgSend":
            self.message(arg(0), self.cstring(arg(1)), False)
        elif name == "objc_msgSendSuper2":
            super_struct = arg(0)
            receiver = self.read64(super_struct)
            cls = self.class_names.get(self.read64(super_struct + 8), "")
            selector = self.cstring(arg(1))
            meta = receiver in self.class_names
            description = self.classes.get(cls)
            if description is not None:
                entry = self.lookup(description.super, selector, meta)
                if entry:
                    self.jump(entry, receiver, selector)
                    return
            self.message(receiver, selector, True)
        elif name == "CFBundleGetMainBundle":
            sett(self.bundle())
        elif name == "CFBundleGetInfoDictionary":
            sett(self.bundle_info())
        elif name == "CFBundleGetValueForInfoDictionaryKey":
            sett(self.dict_of(self.bundle_info()).get(self.string(arg(1)), 0))
        elif name == "CFBundleCopyExecutableURL":
            sett(self.new("NSURL", "file:///ipatool"))
        elif name == "getprogname":
            pointer = self.alloc(8)
            self.mem_write(pointer, b"ipatool\0")
            sett(pointer)
        elif name in ("getpid", "_getpid"):
            sett(123)
        elif name == "CFGetTypeID":
            value = self.objects.get(arg(0))
            if value is None:
                self.panic("CFGetTypeID of unknown object")
            if _is_bool(value.value):
                sett(4)
            elif isinstance(value.value, (bytes, bytearray)):
                sett(1)
            elif isinstance(value.value, str):
                sett(2)
            else:
                sett(3)
        elif name == "CFBooleanGetTypeID":
            sett(4)
        elif name == "CFBooleanGetValue":
            value = self.obj(arg(0)).value
            if not _is_bool(value):
                self.panic("CFBooleanGetValue of a non-boolean")
            sett(bool_value(value))
        elif name == "CFDataGetTypeID":
            sett(1)
        elif name == "CFStringGetTypeID":
            sett(2)
        elif name == "IOMasterPort":
            self.write32(arg(1), 1)
            sett(0)
        elif name == "IOServiceMatching":
            sett(self.new("NSDictionary", {"IOProviderClass": self.new("NSString", self.cstring(arg(0)))}))
        elif name == "IOBSDNameMatching":
            sett(self.new("NSDictionary", {"IOBSDName": self.new("NSString", self.cstring(arg(2)))}))
        elif name == "IOServiceGetMatchingService":
            sett(0)  # no platform expert / serial service
        elif name == "IOServiceGetMatchingServices":
            self.write32(arg(2), 1)
            sett(0)
        elif name == "IOIteratorNext":
            sett(1)
        elif name == "IORegistryEntryGetParentEntry":
            self.write32(arg(2), 2)
            sett(0)
        elif name in ("IORegistryEntryCreateCFProperty", "IORegistryEntrySearchCFProperty"):
            if arg(0) == 0:
                sett(0)
                return
            key = self.string(arg(2 if name == "IORegistryEntrySearchCFProperty" else 1))
            if key in ("IOBuiltin", "IOPrimaryInterface"):
                sett(self.new("NSNumber", True))
            elif key == "IOMACAddress":
                sett(self.new("NSData", bytes(self.hardware_id)))
            else:
                self.panic("unsupported IOKit property " + key)
        elif name in ("IOObjectRelease", "CFRelease"):
            sett(0)
        elif name == "CFDataGetLength":
            sett(len(self.bytes_of(arg(0))))
        elif name == "CFDataGetBytePtr":
            data = self.bytes_of(arg(0))
            pointer = self.alloc(len(data))
            self.mem_write(pointer, data)
            sett(pointer)
        elif name == "CFDataGetBytes":
            data = self.bytes_of(arg(0))
            start, length, destination = arg(1), arg(2), arg(3)
            if start + length > len(data):
                self.panic("CFDataGetBytes range exceeds data")
            self.mem_write(destination, data[start:start + length])
            sett(0)
        elif name == "CFUUIDCreate":
            data = bytearray(os.urandom(16))
            data[6] = (data[6] & 15) | 64
            data[8] = (data[8] & 63) | 128
            sett(self.new("HostUUID", bytes(data)))
        elif name == "CFUUIDGetUUIDBytes":
            data = self.bytes_of(arg(0))
            sett(struct.unpack_from("<Q", data, 0)[0])
            self.set_reg(REG_X1, struct.unpack_from("<Q", data, 8)[0])
        elif name == "NSClassFromString":
            sett(self.class_address(self.string(arg(0))))
        elif name == "class_getMethodImplementation":
            sett(self.lookup(self.class_names.get(arg(0), ""), self.cstring(arg(1)), False))
        elif name == "sel_getName":
            return
        elif name == "objc_getClass":
            sett(self.class_address(self.cstring(arg(0))))
        elif name == "NSStringFromClass":
            sett(0 if arg(0) == 0 else self.new("NSString", self.class_names.get(arg(0), "")))
        elif name == "NSSelectorFromString":
            sett(self.selector(self.string(arg(0))))
        elif name == "NSStringFromSelector":
            sett(self.new("NSString", self.cstring(arg(0))))
        elif name == "SecTaskCreateFromSelf":
            sett(self.new("HostSecurityTask", None))
        elif name == "SecTaskCopyValueForEntitlement":
            if arg(2):
                self.write64(arg(2), 0)
            sett(0)
        elif name == "dispatch_time":
            base = arg(0) or time.time_ns()
            sett(base + arg(1))
        elif name == "dispatch_after":
            deadline, block = arg(0), arg(2)

            def schedule(copied: int) -> None:
                self.timers.append((deadline, copied))
                sett(0)

            self.copy_block(block, schedule)
        elif name == "dispatch_assert_queue":
            if not self.queue_is_within(self.current_queue, arg(0)):
                self.panic(f"dispatch queue mismatch: running {self.current_queue:#x} expected {arg(0):#x}")
        elif name == "dispatch_sync":
            previous = self.current_queue
            self.current_queue = arg(0)

            def finished() -> None:
                self.current_queue = previous
                sett(0)

            self.callback(arg(1), [], finished)
        elif name == "dispatch_sync_f":
            previous = self.current_queue
            self.current_queue = arg(0)

            def finished_f() -> None:
                self.current_queue = previous
                sett(0)

            self.callback_function(arg(2), [arg(1)], finished_f)
        elif name == "dispatch_block_create":
            self.copy_block(arg(1), sett)
        elif name == "dispatch_async":
            queue = arg(0)

            def enqueue(block: int) -> None:
                self.queue_pending(block, queue)
                sett(0)

            self.copy_block(arg(1), enqueue)
        elif name == "dispatch_suspend":
            queue = self.obj(arg(0))
            queue.props["suspendCount"] = queue.props.get("suspendCount", 0) + 1
        elif name == "dispatch_resume":
            queue = self.obj(arg(0))
            if queue.props.get("suspendCount", 0) == 0:
                self.panic("resuming active dispatch queue")
            queue.props["suspendCount"] -= 1
        elif name in ("dispatch_retain", "dispatch_release"):
            return
        elif name == "dispatch_semaphore_create":
            sett(self.new("HostSemaphore", _to_signed(arg(0))))
        elif name == "dispatch_semaphore_signal":
            semaphore = self.obj(arg(0))
            semaphore.value = semaphore.value + 1
            sett(0)
        elif name == "dispatch_semaphore_wait":
            semaphore = self.obj(arg(0))
            if semaphore.value > 0:
                semaphore.value -= 1
                sett(0)
            elif self.pending:
                block = self.next_pending()
                if block == 0:
                    self.panic("all pending queues are suspended")

                def signalled() -> None:
                    if semaphore.value == 0:
                        self.panic("guest semaphore remains unsignaled")
                    semaphore.value -= 1
                    sett(0)

                self.pending_callback(block, signalled)
            else:
                self.panic("guest waits on an unavailable host service")
        elif name in ("Block_copy", "objc_retainBlock"):
            self.copy_block(arg(0), sett)
        elif name in ("Block_release", "Block_object_dispose"):
            return
        elif name == "Block_object_assign":
            destination, value, flags = arg(0), arg(1), arg(2)
            if flags & 0xF == 7:
                self.copy_block(value, lambda copied: self.write64(destination, copied))
            elif flags & 8:
                self.copy_byref(value, lambda copied: self.write64(destination, copied))
            else:
                self.write64(destination, value)
        elif name == "dispatch_once":
            predicate, block = arg(0), arg(1)
            if self.read64(predicate) != 0:
                sett(0)
                return
            self.write64(predicate, U64)
            self.pending_callback(block, lambda: sett(0))
        elif name in ("swift_once", "dispatch_once_f"):
            if name == "swift_once":
                predicate, function, context = arg(0), arg(1), arg(2)
            else:
                predicate, context, function = arg(0), arg(1), arg(2)
            if self.read64(predicate) != 0:
                sett(0)
                return
            self.write64(predicate, U64)
            self.callback_function(function, [context], lambda: sett(0))
        elif name in ("dispatch_queue_attr_make_with_autorelease_frequency", "dispatch_queue_attr_make_with_qos_class"):
            return
        elif name == "dispatch_queue_create_with_target":
            target = arg(2)
            queue = self.new("HostQueue", None)
            self.objects[queue].props["targetQueue"] = target
            sett(queue)
        elif name == "dispatch_set_target_queue":
            self.obj(arg(0)).props["targetQueue"] = arg(1)
        elif name in ("dispatch_queue_create", "dispatch_get_global_queue", "dispatch_get_main_queue"):
            sett(self.new("HostQueue", None))
        elif name in ("os_unfair_lock_assert_not_owner", "objc_sync_enter", "objc_sync_exit",
                      "os_unfair_lock_lock_with_options", "os_unfair_lock_lock", "os_unfair_lock_unlock",
                      "os_unfair_lock_assert_owner", "os_unfair_recursive_lock_lock_with_options",
                      "os_unfair_recursive_lock_unlock"):
            sett(0)
        elif name == "os_feature_enabled_impl":
            key = self.cstring(arg(0)) + "/" + self.cstring(arg(1))
            features = self.profile.metadata.features
            if key not in features:
                self.panic("unresolved native feature flag " + key)
            sett(bool_value(bool(features[key])))
        elif name == "os_log_create":
            sett(self.new("HostOSLog", None))
        elif name in ("os_signpost_enabled", "os_log_type_enabled", "os_variant_has_internal_content"):
            sett(0)
        elif name == "malloc_size":
            sett(self.allocations.get(arg(0), 0))
        elif name in ("malloc", "calloc", "malloc_type_malloc", "malloc_type_calloc"):
            size = arg(0)
            if name in ("calloc", "malloc_type_calloc"):
                if size != 0 and arg(1) > (64 << 20) // size:
                    self.panic("guest calloc exceeds heap budget")
                size *= arg(1)
            sett(self.alloc(size))
        elif name in ("chkstk_darwin", "free"):
            return
        elif name in ("platform_memmove", "platform_memcpy", "memcpy", "memmove", "memcpy_chk", "memmove_chk"):
            if arg(2) == 0:
                return
            if arg(2) > (64 << 20):
                self.panic("guest copy exceeds memory budget")
            self.mem_write(arg(0), self.mem_read(arg(1), arg(2)))
        elif name in ("memset", "memset_chk"):
            if arg(2) > (64 << 20):
                self.panic("guest fill exceeds memory budget")
            if arg(2):
                self.mem_write(arg(0), bytes([arg(1) & 0xFF]) * arg(2))
        elif name == "strlen":
            sett(glen(self.cstring(arg(0))))
        else:
            if self.swift_symbol(name):
                return
            self.panic(f"unsupported import {name} lr={self.reg(REG_LR):#x}")

    def kind_of(self, cls: str, target: str) -> bool:
        if cls == target or target == "NSObject":
            return True
        while cls:
            description = self.classes.get(cls)
            if description is None:
                return False
            if description.super == target:
                return True
            cls = description.super
        return False

    # -- Objective-C messages (bridge.go message) -----------------------------

    def message(self, receiver: int, selector: str, is_super: bool) -> None:
        from .runtime import HEAP_BASE, REG_D0, REG_SP, REG_X1, STACK_BASE, STACK_SIZE

        if receiver == 0:
            self.set_reg(REG_X1, 0)
            for register in range(REG_D0, REG_D0 + 4):
                self.set_reg(register, 0)
            self.set(0)
            return
        cls = self.class_names.get(receiver)
        meta = cls is not None
        target = self.objects.get(receiver)
        if not meta:
            if target is None:
                if selector == "copy" and HEAP_BASE <= receiver < STACK_BASE + STACK_SIZE:
                    self.copy_block(receiver, self.set)
                    return
                self.panic(f"unknown receiver {receiver:#x} for {selector}")
            cls = target.cls
        arg, sett = self.arg, self.set

        if cls == "HostUnavailableProxy":
            error = self.new("NSError", {"domain": self.new("NSString", "NSCocoaErrorDomain"),
                                         "code": self.new("NSNumber", 4099),
                                         "userInfo": self.new("NSDictionary", {})})
            self.callback(target.props.get("errorBlock", 0), [error], lambda: sett(0))
            return
        # Logging is a host service; it must not pull the platform's logging
        # infrastructure into the guest.
        if cls == "AMSLogConfig" or (cls == "AMSConcurrency" and selector == "logFaultFromSwiftConcurrencyOnInternalBuild"):
            sett(0)
            return
        # Keep-alives request host process assertions; a scoped token is enough.
        if cls == "AMSKeepAlive":
            if selector in ("keepAliveWithName:style:", "rbs_keepAliveWithName:style:"):
                if meta:
                    value = self.new("AMSKeepAlive", None)
                    self.objects[value].props["name"] = arg(2)
                    self.objects[value].props["style"] = arg(3)
                    sett(value)
                    return
            elif selector in ("invalidate", "rbs_invalidate"):
                sett(0)
                return
            elif selector in ("name", "style"):
                sett(target.props.get(selector, 0) if target is not None else 0)
                return

        entry = self.lookup(cls, selector, meta)
        if not is_super and entry:
            self.jump(entry, receiver, selector)
            return
        if self.notification_message(receiver, cls, selector, meta):
            return
        if self.account_message(receiver, cls, selector, meta):
            return
        if self.network_message(receiver, cls, selector, meta):
            return

        if not meta and cls in ("NSURLSessionConfiguration", "NSOperationQueue", "NSCache"):
            if _is_setter(selector):
                target.props[_setter_key(selector)] = arg(2)
                sett(0)
                return
            if selector in target.props:
                sett(target.props[selector])
                return

        if selector == "initWithObjectsAndKeys:" or (meta and selector == "dictionaryWithObjectsAndKeys:"):
            values: Dict[str, int] = {}
            value = arg(2)
            sp = self.reg(REG_SP)
            index = 0
            while value != 0:
                if index > 1024:
                    self.panic("dictionary varargs exceeds budget")
                key = self.read64(sp + index * 16)
                values[self.collection_key(key)] = value
                value = self.read64(sp + index * 16 + 8)
                index += 1
            if meta:
                sett(self.new(cls, values))
            else:
                target.value = values
                sett(receiver)
            return

        if meta:
            self._class_message(receiver, cls, selector)
            return
        self._instance_message(receiver, target, cls, selector)

    def _class_message(self, receiver: int, cls: str, selector: str) -> None:
        from .runtime import REG_D0, REG_SP, method_key

        arg, sett = self.arg, self.set
        if selector == "instanceMethodForSelector:":
            sett(self.lookup(cls, self.cstring(arg(2)), False))
        elif selector in ("alloc", "allocWithZone:"):
            sett(self.new(cls, None))
        elif selector == "new":
            created = self.new(cls, None)
            sett(created)
            self.message(created, "init", False)
        elif selector == "isSubclassOfClass:":
            sett(bool_value(self.kind_of(cls, self.class_names.get(arg(2), ""))))
        elif selector == "class":
            sett(receiver)
        elif selector in ("setWithObjects:", "arrayWithObjects:"):
            items: List[int] = []
            first = arg(2)
            if first:
                items.append(first)
                sp = self.reg(REG_SP)
                for index in range(1024):
                    value = self.read64(sp + index * 8)
                    if value == 0:
                        break
                    items.append(value)
            sett(self.new(cls, items))
        elif selector == "dictionaryWithDictionary:":
            sett(self.new(cls, dict(self.dict_of(arg(2)))))
        elif selector in ("fileURLWithPath:", "fileURLWithPath:isDirectory:"):
            sett(self.new("NSURL", GoURL(scheme="file", path=self.string(arg(2))).string()))
        elif selector == "URLWithString:":
            sett(self.new("NSURL", self.string(arg(2))))
        elif selector in ("setWithObject:", "arrayWithObject:"):
            sett(self.new(cls, [arg(2)]))
        elif selector == "setWithArray:":
            sett(self.new(cls, list(self.list_of(arg(2))) if arg(2) else []))
        elif selector == "UUID":
            sett(self.new("NSUUID", self.new_uuid_string()))
        elif selector == "distantPast":
            sett(self.new("NSDate", GoTime(-62135769600, 0)))
        elif selector == "distantFuture":
            sett(self.new("NSDate", GoTime.date(4001, 1, 1)))
        elif selector in ("dateWithTimeIntervalSinceNow:", "dateWithTimeIntervalSince1970:"):
            seconds = _f64(self.reg(REG_D0))
            if math.isnan(seconds) or math.isinf(seconds):
                self.panic("unsupported date interval")
            if selector == "dateWithTimeIntervalSinceNow:":
                now = time.time_ns()
                seconds += float(now // 1_000_000_000) + float(now % 1_000_000_000) / 1e9
            if seconds <= -(2 ** 63) or seconds >= 2 ** 63:
                self.panic("date interval exceeds supported range")
            sett(self.new("NSDate", GoTime.from_float(seconds)))
        elif selector in ("date", "now"):
            sett(self.new("NSDate", GoTime.now()))
        elif selector in ("defaultSessionConfiguration", "ephemeralSessionConfiguration"):
            created = self.new("NSURLSessionConfiguration", None)
            self.objects[created].props = {"usesClassicLoadingMode": 1, "protocolClasses": self.new("NSArray", []),
                                           "HTTPShouldSetCookies": 1, "HTTPMaximumConnectionsPerHost": 6}
            sett(created)
        elif selector == "interfaceWithProtocol:":
            sett(self.new("NSXPCInterface", None))
        elif selector == "currentThread":
            sett(self.new("NSThread", None))
        elif selector == "isMainThread":
            sett(1)
        elif selector == "null":
            if self.null_object == 0:
                self.null_object = self.new("NSNull", None)
            sett(self.null_object)
        elif selector == "standardUserDefaults":
            sett(self.new("NSUserDefaults", {}))
        elif selector == "preferredLanguages":
            sett(self.new("NSArray", [self.new("NSString", "en-US")]))
        elif selector == "decimalDigitCharacterSet":
            sett(self.new("NSCharacterSet", "0123456789"))
        elif selector == "characterSetWithCharactersInString:":
            sett(self.new("NSCharacterSet", self.string(arg(2))))
        elif selector in ("currentLocale", "systemLocale"):
            sett(self.new("NSLocale", "en_US"))
        elif selector == "defaultManager":
            sett(self.new("NSFileManager", None))
        elif selector == "bundleWithPath:":
            if self.string(arg(2)) != "/System/Library/Frameworks/WebKit.framework":
                sett(0)
                return
            bundle = self.new("NSBundle", None)
            self.objects[bundle].props = {"bundlePath": arg(2), "infoDictionary": self.new(
                "NSDictionary", {"CFBundleVersion": self.new("NSString", "22625.1.29.11.28")})}
            sett(bundle)
        elif selector == "bundleForClass:":
            bundle = self.bundle()
            if "AMS" in self.class_names.get(arg(2), ""):
                self.objects[bundle].props["bundleIdentifier"] = self.new("NSString", "com.apple.AppleMediaServices")
            sett(bundle)
        elif selector == "mainBundle":
            sett(self.bundle())
        elif selector == "processInfo":
            created = self.new("NSProcessInfo", None)
            self.objects[created].props = {"processName": self.new("NSString", "ipatool"),
                                           "environment": self.new("NSDictionary", {})}
            sett(created)
        elif selector in ("dictionary", "dictionaryWithCapacity:"):
            sett(self.new(cls, {}))
        elif selector in ("weakToStrongObjectsMapTable", "weakToWeakObjectsMapTable", "strongToWeakObjectsMapTable",
                          "strongToStrongObjectsMapTable"):
            sett(self.new("NSMapTable", {}))
        elif selector in ("set", "setWithCapacity:", "array", "arrayWithCapacity:"):
            sett(self.new(cls, []))
        elif selector in ("numberWithDouble:", "numberWithFloat:"):
            bits = self.reg(REG_D0)
            value = _f64(bits)
            if selector == "numberWithFloat:":
                value = struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]
            sett(self.new("NSNumber", float(value)))
        elif selector == "numberWithBool:":
            sett(self.new("NSNumber", arg(2) != 0))
        elif selector in ("numberWithInteger:", "numberWithInt:", "numberWithUnsignedInteger:", "numberWithLongLong:",
                          "numberWithUnsignedLongLong:"):
            sett(self.new("NSNumber", _to_signed(arg(2))))
        elif selector == "dictionaryWithObjects:forKeys:count:":
            values, keys, count = arg(2), arg(3), arg(4)
            if count > 65536:
                self.panic("guest dictionary exceeds runtime limit")
            result = {}
            for index in range(count):
                result[self.string(self.read64(keys + index * 8))] = self.read64(values + index * 8)
            sett(self.new("NSDictionary", result))
        elif selector in ("setWithObjects:count:", "arrayWithObjects:count:"):
            values, count = arg(2), arg(3)
            if count > 65536:
                self.panic("guest array exceeds runtime limit")
            sett(self.new(cls, [self.read64(values + index * 8) for index in range(count)]))
        elif selector == "stringWithFormat:":
            sett(self.new("NSString", self.format(self.string(arg(2)))))
        elif selector == "stringWithUTF8String:":
            sett(self.new("NSString", self.cstring(arg(2))))
        elif selector == "errorWithDomain:code:userInfo:":
            sett(self.new("NSError", {"domain": arg(2), "code": self.new("NSNumber", _to_signed(arg(3))),
                                      "userInfo": arg(4)}))
        else:
            self.panic("unsupported class message " + method_key(cls, selector, True))

    def _instance_message(self, receiver: int, target, cls: str, selector: str) -> None:
        from .runtime import REG_D0, REG_X1, REG_X2, REG_X8, method_key

        arg, sett = self.arg, self.set
        value = target.value
        if selector == "initWithMachServiceName:options:":
            target.props["serviceName"] = arg(2)
            sett(receiver)
        elif selector == "_setQueue:":
            target.props["queue"] = arg(2)
            sett(0)
        elif selector == "setRemoteObjectInterface:":
            target.props["interface"] = arg(2)
            sett(0)
        elif selector in ("setInterruptionHandler:", "setInvalidationHandler:"):
            def keep(block: int) -> None:
                target.props[selector] = block
                sett(0)

            self.copy_block(arg(2), keep)
        elif selector == "remoteObjectProxyWithErrorHandler:":
            def proxy(block: int) -> None:
                created = self.new("HostUnavailableProxy", None)
                self.objects[created].props["errorBlock"] = block
                sett(created)

            self.copy_block(arg(2), proxy)
        elif selector in ("resume", "invalidate", "setClass:forSelector:argumentIndex:ofReply:",
                          "setClasses:forSelector:argumentIndex:ofReply:", "setInterface:forSelector:argumentIndex:ofReply:"):
            if cls not in ("NSXPCConnection", "NSXPCInterface"):
                self.panic("unsupported message " + cls + " " + selector)
            sett(0)
        elif selector == "addOperationWithBlock:":
            def enqueue(block: int) -> None:
                self.queue_pending(block, receiver)
                sett(0)

            self.copy_block(arg(2), enqueue)
        elif selector in ("lock", "unlock", "signal", "broadcast"):
            if cls not in ("NSCondition", "NSLock", "NSRecursiveLock"):
                self.panic("unsupported lock receiver " + cls)
            sett(0)
        elif selector in ("wait", "waitUntilDate:"):
            if cls != "NSCondition" or not self.pending:
                self.panic("guest condition has no runnable callback")
            block = self.next_pending()
            if block == 0:
                self.panic("all pending queues are suspended")
            self.pending_callback(block, lambda: sett(1))
        elif selector in ("createDirectoryAtURL:withIntermediateDirectories:attributes:error:",
                          "createDirectoryAtPath:withIntermediateDirectories:attributes:error:"):
            if arg(5):
                self.write64(arg(5), self.new("NSError", {"domain": self.new("NSString", "NSCocoaErrorDomain"),
                                                          "code": self.new("NSNumber", 513),
                                                          "userInfo": self.new("NSDictionary", {})}))
            sett(0)
        elif selector in ("isWritableFileAtPath:", "fileExistsAtPath:", "fileExistsAtPath:isDirectory:"):
            if selector == "fileExistsAtPath:isDirectory:" and arg(3):
                self.mem_write(arg(3), b"\0")
            sett(0)
        elif selector == "URLsForDirectory:inDomains:":
            if cls != "NSFileManager":
                self.panic("invalid file-manager receiver")
            sett(self.new("NSArray", [self.new("NSURL", "file:///ipatool/cache/")]))
        elif selector == "URLForDirectory:inDomain:appropriateForURL:create:error:":
            sett(self.new("NSURL", "file:///ipatool/cache/"))
        elif selector == "threadDictionary":
            if target.props.get(selector, 0) == 0:
                target.props[selector] = self.new("NSMutableDictionary", {})
            sett(target.props[selector])
        elif selector == "boolForKey:":
            if not isinstance(value, dict):
                self.panic("boolForKey: on " + cls)
            stored = value.get(self.string(arg(2)), 0)
            if stored == 0:
                sett(0)
            else:
                self.message(stored, "boolValue", False)
        elif selector == "operatingSystemVersion":
            out = self.reg(REG_X8)
            self.write64(out, 27)
            self.write64(out + 8, 0)
            self.write64(out + 16, 1)
        elif selector == "operatingSystemVersionString":
            sett(self.new("NSString", "Version 27.0.1 (Build 26A434)"))
        elif selector == "initWithTimeIntervalSince1970:":
            if cls != "NSDate":
                self.panic("unsupported date initializer")
            target.value = GoTime.from_float(_f64(self.reg(REG_D0)))
            sett(receiver)
        elif selector == "initWithBytesNoCopy:length:encoding:freeWhenDone:":
            if not self.kind_of(cls, "NSString") or arg(4) not in (4, 1) or arg(3) > 1 << 20:
                self.panic("unsupported string buffer initialization")
            target.value = self.mem_read(arg(2), arg(3)).decode("utf-8", "surrogateescape")
            sett(receiver)
        elif selector == "initWithBytesNoCopy:length:freeWhenDone:":
            if not self.kind_of(cls, "NSData") or arg(3) > 1 << 20:
                self.panic("unsupported data buffer initialization")
            target.value = self.mem_read(arg(2), arg(3))
            sett(receiver)
        elif selector == "timeIntervalSinceDate:":
            if not isinstance(value, GoTime):
                self.panic("timeIntervalSinceDate: on " + cls)
            self.set_reg(REG_D0, _bits(value.sub_seconds(self.time_of(arg(2)))))
        elif selector in ("timeIntervalSinceNow", "timeIntervalSince1970", "timeIntervalSinceReferenceDate"):
            if not isinstance(value, GoTime):
                self.panic(selector + " on " + cls)
            seconds = value.unix_float()
            if selector == "timeIntervalSinceNow":
                seconds = value.sub_seconds(GoTime.now())
            elif selector == "timeIntervalSinceReferenceDate":
                seconds -= 978307200
            self.set_reg(REG_D0, _bits(seconds))
        elif selector == "localizedStringForKey:value:table:":
            if cls != "NSBundle":
                self.panic("unsupported localization receiver")
            # No bundle resources are mounted: Foundation falls back to the
            # supplied value, then to the key.
            if arg(3) and self.string(arg(3)) != "":
                sett(arg(3))
            else:
                sett(arg(2))
        elif selector == "localeIdentifier":
            sett(self.new("NSString", "en_US"))
        elif selector == "languageCode":
            sett(self.new("NSString", "en"))
        elif selector == "infoDictionary":
            stored = target.props.get("infoDictionary", 0)
            sett(stored if stored else self.bundle_info())
        elif selector in ("executableURL", "bundleURL"):
            sett(self.new("NSURL", "file:///ipatool"))
        elif selector in ("bundleIdentifier", "bundlePath", "processName", "environment"):
            sett(target.props.get(selector, 0))
        elif selector == "objectForInfoDictionaryKey:":
            info = target.props.get("infoDictionary", 0) or self.bundle_info()
            sett(self.dict_of(info).get(self.string(arg(2)), 0))
        elif selector == "initWithCapacity:":
            if cls == "NSMutableString":
                target.value = ""
            elif "Array" in cls:
                target.value = []
            else:
                target.value = {}
            sett(receiver)
        elif selector == "appendFormat:":
            target.value = self.string(receiver) + self.format(self.string(arg(2)))
            sett(0)
        elif selector == "init":
            if target.value is None:
                if cls in ("NSString", "NSMutableString"):
                    target.value = ""
                elif cls in ("NSCache", "NSDictionary", "NSMutableDictionary"):
                    target.value = {}
                elif cls in ("NSArray", "NSMutableArray", "NSSet", "NSMutableSet", "NSOrderedSet", "NSMutableOrderedSet"):
                    target.value = []
            sett(receiver)
        elif selector == "containsObject:":
            items = self._list(target, cls)
            other = self.objects.get(arg(2))
            match = False
            for item in items:
                stored = self.objects.get(item)
                match = match or item == arg(2) or (
                    stored is not None and other is not None and go_sprint(stored.value) == go_sprint(other.value))
            sett(bool_value(match))
        elif selector == "UUIDString":
            sett(self.new("NSString", value))
        elif selector == "initWithFormat:":
            target.value = self.format(self.string(arg(2)))
            sett(receiver)
        elif selector == "initWithFormat:locale:arguments:":
            target.value = self.format_at(self.string(arg(2)), arg(4))
            sett(receiver)
        elif selector == "initWithString:":
            target.value = self.string(arg(2))
            sett(receiver)
        elif selector == "stringByAppendingPathComponent:":
            sett(self.new("NSString", path_join(self.string(receiver), self.string(arg(2)))))
        elif selector == "stringByDeletingPathExtension":
            text = self.string(receiver)
            extension = path_ext(text)
            sett(self.new("NSString", text[:-len(extension)] if extension and text.endswith(extension) else text))
        elif selector == "componentsJoinedByString:":
            parts = [self.string(item) for item in self._list(target, cls)]
            sett(self.new("NSString", self.string(arg(2)).join(parts)))
        elif selector == "componentsSeparatedByString:":
            separator = self.string(arg(2))
            text = self.string(receiver)
            parts = _go_split(text, separator)
            sett(self.new("NSArray", [self.new("NSString", part) for part in parts]))
        elif selector == "sortedArrayUsingComparator:":
            items = list(self._list(target, cls))
            if len(items) > 4096:
                self.panic("sort exceeds runtime budget")
            block = arg(2)
            state = {"i": 1, "j": 1}

            def step() -> None:
                while True:
                    if state["i"] >= len(items):
                        sett(self.new("NSArray", items))
                        return
                    if state["j"] == 0:
                        state["i"] += 1
                        state["j"] = state["i"]
                        continue
                    break
                j = state["j"]

                def compared() -> None:
                    if _to_signed(self.arg(0)) > 0:
                        items[j - 1], items[j] = items[j], items[j - 1]
                        state["j"] -= 1
                    else:
                        state["i"] += 1
                        state["j"] = state["i"]
                    step()

                self.callback(block, [items[j - 1], items[j]], compared)

            step()
        elif selector == "compare:":
            if isinstance(value, GoTime):
                sett(value.compare(self.time_of(arg(2))))
                return
            sett(_compare(self.string(receiver), self.string(arg(2))))
        elif selector == "allObjects":
            sett(self.new("NSArray", list(self._list(target, cls))))
        elif selector in ("firstObject", "lastObject"):
            items = self._list(target, cls)
            if not items:
                sett(0)
            else:
                sett(items[0] if selector == "firstObject" else items[-1])
        elif selector in ("objectAtIndex:", "objectAtIndexedSubscript:"):
            items = self._list(target, cls)
            if arg(2) >= len(items):
                self.panic("array index out of range")
            sett(items[arg(2)])
        elif selector in ("removeObjectsInArray:", "removeObject:"):
            if arg(2) == 0:
                sett(0)
                return
            remove = [arg(2)] if selector == "removeObject:" else list(self.list_of(arg(2)))
            items = [item for item in self._list(target, cls)
                     if not any(self.foundation_equal(item, other) for other in remove)]
            target.value = items
            sett(0)
        elif selector == "addObjectsFromArray:":
            target.value = list(self._list(target, cls)) + list(self.list_of(arg(2)))
            sett(0)
        elif selector == "removeObjectAtIndex:":
            items = self._list(target, cls)
            index = arg(2)
            if index >= len(items):
                self.panic("array removal index out of bounds")
            target.value = items[:index] + items[index + 1:]
            sett(0)
        elif selector == "addObject:":
            target.value = list(self._list(target, cls)) + [arg(2)]
            sett(0)
        elif selector in ("path", "lastPathComponent"):
            if not isinstance(value, str):
                self.panic(selector + " on " + cls)
            text = value
            if cls == "NSURL":
                try:
                    text = GoURL.parse(value).path
                except ValueError as exc:
                    self.panic(str(exc))
            if selector == "lastPathComponent":
                text = path_base(text)
            sett(self.new("NSString", text))
        elif selector == "absoluteString":
            if not isinstance(value, str):
                self.panic("absoluteString on " + cls)
            sett(self.new("NSString", value))
        elif selector == "stringValue":
            sett(self.new("NSString", go_sprint(value)))
        elif selector == "description":
            if not self.kind_of(cls, "NSString"):
                self.panic("unsupported instance message " + method_key(cls, selector, False))
            sett(receiver)
        elif selector == "lowercaseString":
            sett(self.new("NSString", self.string(receiver).lower()))
        elif selector == "uppercaseString":
            sett(self.new("NSString", self.string(receiver).upper()))
        elif selector == "appendString:":
            target.value = self.string(receiver) + self.string(arg(2))
            sett(0)
        elif selector == "stringByAppendingString:":
            sett(self.new("NSString", self.string(receiver) + self.string(arg(2))))
        elif selector == "initWithDomain:code:userInfo:":
            target.value = {"domain": arg(2), "code": self.new("NSNumber", _to_signed(arg(3))), "userInfo": arg(4)}
            sett(receiver)
        elif selector == "copy":
            entry = self.lookup(cls, "copyWithZone:", False)
            if entry:
                self.set_reg(REG_X2, 0)
                self.jump(entry, receiver, "copyWithZone:")
            else:
                sett(self.foundation_copy(receiver, False))
        elif selector in ("retain", "autorelease", "copyWithZone:"):
            sett(receiver)
        elif selector in ("mutableCopy", "mutableCopyWithZone:"):
            if isinstance(value, dict):
                sett(self.new("NSMutableDictionary", dict(value)))
            else:
                sett(self.new(cls, value))
        elif selector == "release":
            sett(0)
        elif selector == "class":
            description = self.classes.get(cls)
            if description is None:
                self.panic("class of unknown class " + cls)
            sett(description.address)
        elif selector == "isKindOfClass:":
            sett(bool_value(self.kind_of(cls, self.class_names.get(arg(2), ""))))
        elif selector in ("isEqualToDate:", "isEqual:", "isEqualToString:", "isEqualToDictionary:", "isEqualToArray:"):
            sett(bool_value(self.foundation_equal(receiver, arg(2))))
        elif selector in ("length", "count"):
            if isinstance(value, str):
                sett(glen(value))
            elif isinstance(value, (bytes, bytearray, list, dict)):
                sett(len(value))
            else:
                self.panic("count of " + cls)
        elif selector in ("valueForKey:", "__swift_objectForKeyedSubscript:", "objectForKey:", "objectForKeyedSubscript:"):
            if not isinstance(value, dict):
                self.panic("dictionary access on " + cls)
            sett(value.get(self.collection_key(arg(2)), 0))
        elif selector in ("setObject:forKey:cost:", "setValue:forKey:", "setObject:forKey:", "setObject:forKeyedSubscript:"):
            if not isinstance(value, dict):
                self.panic("dictionary mutation on " + cls)
            key = self.collection_key(arg(3))
            if arg(2) == 0:
                value.pop(key, None)
            else:
                value[key] = arg(2)
            sett(0)
        elif selector == "countByEnumeratingWithState:objects:count:":
            state, buffer, limit = arg(2), arg(3), arg(4)
            if limit > 100000:
                self.panic("enumeration limit too large")
            if isinstance(value, list):
                items = value
            elif isinstance(value, dict):
                items = [self.new("NSString", key) for key in sorted(value, key=_go_key)]
            else:
                self.panic("invalid collection")
            index = self.read64(state)
            if index >= len(items):
                sett(0)
                return
            count = min(limit, len(items) - index)
            for offset in range(count):
                self.write64(buffer + offset * 8, items[index + offset])
            if target.props.get("mutationCounter", 0) == 0:
                target.props["mutationCounter"] = self.alloc(8)
            self.write64(state, index + count)
            self.write64(state + 8, buffer)
            self.write64(state + 16, target.props["mutationCounter"])
            sett(count)
        elif selector == "enumerateKeysAndObjectsUsingBlock:":
            if not isinstance(value, dict):
                self.panic("enumeration of " + cls)
            entries = value
            keys = sorted(entries, key=_go_key)
            block = arg(2)
            stop = self.alloc(8)
            position = {"index": 0}

            def advance() -> None:
                if position["index"] == len(keys) or self.read64(stop) != 0:
                    sett(0)
                    return
                key = keys[position["index"]]
                position["index"] += 1
                self.callback(block, [self.new("NSString", key), entries.get(key, 0), stop], advance)

            advance()
        elif selector == "allValues":
            if not isinstance(value, dict):
                self.panic("allValues of " + cls)
            sett(self.new("NSArray", [value[key] for key in sorted(value, key=_go_key)]))
        elif selector == "allKeys":
            if not isinstance(value, dict):
                self.panic("allKeys of " + cls)
            sett(self.new("NSArray", [self.new("NSString", key) for key in sorted(value, key=_go_key)]))
        elif selector in ("doubleValue", "floatValue"):
            if isinstance(value, float):
                number = value
            elif _is_bool(value):
                number = float(bool_value(value))
            elif _is_int(value):
                number = float(value)
            elif isinstance(value, str):
                number = _parse_float(value)
            else:
                self.panic("unsupported numeric conversion")
            self.set_reg(REG_D0, _f32_bits(number) if selector == "floatValue" else _bits(number))
        elif selector in ("integerValue", "intValue", "longLongValue", "unsignedIntegerValue", "unsignedLongLongValue",
                          "boolValue"):
            number = 0
            if isinstance(value, float):
                number = _float_to_int64(value)
                if selector == "boolValue":
                    number = bool_value(value != 0)
            elif _is_bool(value):
                number = 1 if value else 0
            elif _is_int(value):
                number = value
            elif isinstance(value, str):
                number = _parse_int(value)
            sett(number)
        elif selector in ("localizedDescription", "localizedFailureReason", "localizedRecoverySuggestion"):
            if not self.kind_of(cls, "NSError"):
                self.panic("unsupported localized error receiver")
            fields = value
            key = {"localizedDescription": "NSLocalizedDescription",
                   "localizedFailureReason": "NSLocalizedFailureReason",
                   "localizedRecoverySuggestion": "NSLocalizedRecoverySuggestion"}[selector]
            text = 0
            info = self.objects.get(fields.get("userInfo", 0))
            if info is not None:
                if not isinstance(info.value, dict):
                    self.panic("error user info is not a dictionary")
                text = info.value.get(key, 0)
            if text == 0 and selector == "localizedDescription":
                code = self.obj(fields.get("code", 0)).value
                text = self.new("NSString", f"{self.string(fields.get('domain', 0))} error {go_sprint(code)}")
            sett(text)
        elif selector in ("domain", "userInfo", "code"):
            if not isinstance(value, dict):
                self.panic(selector + " of " + cls)
            stored = value.get(selector, 0)
            if selector == "code":
                code = self.obj(stored).value
                if not _is_int(code):
                    self.panic("error code is not an integer")
                stored = code
            sett(stored)
        elif selector in ("cStringUsingEncoding:", "UTF8String"):
            encoded = self.string(receiver).encode("utf-8", "surrogateescape") + b"\0"
            address = self.alloc(len(encoded))
            self.mem_write(address, encoded)
            sett(address)
        elif selector == "dataUsingEncoding:":
            text = self.string(receiver)
            if arg(2) == 4:  # NSUTF8StringEncoding
                data = text.encode("utf-8", "surrogateescape")
            elif arg(2) == 10:  # NSUnicodeStringEncoding: arm64 byte order with a BOM
                units = utf16_units(text)
                data = struct.pack("<H", 0xFEFF) + struct.pack(f"<{len(units)}H", *units)
            else:
                self.panic(f"unsupported string encoding {arg(2)}")
            sett(self.new("NSData", data))
        elif selector == "base64EncodedStringWithOptions:":
            if not self.kind_of(cls, "NSData"):
                self.panic("base64 encoding on " + cls)
            if not isinstance(value, (bytes, bytearray)):
                self.panic("base64 encoding of non-data")
            sett(self.new("NSString", base64.b64encode(bytes(value)).decode("ascii")))
        elif selector == "removeAllObjects":
            if isinstance(value, list):
                target.value = []
            elif isinstance(value, dict):
                target.value = {}
            else:
                self.panic("removeAllObjects on " + cls)
            sett(0)
        elif selector == "removeObjectForKey:":
            if not isinstance(value, dict):
                self.panic("removeObjectForKey: on " + cls)
            value.pop(self.collection_key(arg(2)), None)
            sett(0)
        elif selector == "addEntriesFromDictionary:":
            if not isinstance(value, dict):
                self.panic("addEntriesFromDictionary: on " + cls)
            value.update(self.dict_of(arg(2)))
            sett(0)
        elif selector == "initWithArray:":
            target.value = list(self.list_of(arg(2)))
            sett(receiver)
        elif selector == "initWithDictionary:":
            target.value = dict(self.dict_of(arg(2)))
            sett(receiver)
        elif selector == "initWithDictionary:copyItems:":
            self.initialize_dictionary(receiver, arg(2), arg(3) != 0)
        elif selector in ("rangeOfString:options:", "rangeOfString:"):
            text, needle = self.string(receiver), self.string(arg(2))
            options = arg(3) if selector == "rangeOfString:options:" else 0
            if options & 1:
                text, needle = text.lower(), needle.lower()
            index = text.rfind(needle) if options & 4 else text.find(needle)
            start, length = _NOT_FOUND, 0
            if index >= 0:
                start, length = utf16_length(text[:index]), utf16_length(needle)
            sett(start)
            self.set_reg(REG_X1, length)
        elif selector == "invertedSet":
            created = self.new("NSCharacterSet", value)
            self.objects[created].props["inverted"] = 1 - target.props.get("inverted", 0)
            sett(created)
        elif selector == "stringByTrimmingCharactersInSet:":
            charset = self.obj(arg(2))
            text = self.string(receiver)
            start, end = 0, len(text)
            while start < end and character_set_contains(charset, text[start]):
                start += 1
            while end > start and character_set_contains(charset, text[end - 1]):
                end -= 1
            sett(self.new("NSString", text[start:end]))
        elif selector in ("rangeOfCharacterFromSet:", "rangeOfCharacterFromSet:options:"):
            charset = self.obj(arg(2))
            options = arg(3) if selector == "rangeOfCharacterFromSet:options:" else 0
            start, length, offset = _NOT_FOUND, 0, 0
            for character in self.string(receiver):
                size = utf16_length(character)
                if character_set_contains(charset, character):
                    start, length = offset, size
                    if options & 4 == 0:
                        break
                offset += size
            sett(start)
            self.set_reg(REG_X1, length)
        elif selector in ("substringFromIndex:", "substringToIndex:", "substringWithRange:"):
            units = utf16_units(self.string(receiver))
            start, end = 0, len(units)
            if selector == "substringFromIndex:":
                start = arg(2)
            elif selector == "substringToIndex:":
                end = arg(2)
            else:
                start = arg(2)
                end = start + arg(3)
            if end > len(units) or start > end:
                self.panic("substring range exceeds string")
            sett(self.new("NSString", utf16_decode(units[start:end])))
        elif selector == "hasSuffix:":
            sett(bool_value(self.string(receiver).endswith(self.string(arg(2)))))
        elif selector == "containsString:":
            sett(bool_value(self.string(arg(2)) in self.string(receiver)))
        elif selector == "caseInsensitiveCompare:":
            sett(_compare(self.string(receiver).lower(), self.string(arg(2)).lower()))
        elif selector == "hasPrefix:":
            sett(bool_value(self.string(receiver).startswith(self.string(arg(2)))))
        else:
            self.panic("unsupported instance message " + method_key(cls, selector, False))

    def _list(self, target, cls: str) -> List[int]:
        if not isinstance(target.value, list):
            self.panic("array operation on " + cls)
        return target.value

    def responds(self, receiver: int, selector: str) -> bool:
        if receiver == 0:
            return False
        cls = self.class_names.get(receiver)
        meta = cls is not None
        target = self.objects.get(receiver)
        if not meta:
            if target is None:
                return False
            cls = target.cls
        if self.lookup(cls, selector, meta):
            return True
        if meta:
            return selector in ("class", "alloc", "new")
        if selector in ("class", "retain", "release", "autorelease", "copy", "mutableCopy", "isKindOfClass:", "isEqual:",
                        "respondsToSelector:"):
            return True
        value = target.value
        if isinstance(value, str):
            return selector in ("length", "isEqualToString:", "hasPrefix:", "UTF8String", "integerValue", "intValue",
                                "longLongValue", "unsignedIntegerValue", "unsignedLongLongValue", "boolValue")
        if _is_int(value):
            return selector in ("integerValue", "intValue", "longLongValue", "unsignedIntegerValue",
                                "unsignedLongLongValue", "boolValue")
        if isinstance(value, dict):
            return selector in ("count", "objectForKey:", "objectForKeyedSubscript:", "allKeys", "setObject:forKey:",
                                "setObject:forKeyedSubscript:")
        if isinstance(value, (list, bytes, bytearray)):
            return selector in ("count", "length")
        return False

    def format(self, layout: str) -> str:
        from .runtime import REG_SP

        return self.format_at(layout, self.reg(REG_SP))

    def format_at(self, layout: str, sp: int) -> str:
        """printf-style formatting of a guest format string (``%@``, ints, ``%s``)."""
        data = layout.encode("utf-8", "surrogateescape")
        out = bytearray()
        offset = 0
        index = 0
        while index < len(data):
            if data[index] != 0x25:  # '%'
                out.append(data[index])
                index += 1
                continue
            index += 1
            if index >= len(data):
                self.panic("incomplete format")
            if data[index] == 0x25:
                out.append(0x25)
                index += 1
                continue
            width_start = index
            while index < len(data) and 0x30 <= data[index] <= 0x39:
                index += 1
            width = data[width_start:index].decode("ascii")
            while index < len(data) and data[index] in (0x6C, 0x7A):  # 'l', 'z'
                index += 1
            if index >= len(data):
                self.panic("invalid format")
            value = self.read64(sp + offset)
            offset += 8
            verb = chr(data[index])
            if verb == "@":
                if value == 0:
                    out += b"(null)"
                else:
                    stored = self.objects.get(value)
                    if stored is None:
                        cls = self.class_names.get(value, "")
                        if not cls:
                            self.panic(f"unknown format object {value:#x}")
                        out += cls.encode("utf-8", "surrogateescape")
                    else:
                        out += go_sprint(stored.value).encode("utf-8", "surrogateescape")
            elif verb in ("d", "i"):
                out += str(_to_signed(value)).encode("ascii")
            elif verb == "u":
                out += str(value).encode("ascii")
            elif verb in ("x", "X"):
                out += _go_hex(value, width, verb).encode("ascii")
            elif verb == "p":
                out += f"%!p(uint64={value})".encode("ascii")
            elif verb == "s":
                out += self.cstring(value).encode("utf-8", "surrogateescape")
            else:
                self.panic("unsupported format " + layout)
            index += 1
        return out.decode("utf-8", "surrogateescape")

    def bundle(self) -> int:
        created = self.new("NSBundle", None)
        self.objects[created].props = {"bundleIdentifier": self.new("NSString", "me.majd.ipatool"),
                                       "bundlePath": self.new("NSString", "/ipatool")}
        return created

    def bundle_info(self) -> int:
        return self.new("NSDictionary", {"CFBundleIdentifier": self.new("NSString", "me.majd.ipatool"),
                                         "CFBundleVersion": self.new("NSString", "1.0"),
                                         "CFBundleExecutable": self.new("NSString", "ipatool"),
                                         "CFBundleName": self.new("NSString", "ipatool")})

    def foundation_copy(self, receiver: int, mutable: bool) -> int:
        stored = self.obj(receiver)
        if stored.cls in ("NSArray", "NSMutableArray", "NSSet", "NSMutableSet"):
            cls = "NSSet" if "Set" in stored.cls else "NSArray"
            if mutable:
                cls = "NSMutable" + cls[2:]
            return self.new(cls, list(self._list(stored, stored.cls)))
        if stored.cls in ("NSDictionary", "NSMutableDictionary"):
            if not isinstance(stored.value, dict):
                self.panic("copy of a dictionary without entries")
            return self.new("NSMutableDictionary" if mutable else "NSDictionary", dict(stored.value))
        if stored.cls == "NSMutableString":
            return self.new("NSString", stored.value)
        return receiver

    def initialize_dictionary(self, receiver: int, source: int, copy_items: bool) -> None:
        """copyItems copies each immediate value (its copyWithZone: when it
        has one); nested collection contents stay shared, as in Foundation."""
        values = dict(self.dict_of(source))
        self.objects[receiver].value = values
        if not copy_items:
            self.set(receiver)
            return
        keys = sorted(values, key=_go_key)
        position = {"index": 0}

        def advance() -> None:
            while position["index"] < len(keys):
                key = keys[position["index"]]
                stored = values[key]
                position["index"] += 1
                entry = self.lookup(self.obj(stored).cls, "copyWithZone:", False)
                if entry:
                    def copied(key=key) -> None:
                        values[key] = self.arg(0)
                        advance()

                    self.callback_function(entry, [stored, self.selector("copyWithZone:"), 0], copied)
                    return
                values[key] = self.foundation_copy(stored, False)
            self.set(receiver)

        advance()

    def collection_key(self, address: int) -> str:
        stored = self.objects.get(address)
        if stored is not None:
            if isinstance(stored.value, str):
                return stored.value
            if _is_int(stored.value):
                return f"#number:{stored.value}"
        return f"#object:{address:x}"

    def foundation_equal(self, a: int, b: int) -> bool:
        if a == b:
            return True
        x, y = self.objects.get(a), self.objects.get(b)
        if x is None or y is None:
            return False
        v, w = x.value, y.value
        if isinstance(v, GoTime):
            return isinstance(w, GoTime) and v.compare(w) == 0
        if isinstance(v, str):
            return isinstance(w, str) and v == w
        if _is_int(v):
            if _is_int(w):
                return v == w
            if _is_bool(w):
                return v == bool_value(w)
            return False
        if _is_bool(v):
            if _is_int(w):
                return bool_value(v) == w
            if _is_bool(w):
                return v == w
            return False
        if isinstance(v, (bytes, bytearray)):
            return isinstance(w, (bytes, bytearray)) and bytes(v) == bytes(w)
        if isinstance(v, list):
            return isinstance(w, list) and len(v) == len(w) and all(
                self.foundation_equal(p, q) for p, q in zip(v, w))
        if isinstance(v, dict):
            return isinstance(w, dict) and len(v) == len(w) and all(
                key in w and self.foundation_equal(p, w[key]) for key, p in v.items())
        return False

    def new_uuid_string(self) -> str:
        data = bytearray(os.urandom(16))
        data[6] = (data[6] & 15) | 64
        data[8] = (data[8] & 63) | 128
        h = data.hex().upper()
        return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"

    # -- notifications.go -----------------------------------------------------

    def notification_message(self, receiver: int, cls: str, selector: str, meta: bool) -> bool:
        arg, sett = self.arg, self.set
        if meta and cls == "NSNotificationCenter" and selector == "defaultCenter":
            if self.notification_center == 0:
                self.notification_center = self.new(cls, None)
            sett(self.notification_center)
            return True
        if cls == "NSNotification":
            if selector in ("name", "object", "userInfo"):
                sett(self.obj(receiver).props.get(selector, 0))
                return True
            return False
        if meta or cls != "NSNotificationCenter":
            return False
        if selector == "addObserver:selector:name:object:":
            observer = self.new("HostObserver", None)
            entry = self.objects[observer]
            entry.props = {"observer": arg(2), "selector": arg(3), "name": arg(4), "object": arg(5)}
            self.observers[observer] = entry
            sett(0)
        elif selector in ("postNotificationName:object:userInfo:", "postNotificationName:object:"):
            name, sender = arg(2), arg(3)
            info = arg(4) if selector == "postNotificationName:object:userInfo:" else 0
            notification = self.new("NSNotification", None)
            self.objects[notification].props = {"name": name, "object": sender, "userInfo": info}
            for entry in list(self.observers.values()):
                wanted = entry.props.get("name", 0)
                if wanted and self.string(wanted) != self.string(name):
                    continue
                source = entry.props.get("object", 0)
                if source and source != sender:
                    continue
                observer, action = entry.props.get("observer", 0), self.cstring(entry.props.get("selector", 0))
                self.pending.append(self.host_block(
                    lambda observer=observer, action=action: self.delegate_call(
                        observer, action, [notification], lambda: self.set(0))))
            sett(0)
        elif selector in ("removeObserver:", "removeObserver:name:object:"):
            for key in [k for k, o in self.observers.items() if k == arg(2) or o.props.get("observer", 0) == arg(2)]:
                del self.observers[key]
            sett(0)
        else:
            return False
        return True

    # -- accounts.go ------------------------------------------------------------

    def account_message(self, receiver: int, cls: str, selector: str, meta: bool) -> bool:
        arg, sett = self.arg, self.set
        if not meta and cls in ("ACAccountStore", "ACDAccountStore"):
            if selector in ("accountTypeWithAccountTypeIdentifier:", "accountTypeWithAccountTypeIdentifier:error:"):
                account_type = self.new("ACAccountType", None)
                self.objects[account_type].props = {"identifier": arg(2)}
                if selector == "accountTypeWithAccountTypeIdentifier:error:" and arg(3):
                    self.write64(arg(3), 0)
                sett(account_type)
                return True
            if selector in ("accountsWithAccountType:", "accountsWithAccountType:options:error:",
                            "accountsWithAccountType:options:classification:error:"):
                if selector == "accountsWithAccountType:options:error:" and arg(4):
                    self.write64(arg(4), 0)
                if selector == "accountsWithAccountType:options:classification:error:" and arg(5):
                    self.write64(arg(5), 0)
                sett(self.new("NSArray", []))
                return True
            if selector == "accounts":
                sett(self.new("NSArray", []))
                return True
            if selector == "accountWithIdentifier:":
                sett(0)
                return True
        if meta or (not self.kind_of(cls, "ACAccount") and cls not in ("ACAccountType", "ACAccountCredential")):
            return False
        target = self.obj(receiver)
        if selector == "initWithIdentifier:description:":
            target.props["identifier"] = arg(2)
            target.props["accountTypeDescription"] = arg(3)
            sett(receiver)
        elif selector == "initWithAccountType:":
            target.props["identifier"] = self.new("NSString", self.new_uuid_string())
            target.props["accountType"] = arg(2)
            target.props["accountProperties"] = self.new("NSMutableDictionary", {})
            sett(receiver)
        elif selector == "initWithPassword:":
            target.props["password"] = arg(2)
            sett(receiver)
        elif selector == "accountPropertyForKey:":
            sett(self.dict_of(target.props.get("accountProperties", 0)).get(self.string(arg(2)), 0))
        elif selector == "setAccountProperty:forKey:":
            fields = self.dict_of(target.props.get("accountProperties", 0))
            key = self.string(arg(3))
            if arg(2) == 0:
                fields.pop(key, None)
            else:
                fields[key] = arg(2)
            sett(0)
        elif selector in ("accountType", "identifier", "username", "credential", "accountProperties", "authenticated",
                          "active", "owningBundleID", "accountDescription", "parentAccount", "isDirty"):
            sett(target.props.get(selector, 0))
        elif _is_setter(selector):
            target.props[_setter_key(selector)] = arg(2)
            sett(0)
        else:
            return False
        return True

    # -- network.go (messages; requests themselves are not bridged) ---------------

    def import_value(self, value: Any) -> int:
        if value is None:
            return 0
        if isinstance(value, str):
            return self.new("NSString", value)
        if isinstance(value, (bytes, bytearray)):
            return self.new("NSData", bytes(value))
        if isinstance(value, GoTime):
            return self.new("NSDate", value)
        if isinstance(value, bool):
            return self.new("NSNumber", value)
        if isinstance(value, int):
            return self.new("NSNumber", _to_signed(value))
        if isinstance(value, float):
            if value == math.trunc(value) and -(2 ** 63) <= value < 2 ** 63:
                return self.new("NSNumber", int(value))
            return self.new("NSNumber", value)
        if isinstance(value, list):
            return self.new("NSArray", [self.import_value(item) for item in value])
        if isinstance(value, dict):
            return self.new("NSDictionary", {key: self.import_value(item) for key, item in value.items()})
        self.panic(f"unsupported Foundation import {type(value).__name__}")

    def network_message(self, receiver: int, cls: str, selector: str, meta: bool) -> bool:
        from .runtime import REG_D0, REG_X2, REG_X3

        arg, sett = self.arg, self.set
        target = self.objects.get(receiver)
        if not meta and cls == "NSURLSessionConfiguration" and selector in ("_allowsTCPFastOpen", "_allowsTLSSessionTickets", "URLCache"):
            sett(0)
            return True
        if not meta and cls == "NSHTTPURLResponse" and selector == "_CFURLResponse":
            sett(receiver)
            return True
        if not meta and cls == "NSURLSessionDataTask" and selector == "_timingData":
            sett(0)
            return True
        if not meta and cls == "AKAppleIDSession" and selector == "handleResponse:forRequest:shouldRetry:":
            status = self.obj(arg(2)).props.get("statusCode", 0)
            if status in (431, 433, 434, 441, 442, 443, 444):
                self.panic("AuthKit anisette challenge is not supported")
            if arg(4):
                self.mem_write(arg(4), b"\0")
            sett(0)
            return True

        if meta:
            if cls == "NSURLComponents" and selector == "componentsWithURL:resolvingAgainstBaseURL:":
                try:
                    sett(self.new("NSURLComponents", GoURL.parse(self.string(arg(2)))))
                except ValueError:
                    sett(0)
            elif cls == "NSURLCache" and selector == "sharedURLCache":
                sett(0)
            elif cls == "NSJSONSerialization" and selector == "isValidJSONObject:":
                sett(bool_value(self.valid_json_object(arg(2), True, 0)))
            elif cls == "NSURLQueryItem" and selector == "queryItemWithName:value:":
                item = self.new(cls, None)
                self.objects[item].props = {"name": arg(2), "value": arg(3)}
                sett(item)
            elif cls == "NSHTTPCookie" and selector == "cookieWithProperties:":
                sett(self.new("NSHTTPCookie", self._cookie_from(self.dict_of(arg(2)))))
            elif cls == "NSHTTPCookie" and selector in ("requestHeaderFieldsWithCookies:", "cookiesWithResponseHeaderFields:forURL:"):
                self.panic("cookie handling is not bridged; the client manages Store cookies")
            elif cls == "NSURLSession" and selector == "sessionWithConfiguration:delegate:delegateQueue:":
                session = self.new("NSURLSession", None)
                self.objects[session].props = {"configuration": arg(2), "delegate": arg(3), "delegateQueue": arg(4)}
                sett(session)
            elif cls in ("NSURLRequest", "NSMutableURLRequest") and selector == "requestWithURL:":
                request = self.new(cls, None)
                self.objects[request].props = {"URL": arg(2), "HTTPMethod": self.new("NSString", "GET"),
                                               "allHTTPHeaderFields": self.new("NSMutableDictionary", {})}
                sett(request)
            elif cls == "NSJSONSerialization" and selector == "JSONObjectWithData:options:error:":
                try:
                    decoded = json.loads(self.bytes_of(arg(2)), parse_int=float)
                except ValueError:
                    self.parser_error(arg(4))
                    sett(0)
                    return True
                sett(self.import_value(decoded))
            elif cls == "NSPropertyListSerialization" and selector == "propertyList:isValidForFormat:":
                try:
                    plistlib.dumps(_plist_ready(self.export(arg(2))), fmt=plistlib.FMT_XML)
                    valid = True
                except Exception:  # noqa: BLE001 - any failure means "not a property list"
                    valid = False
                sett(bool_value(valid))
            elif cls == "NSPropertyListSerialization" and selector == "propertyListWithData:options:format:error:":
                try:
                    decoded = plistlib.loads(self.bytes_of(arg(2)))
                except Exception:  # noqa: BLE001
                    self.parser_error(arg(5))
                    sett(0)
                    return True
                sett(self.import_value(_from_plist(decoded)))
            elif cls == "NSPropertyListSerialization" and selector == "dataWithPropertyList:format:options:error:":
                fmt = plistlib.FMT_BINARY if arg(3) == 200 else plistlib.FMT_XML
                sett(self.new("NSData", plistlib.dumps(_plist_ready(self.export(arg(2))), fmt=fmt, sort_keys=True)))
            else:
                return False
            return True

        if selector == "initWithIndexesInRange:" and cls == "NSIndexSet":
            target.value = (arg(2), arg(3))
            sett(receiver)
            return True
        if selector == "containsIndex:" and cls == "NSIndexSet":
            first, length = target.value
            sett(bool_value(arg(2) >= first and arg(2) - first < length))
            return True
        if selector == "initWithURL:" and self.kind_of(cls, "NSURLRequest"):
            self.set_reg(REG_X3, 0)
            self.set_reg(REG_D0, _bits(60.0))
            self.message(receiver, "initWithURL:cachePolicy:timeoutInterval:", False)
            return True
        if selector == "initWithURL:cachePolicy:timeoutInterval:" and self.kind_of(cls, "NSURLRequest"):
            target.props = {"URL": arg(2), "cachePolicy": arg(3), "HTTPMethod": self.new("NSString", "GET"),
                            "allHTTPHeaderFields": self.new("NSMutableDictionary", {})}
            sett(receiver)
            return True
        if cls == "NSHTTPURLResponse" and selector == "valueForHTTPHeaderField:":
            wanted = self.string(arg(2)).lower()
            for key, stored in self.dict_of(target.props.get("allHeaderFields", 0)).items():
                if key.lower() == wanted:
                    sett(stored)
                    return True
            sett(0)
            return True
        if self.kind_of(cls, "NSURLRequest"):
            if selector in ("HTTPBody", "HTTPBodyStream"):
                sett(target.props.get(selector, 0))
                return True
            if selector in ("copy", "copyWithZone:", "mutableCopy", "mutableCopyWithZone:"):
                if selector in ("copy", "mutableCopy"):
                    zone = selector + "WithZone:"
                    entry = self.lookup(cls, zone, False)
                    if entry:
                        self.set_reg(REG_X2, 0)
                        self.jump(entry, receiver, zone)
                        return True
                copied = self.new(cls, target.value)
                self.objects[copied].props.update(target.props)
                fields = target.props.get("allHTTPHeaderFields", 0)
                if fields:
                    self.objects[copied].props["allHTTPHeaderFields"] = self.foundation_copy(fields, True)
                sett(copied)
                return True
            if selector == "_CFURLRequest":
                sett(receiver)
                return True
            if selector == "_initWithCFURLRequest:":
                source = self.obj(arg(2))
                target.props = dict(source.props)
                fields = target.props.get("allHTTPHeaderFields", 0)
                if fields:
                    target.props["allHTTPHeaderFields"] = self.foundation_copy(fields, True)
                sett(receiver)
                return True
            if selector in ("setValue:forHTTPHeaderField:", "addValue:forHTTPHeaderField:"):
                if target.props.get("allHTTPHeaderFields", 0) == 0:
                    target.props["allHTTPHeaderFields"] = self.new("NSMutableDictionary", {})
                fields = self.dict_of(target.props["allHTTPHeaderFields"])
                key = canonical_header_key(self.string(arg(3)))
                if arg(2) == 0:
                    fields.pop(key, None)
                else:
                    fields[key] = arg(2)
                sett(0)
                return True
            if selector == "valueForHTTPHeaderField:":
                fields = self.dict_of(target.props.get("allHTTPHeaderFields", 0))
                sett(fields.get(canonical_header_key(self.string(arg(2))), 0))
                return True
        if cls == "NSURLSession" and selector == "dataTaskWithRequest:":
            task = self.new("NSURLSessionDataTask", None)
            self.objects[task].props = {"currentRequest": arg(2), "originalRequest": arg(2), "session": receiver,
                                        "taskIdentifier": task, "state": 1}
            sett(task)
            return True
        if cls == "NSURLSessionDataTask" and selector == "resume":
            self.panic("the Store framework tried to send a request; requests are made by the client, not the guest")
        if (cls == "NSURLSession" and selector in ("invalidateAndCancel", "finishTasksAndInvalidate")) or (
                cls == "NSURLSessionDataTask" and selector == "cancel"):
            sett(0)
            return True
        if cls in ("NSURLSession", "NSURLSessionDataTask", "NSHTTPURLResponse", "NSURLResponse") or self.kind_of(cls, "NSURLRequest"):
            if _is_setter(selector):
                target.props[_setter_key(selector)] = arg(2)
                sett(0)
                return True
            if selector in target.props:
                sett(target.props[selector])
                return True
        if cls == "NSHTTPCookie":
            if selector == "initWithProperties:":
                target.value = self._cookie_from(self.dict_of(arg(2)))
                sett(receiver)
                return True
            cookie = target.value
            if not isinstance(cookie, _Cookie):
                self.panic("cookie without properties")
            if selector == "properties":
                fields: Dict[str, Any] = {"Name": cookie.name, "Value": cookie.value, "Domain": cookie.domain,
                                          "Path": cookie.path, "Created": int(time.time()) - 978307200}
                if cookie.secure:
                    fields["Secure"] = "TRUE"
                if cookie.http_only:
                    fields["HttpOnly"] = "TRUE"
                if cookie.expires is None:
                    fields["Discard"] = "TRUE"
                else:
                    fields["Expires"] = cookie.expires
                sett(self.import_value(fields))
                return True
            simple = {"name": cookie.name, "domain": cookie.domain, "path": cookie.path, "value": cookie.value}
            if selector in simple:
                sett(self.new("NSString", simple[selector]))
                return True
            if selector == "expiresDate":
                sett(0 if cookie.expires is None else self.new("NSDate", cookie.expires))
                return True
            if selector == "isSessionOnly":
                sett(bool_value(cookie.expires is None))
                return True
            if selector == "version":
                sett(0)
                return True
            if selector == "isSecure":
                sett(bool_value(cookie.secure))
                return True
            if selector == "isHTTPOnly":
                sett(bool_value(cookie.http_only))
                return True
        if cls == "NSURLQueryItem" and selector in ("name", "value"):
            sett(target.props.get(selector, 0))
            return True
        if cls == "NSURLComponents":
            if selector == "initWithURL:resolvingAgainstBaseURL:":
                try:
                    target.value = GoURL.parse(self.string(arg(2)))
                except ValueError as exc:
                    self.panic(str(exc))
                sett(receiver)
                return True
            url = target.value
            if not isinstance(url, GoURL):
                self.panic("URL components without a URL")
            if selector in ("setQuery:", "setPercentEncodedQuery:"):
                url.raw_query = ""
                url.force_query = arg(2) != 0
                if arg(2):
                    url.raw_query = self.string(arg(2))
                    if selector == "setQuery:":
                        url.raw_query = encode_component_query(url.raw_query)
                sett(0)
                return True
            if selector in ("query", "percentEncodedQuery"):
                if url.raw_query == "" and not url.force_query:
                    sett(0)
                else:
                    text = url.raw_query
                    if selector == "query":
                        try:
                            text = path_unescape(text)
                        except ValueError:
                            self.panic("invalid URL query encoding")
                    sett(self.new("NSString", text))
                return True
            if selector == "setFragment:":
                url.fragment = self.string(arg(2))
                sett(0)
                return True
            if selector == "URL":
                sett(self.new("NSURL", url.string()))
                return True
            if selector in ("queryItems", "percentEncodedQueryItems"):
                items = []
                if url.raw_query:
                    for part in url.raw_query.split("&"):
                        key, has_value, text = part.partition("=")
                        if selector == "queryItems":
                            key = query_unescape(key.replace("+", "%2B"))[0]
                            text = query_unescape(text.replace("+", "%2B"))[0]
                        item = self.new("NSURLQueryItem", None)
                        self.objects[item].props["name"] = self.new("NSString", key)
                        if has_value:
                            self.objects[item].props["value"] = self.new("NSString", text)
                        items.append(item)
                sett(self.new("NSArray", items))
                return True
            if selector in ("setQueryItems:", "setPercentEncodedQueryItems:"):
                parts = []
                if arg(2):
                    for item in self.list_of(arg(2)):
                        props = self.obj(item).props
                        if selector == "setPercentEncodedQueryItems:":
                            part = self.string(props.get("name", 0))
                            if props.get("value", 0):
                                part += "=" + self.string(props["value"])
                        else:
                            part = query_escape(self.string(props.get("name", 0))).replace("+", "%20")
                            if props.get("value", 0):
                                part += "=" + query_escape(self.string(props["value"])).replace("+", "%20")
                        parts.append(part)
                url.raw_query = "&".join(parts)
                sett(0)
                return True
        if cls == "NSURL":
            try:
                url = GoURL.parse(self.string(receiver))
            except ValueError as exc:
                self.panic(str(exc))
            if selector in ("URLByAppendingPathComponent:", "URLByAppendingPathComponent:isDirectory:"):
                try:
                    sett(self.new("NSURL", url_join_path(url.string(), self.string(arg(2)))))
                except ValueError as exc:
                    self.panic(str(exc))
                return True
            if selector == "fileSystemRepresentation":
                encoded = url.path.encode("utf-8", "surrogateescape") + b"\0"
                pointer = self.alloc(len(encoded))
                self.mem_write(pointer, encoded)
                sett(pointer)
                return True
            if selector == "isFileURL":
                sett(bool_value(url.scheme == "file"))
                return True
            if selector == "fragment":
                sett(self.new("NSString", url.fragment) if url.fragment else 0)
                return True
            if selector == "host":
                sett(self.new("NSString", url.hostname()))
                return True
            if selector == "scheme":
                sett(self.new("NSString", url.scheme))
                return True
            if selector == "query":
                sett(self.new("NSString", url.raw_query))
                return True
        if cls in ("NSData", "NSMutableData"):
            data = target.value if isinstance(target.value, (bytes, bytearray)) else b""
            if selector == "bytes":
                pointer = self.alloc(len(data))
                self.mem_write(pointer, bytes(data))
                sett(pointer)
                return True
            if selector == "appendBytes:length:":
                size = arg(3)
                if size > 32 << 20:
                    self.panic("data append exceeds budget")
                target.value = bytes(data) + self.mem_read(arg(2), size)
                sett(0)
                return True
            if selector == "appendData:":
                target.value = bytes(data) + self.bytes_of(arg(2))
                sett(0)
                return True
        return False

    def _cookie_from(self, fields: Dict[str, int]) -> _Cookie:
        cookie = _Cookie(self.string(fields.get("Name", 0)), self.string(fields.get("Value", 0)),
                         self.string(fields.get("Domain", 0)), self.string(fields.get("Path", 0)))
        if fields.get("Secure", 0):
            cookie.secure = go_sprint(self.obj(fields["Secure"]).value).upper() == "TRUE"
        if fields.get("HttpOnly", 0):
            cookie.http_only = go_sprint(self.obj(fields["HttpOnly"]).value).upper() == "TRUE"
        if fields.get("Expires", 0):
            expires = self.obj(fields["Expires"]).value
            cookie.expires = expires if isinstance(expires, GoTime) else None
        return cookie

    def valid_json_object(self, address: int, top: bool, depth: int) -> bool:
        if depth > 64:
            return False
        stored = self.objects.get(address)
        if stored is None:
            return False
        value = stored.value
        if isinstance(value, dict):
            return all(self.valid_json_object(child, False, depth + 1) for child in value.values())
        if isinstance(value, list):
            return "Array" in stored.cls and all(self.valid_json_object(child, False, depth + 1) for child in value)
        if isinstance(value, (str, bool, int)):
            return not top
        if isinstance(value, float):
            return not top and not math.isinf(value) and not math.isnan(value)
        return not top and stored.cls == "NSNull"

    def delegate_call(self, receiver: int, selector: str, args: List[int], after: Callable[[], None]) -> None:
        stored = self.objects.get(receiver)
        if stored is None:
            self.panic("missing transport delegate")
        entry = self.lookup(stored.cls, selector, False)
        if entry == 0:
            forward = self.lookup(stored.cls, "forwardingTargetForSelector:", False)
            if forward == 0:
                self.panic("missing transport delegate method " + selector)

            def forwarded() -> None:
                target = self.arg(0)
                if target == 0 or target == receiver:
                    self.panic("transport delegate cannot forward " + selector)
                self.delegate_call(target, selector, args, after)

            self.callback_function(forward, [receiver, self.selector("forwardingTargetForSelector:"),
                                             self.selector(selector)], forwarded)
            return
        self.callback_function(entry, [receiver, self.selector(selector)] + list(args), after)

    def parser_error(self, out: int) -> None:
        if out == 0:
            return
        self.write64(out, self.new("NSError", {"domain": self.new("NSString", "NSCocoaErrorDomain"),
                                               "code": self.new("NSNumber", 3840),
                                               "userInfo": self.new("NSDictionary", {})}))

    # -- compression.go ---------------------------------------------------------

    def compression_symbol(self, name: str) -> bool:
        arg, sett = self.arg, self.set
        if name == "inflateInit2_":
            if arg(3) != 112:
                self.panic("unsupported zlib stream ABI")
            bits = arg(1) & 0xFFFFFFFF
            self.inflaters[arg(0)] = _Inflate(bits - (1 << 32) if bits >> 31 else bits)
            self.write64(arg(0) + 16, 0)
            self.write64(arg(0) + 40, 0)
            sett(0)
        elif name == "inflateEnd":
            self.inflaters.pop(arg(0), None)
            sett(0)
        elif name == "inflate":
            address = arg(0)
            state = self.inflaters.get(address)
            if state is None:
                self.panic("uninitialized inflate stream")
            size = self.read64(address + 8) & 0xFFFFFFFF
            if size > 32 << 20:
                self.panic("inflate input exceeds budget")
            if size:
                pointer = self.read64(address)
                state.input += self.mem_read(pointer, size)
                self.write64(address, pointer + size)
                self.write32(address + 8, 0)
                self.write64(address + 16, self.read64(address + 16) + size)
            if not state.decoded:
                window = {31: 31, 47: 47, 15: 15, -15: -15}.get(state.bits)
                if window is None:
                    self.panic("unsupported inflate window size")
                try:
                    decoder = zlib.decompressobj(window)
                    output = decoder.decompress(bytes(state.input), (32 << 20) + 1)
                    if not decoder.eof:
                        raise zlib.error("truncated stream")
                except zlib.error:
                    sett(U64 - 2)  # Z_DATA_ERROR
                    return True
                if len(output) > 32 << 20:
                    self.panic("decompressed response exceeds runtime limit")
                state.output = output
                state.decoded = True
            size = self.read64(address + 32) & 0xFFFFFFFF
            count = min(size, len(state.output) - state.position)
            out = self.read64(address + 24)
            if count:
                self.mem_write(out, state.output[state.position:state.position + count])
            state.position += count
            self.write64(address + 24, out + count)
            self.write32(address + 32, size - count)
            self.write64(address + 40, self.read64(address + 40) + count)
            sett(bool_value(state.position == len(state.output)))
        else:
            return False
        return True

    # -- delegate.go / anisette.go ------------------------------------------------

    def install_store_amd_adapter(self) -> None:
        """The libxpc functions AppleMediaServices' type-2 anisette provider
        calls, answered by the emulated com.apple.adid service."""
        arg, sett = self.arg, self.set

        def create_dictionary() -> None:
            sett(self.new("HostXPCDictionary", {}))

        def set_data() -> None:
            dictionary = self.dict_of(arg(0))
            length = arg(3)
            if length > 1 << 20:
                self.panic("XPC data exceeds runtime limit")
            dictionary[self.cstring(arg(1))] = self.new("NSData", self.mem_read(arg(2), length))
            sett(0)

        def get_data() -> None:
            dictionary = self.dict_of(arg(0))
            stored = self.objects.get(dictionary.get(self.cstring(arg(1)), 0))
            if stored is None:
                if arg(2):
                    self.write64(arg(2), 0)
                sett(0)
                return
            data = stored.value
            if not isinstance(data, (bytes, bytearray)):
                self.panic("XPC value is not data")
            pointer = self.alloc(max(len(data), 1))
            if data:
                self.mem_write(pointer, bytes(data))
            if arg(2):
                self.write64(arg(2), len(data))
            sett(pointer)

        def create_connection() -> None:
            connection = self.new("HostXPCConnection", self.cstring(arg(0)))
            self.objects[connection].props["targetQueue"] = arg(1)
            self.objects[connection].props["flags"] = arg(2)
            sett(connection)

        def set_event_handler() -> None:
            self.obj(arg(0)).props["eventHandler"] = arg(1)
            sett(0)

        def send_sync() -> None:
            connection = self.obj(arg(0))
            message = self.dict_of(arg(1))
            stored = self.objects.get(message.get("data", 0))
            if self.xpc_sync_handler is None or stored is None:
                self.panic("Store AMD XPC handler is unavailable")
            reply = self.xpc_sync_handler(go_sprint(connection.value), bytes(stored.value))
            sett(self.new("HostXPCDictionary", {"data": self.new("NSData", bytes(reply))}))

        def notify_register_check() -> None:
            if arg(1):
                self.write64(arg(1), 1)
            sett(0)

        def notify_check() -> None:
            if arg(1):
                self.write64(arg(1), 0)
            sett(0)

        def gettimeofday() -> None:
            now = time.time_ns()
            if arg(0):
                self.write64(arg(0), now // 1_000_000_000)
                self.write64(arg(0) + 8, (now % 1_000_000_000) // 1000)
            sett(0)

        for address, handler in (
            (0x180574A18, create_dictionary),
            (0x180553470, set_data),
            (0x180553A00, get_data),
            (0x18054C6B8, lambda: sett(0)),
            (0x180554C88, create_connection),
            (0x180554DAC, set_event_handler),
            (0x1805550B4, lambda: sett(0)),
            (0x180556440, send_sync),
            (0x184E50B38, notify_register_check),
            (0x184E51370, notify_check),
            (0x18073BC1C, lambda: sett(0)),
            (0x18071BEC4, gettimeofday),
        ):
            self.install_callback(address, handler)


def character_set_contains(charset, character: str) -> bool:
    chars = charset.value if isinstance(charset.value, str) else ""
    match = character in chars
    if chars == "0123456789":
        match = unicodedata.category(character) == "Nd"
    if charset.props.get("inverted", 0):
        match = not match
    return match


def encode_component_query(query: str) -> str:
    digits = "0123456789ABCDEF"
    out = []
    for byte in query.encode("utf-8", "surrogateescape"):
        character = chr(byte)
        if ("a" <= character <= "z" or "A" <= character <= "Z" or "0" <= character <= "9"
                or character in "-._~!$&'()*+,;=:@/?"):
            out.append(character)
        else:
            out.append("%" + digits[byte >> 4] + digits[byte & 15])
    return "".join(out)


def _go_key(value: str) -> bytes:
    """sort.Strings orders by bytes."""
    return value.encode("utf-8", "surrogateescape")


def _go_split(text: str, separator: str) -> List[str]:
    if separator == "":
        return list(text)
    return text.split(separator)


def _go_hex(value: int, width: str, verb: str) -> str:
    text = format(value, "X" if verb == "X" else "x")
    if width:
        pad = "0" if width.startswith("0") else " "
        text = text.rjust(int(width), pad)
    return text


def _parse_float(text: str) -> float:
    try:
        return float(text)
    except ValueError:
        return 0.0


def _parse_int(text: str) -> int:
    """strconv.ParseInt(v, 10, 64): 0 unless the whole string is an integer."""
    stripped = text
    if stripped[:1] in "+-":
        digits = stripped[1:]
    else:
        digits = stripped
    if not digits or not digits.isascii() or not digits.isdigit():
        return 0
    value = int(stripped)
    if value > (1 << 63) - 1:
        return (1 << 63) - 1
    if value < -(1 << 63):
        return -(1 << 63)
    return value


def _float_to_int64(value: float) -> int:
    if math.isnan(value) or math.isinf(value) or not -(2 ** 63) <= value < 2 ** 63:
        return -(1 << 63)  # arm64's conversion result Go yields for out-of-range floats
    return int(value)


def _plist_ready(value: Any) -> Any:
    if isinstance(value, GoTime):
        import datetime

        return datetime.datetime.fromtimestamp(value.seconds, datetime.timezone.utc).replace(tzinfo=None)
    if isinstance(value, dict):
        return {key: _plist_ready(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_plist_ready(item) for item in value]
    if value is None:
        raise ValueError("nil is not a property list value")
    return value


def _from_plist(value: Any) -> Any:
    import datetime

    if isinstance(value, datetime.datetime):
        stamp = value.replace(tzinfo=datetime.timezone.utc).timestamp() if value.tzinfo is None else value.timestamp()
        return GoTime(int(stamp), 0)
    if isinstance(value, dict):
        return {key: _from_plist(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_from_plist(item) for item in value]
    if isinstance(value, plistlib.UID):
        return int(value.data)
    return value


__all__ = ["BridgeMixin", "character_set_contains", "encode_component_query"]
