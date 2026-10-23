"""Run Apple's FairPlay/AppleMediaServices code inside the Unicorn CPU emulator.

Python port of ipatool ``internal/sap/machine`` since 0259df3 / b0fe32d
(arm64, macOS 27 frameworks; MIT). CoreFP is relocated and mapped into an
arm64 Unicorn instance next to AppleMediaServices, which comes from the dyld
shared cache and stays at its cache addresses; the libSystem /
CoreFoundation / IOKit functions they call are emulated by Python "shims"
that a code hook dispatches. Then the five obfuscated AppleMediaServices
entry points are invoked with the AAPCS64 calling convention to initialize,
run the SAP handshake and sign requests. For kbsync, CommerceKit's
``commerce`` daemon is loaded as an extra image and called at fixed offsets.
"""
from __future__ import annotations

import ctypes
import os
import struct
import time
from typing import Callable, Dict, List, Optional

from unicorn import UC_ARCH_ARM64, UC_HOOK_CODE, UC_MODE_ARM, UC_PROT_ALL, UC_QUERY_TIMEOUT, Uc, UcError
from unicorn import arm64_const as _arm

from . import macho
from .errors import SAPError

U64 = (1 << 64) - 1
U32 = (1 << 32) - 1

# Fixed guest memory layout, identical to upstream machine.go.
RETURN_ADDRESS = 0x0000000100000000
CORE_FP_BASE = 0x0000100000000000
SCRATCH_BASE = 0x0000300000000000
SCRATCH_SIZE = 32 << 20
HEAP_BASE = 0x0000400000000000
HEAP_SIZE = 64 << 20
STACK_BASE = 0x0000500000000000
STACK_SIZE = 8 << 20
STACK_END = STACK_BASE + STACK_SIZE
SHIM_BASE = 0x00007FF880000000
SHIM_CODE_SIZE = 0x0000000000080000
SHIM_SIZE = 0x0000000000100000
SHIM_SLOT_SIZE = 16
PAGE_SIZE = 0x1000
MAX_OUTPUT_SIZE = 16 << 20
MAX_GUEST_TRANSFER = 64 << 20
SAP_GUEST_TIMEOUT = 60.0  # seconds

# StoreAgent (storeagent.go since b0fe32d): CommerceKit's "commerce" daemon,
# loaded as an extra image; private entry points at fixed offsets of the
# pinned binary.
STOREAGENT_BASE = 0x00001000C0000000
_STOREAGENT_GLOBAL_INIT = STOREAGENT_BASE + 0x1312FC
_STOREAGENT_KBSYNC = STOREAGENT_BASE + 0x19AE34
_STOREAGENT_GLOBAL_CLOSE = STOREAGENT_BASE + 0x130EB4
_STOREAGENT_SC_INFO_PATH = b"/Users/Shared/SC Info\x00"
_STOREAGENT_ZERO_RETURN_ALIASES = (
    "_pthread_rwlock_rdlock",
    "_pthread_rwlock_rdlock$UNIX2003",
    "_pthread_mutex_init",
    "_pthread_mutex_destroy",
    "_pthread_rwlock_destroy",
)

# macos27.go: AppleMediaServices' pointers into other shared-cache images
# (their unslid cache addresses), replaced with the emulator's services.
SHARED_CACHE_FUNCTIONS = {
    0x0000000180675CE8: "_malloc",
    0x00000001806766F0: "_free",
    0x00000001806CF570: "_dispatch_once",
    0x000000018071ACC8: "_sysctlbyname",
    0x000000018071BEC4: "_gettimeofday",
    0x0000000180721FB8: "_arc4random",
    0x00000001807238A4: "___memset_chk",
    0x00000001807903C4: "_abort",
    0x0000000180849604: "___error",
    0x0000000180889BC4: "_pthread_once",
    0x000000018088A6F8: "_pthread_rwlock_unlock",
    0x000000018088A7C0: "_pthread_rwlock_wrlock",
    0x000000018088B2D8: "_pthread_rwlock_init",
    0x0000000180894B40: "_strlen",
    0x00000001808CF540: "_CFStringCreateWithCString",
    0x00000001808D4200: "_CFStringGetLength",
    0x00000001808D44DC: "_CFStringGetCString",
    0x00000001808D7278: "_CFRelease",
    0x00000001808E89E8: "_CFDataGetLength",
    0x0000000184D6B4CC: "_IOServiceMatching",
    0x0000000184D6C168: "_IOServiceGetMatchingServices",
    0x0000000184D6C4FC: "_IOIteratorNext",
    0x0000000184D6CB50: "_IOObjectRelease",
}
SHARED_CACHE_SLOTS = {
    0x00000001E02205C0: "___stack_chk_guard",
    0x00000001E800C958: "___chkstk_darwin",
}

_ARG_REGISTERS = [getattr(_arm, f"UC_ARM64_REG_X{i}") for i in range(8)]

_CORE_EXPORT_NAMES = [
    "_WIn9UJ86JKdV4dM",
    "_X46O5IeS",
    "_YlCJ3lg",
    "_dku592fbFAj",
    "_fdjkDSAFjklaf2s",
    "_lxpgvVMLd0S7uRl",
]
_ENTRY_NAMES = ["_cp2g1b9ro", "_Mib5yocT", "_Fc3vhtJDvr", "_IPaI1oem5iL", "_jEHf8Xzsv8K"]

_FAKE_HANDLE = U64
_CORE_FP_FILE = 3
_CORE_FP_PATH = "/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP"
_ICXS_PATH = "./../CoreFP.icxs"
_KEY_SERIAL = "IOPlatformSerialNumber"
_KEY_UUID = "IOPlatformUUID"
_KEY_BOARD = "board-id"
_KEYED_MESSAGE = "objectForKey:"
_ONCE_DONE = 0x4F4E4345

_RET = struct.pack("<I", 0xD65F03C0)
_BRK = struct.pack("<I", 0xD4200000)

# arm64.go: instructions this Unicorn build doesn't implement.
_ATOMIC_MASK = 0xFFE0FC00
_CASAL32, _CASAL64 = 0x88E0FC00, 0xC8E0FC00
_SWPAL32, _SWPAL64 = 0xB8E08000, 0xF8E08000
_EOR3_MASK, _EOR3 = 0xFFE08000, 0xCE000000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _general_register(index: int) -> Optional[int]:
    if index <= 28:
        return _arm.UC_ARM64_REG_X0 + index
    if index == 29:
        return _arm.UC_ARM64_REG_X29
    if index == 30:
        return _arm.UC_ARM64_REG_LR
    return None


class Machine:
    """One emulator instance holding CoreFP and AppleMediaServices."""

    def __init__(self, bundle, extra_images=(), zero_return_aliases=()) -> None:
        self._extra_images = tuple(extra_images)  # (name, data, base)
        self._zero_return_aliases = tuple(zero_return_aliases)
        try:
            self._uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        except UcError as exc:
            raise SAPError(
                "this Unicorn build has no arm64 support, which sign-in needs since Apple's macOS 27 "
                "frameworks are used - on iOS/Android rebuild it from the project folder with "
                "'pip install --force-reinstall --no-deps ./vendor/unicorn'"
            ) from exc
        if os.name == "nt":
            # As upstream (engine_config_windows.go): Windows commits the JIT
            # translation buffer eagerly, so keep it modest.
            try:
                self._uc.ctl_set_tcg_buffer_size(64 << 20)
            except Exception:  # noqa: BLE001 - older bindings: keep the default
                pass
        # Unicorn's most capable ARM64 model; the compatibility layer below
        # handles the few newer instructions it lacks.
        self._uc.ctl_set_cpu_model(_arm.UC_CPU_ARM64_MAX)
        self._closed = False
        self._scratch_cursor = 0
        self._fault: Optional[Exception] = None

        # Shim state.
        self._shim_entries: Dict[int, "_Shim"] = {}
        self._shim_symbols: Dict[str, int] = {}
        self._code_cursor = SHIM_BASE
        self._data_cursor = SHIM_BASE + SHIM_CODE_SIZE
        self._core_exports: Dict[str, int] = {}
        self._icxs = bundle.core_fp_icxs
        self._icxs_offset = 0
        self._errno_addr = 0
        self._heap_cursor = 0
        self._allocations: Dict[int, int] = {}  # address -> reserved size
        self._alloc_sizes: Dict[int, int] = {}  # address -> requested size
        self._free_blocks: List[List[int]] = []  # [address, size]
        self._iterator = 0
        self._callback_returns: List[int] = []

        self._entry: Dict[str, int] = {}
        self.exports: Dict[str, int] = {}

        try:
            self._open_runtime(bundle)
        except Exception:
            self.close()
            raise

    # -- setup ------------------------------------------------------------

    def _open_runtime(self, bundle) -> None:
        core = macho.Image("CoreFP", bundle.core_fp)
        media = macho.PrelinkedImage("AppleMediaServices", bundle.apple_media_services)
        extras = [(name, macho.Image(name, data), base) for name, data, base in self._extra_images]

        exports: Dict[str, int] = {}
        for name in _CORE_EXPORT_NAMES:
            exports[name] = core.export(name, CORE_FP_BASE)
        self._core_exports = dict(exports)
        for name in _ENTRY_NAMES:
            exports[name] = media.export(name)
        self.exports = exports

        for address, size in (
            (RETURN_ADDRESS, PAGE_SIZE),
            (SCRATCH_BASE, SCRATCH_SIZE),
            (HEAP_BASE, HEAP_SIZE),
            (STACK_BASE, STACK_SIZE),
        ):
            self._uc.mem_map(address, size, UC_PROT_ALL)
        self._uc.mem_write(RETURN_ADDRESS, _BRK)  # sentinel at the return address

        self._setup_shims()
        if self._zero_return_aliases:
            self._alias(list(self._zero_return_aliases), self._sh_return_zero)

        def resolve(name: str) -> int:
            if name in exports:
                return exports[name]
            return self._shim_resolve(name)

        self._load_prelinked_slots(SHARED_CACHE_SLOTS, resolve)
        self._load_prelinked_functions(SHARED_CACHE_FUNCTIONS, resolve)

        core.relocate(CORE_FP_BASE, resolve)
        core.load(self._uc)
        media.prepare_prelinked(SHARED_CACHE_FUNCTIONS, resolve)
        media.load(self._uc)
        for _name, image, base in extras:
            image.relocate(base, resolve)
            image.load(self._uc)

        self._entry = {
            "initialize": exports["_cp2g1b9ro"],
            "exchange": exports["_Mib5yocT"],
            "sign": exports["_Fc3vhtJDvr"],
            "teardown": exports["_IPaI1oem5iL"],
            "dispose": exports["_jEHf8Xzsv8K"],
        }

    def _map_pages(self, pages) -> None:
        for page in sorted(pages):
            self._uc.mem_map(page, PAGE_SIZE, UC_PROT_ALL)

    def _load_prelinked_functions(self, functions: Dict[int, str], resolve) -> None:
        """loadPrelinkedFunctions: a branch to the emulator's service at each
        cache function address AppleMediaServices calls directly."""
        pages = set()
        for address in functions:
            pages.add(address - address % PAGE_SIZE)
            end = address + 15
            pages.add(end - end % PAGE_SIZE)
        self._map_pages(pages)
        for address, name in functions.items():
            trampoline = struct.pack("<IIQ", 0x58000050, 0xD61F0200, resolve(name))  # ldr x16, #8; br x16
            self._uc.mem_write(address, trampoline)

    def _load_prelinked_slots(self, slots: Dict[int, str], resolve) -> None:
        self._map_pages({address - address % PAGE_SIZE for address in slots})
        for address, name in slots.items():
            self._uc.mem_write(address, struct.pack("<Q", resolve(name) & U64))

    # -- public API mirrors signer.Signer's needs -------------------------

    def initialize(self, hardware_id: bytes) -> int:
        hardware = _hardware_block(hardware_id)
        self._begin_call()
        try:
            context_field = self._scratch(None, 8)
            hardware_addr = self._scratch(hardware, len(hardware))
            status = self._invoke(self._entry["initialize"], context_field, hardware_addr)
            if _to_i32(status) != 0:
                raise SAPError(f"SAP initialization returned {_to_i32(status)}")
            context = self._read_u64(context_field)
            if context == 0:
                raise SAPError("SAP initialization returned a null context")
            return context
        finally:
            self._clear_scratch()

    def exchange(self, version: int, hardware_id: bytes, context: int, data: bytes):
        if len(data) > U32:
            raise SAPError("SAP exchange input is too large")
        hardware = _hardware_block(hardware_id)
        self._begin_call()
        try:
            hardware_addr = self._scratch(hardware, len(hardware))
            input_addr = self._scratch(data, len(data))
            output_field = self._scratch(None, 8)
            length_field = self._scratch(None, 8)
            result_field = self._scratch(None, 4)
            status = self._invoke(
                self._entry["exchange"], version, hardware_addr, context, input_addr, len(data),
                output_field, length_field, result_field,
            )
            if _to_i32(status) != 0:
                raise SAPError(f"SAP exchange returned {_to_i32(status)}")
            output = self._consume_output(output_field, length_field)
            state = self._read_u32(result_field)
            return output, _to_i32(state)
        finally:
            self._clear_scratch()

    def sign(self, context: int, data: bytes) -> bytes:
        if len(data) > U32:
            raise SAPError("SAP signing input is too large")
        self._begin_call()
        try:
            input_addr = self._scratch(data, len(data))
            output_field = self._scratch(None, 8)
            length_field = self._scratch(None, 8)
            status = self._invoke(self._entry["sign"], context, input_addr, len(data), output_field, length_field)
            if _to_i32(status) != 0:
                raise SAPError(f"SAP signing returned {_to_i32(status)}")
            return self._consume_output(output_field, length_field)
        finally:
            self._clear_scratch()

    def teardown(self, context: int) -> None:
        status = self._invoke(self._entry["teardown"], context)
        if _to_i32(status) != 0:
            raise SAPError(f"SAP teardown returned {_to_i32(status)}")

    def _dispose(self, output: int) -> None:
        status = self._invoke(self._entry["dispose"], output)
        if _to_i32(status) != 0:
            raise SAPError(f"SAP storage disposal returned {_to_i32(status)}")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._uc = None  # let the emulator be collected

    # -- calling convention ----------------------------------------------

    def _invoke(self, function: int, *arguments: int) -> int:
        if self._closed:
            raise SAPError("SAP guest machine is closed")
        if not function:
            raise SAPError("SAP guest entry point is unavailable")
        uc = self._uc
        for index, register in enumerate(_ARG_REGISTERS):
            uc.reg_write(register, arguments[index] & U64 if index < len(arguments) else 0)
        extra = max(len(arguments) - len(_ARG_REGISTERS), 0)
        stack = STACK_END - extra * 8
        stack -= stack % 16
        for index in range(extra):
            self._write_u64(stack + index * 8, arguments[len(_ARG_REGISTERS) + index] & U64)
        uc.reg_write(_arm.UC_ARM64_REG_SP, stack)
        uc.reg_write(_arm.UC_ARM64_REG_LR, RETURN_ADDRESS)

        self._fault = None
        self._callback_returns = []
        # SAP's cryptographic routines have input- and host-dependent
        # instruction counts: bound execution by wall time instead.
        deadline = time.monotonic() + SAP_GUEST_TIMEOUT
        start = function
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SAPError(f"SAP guest timed out after {SAP_GUEST_TIMEOUT:g}s")
            try:
                uc.emu_start(start, RETURN_ADDRESS, int(remaining * 1_000_000), 0)
                break
            except UcError as exc:
                if self._fault is not None:
                    raise self._fault
                if self._emulate_invalid_instruction():
                    start = uc.reg_read(_arm.UC_ARM64_REG_PC)
                    continue
                pc = uc.reg_read(_arm.UC_ARM64_REG_PC)
                lr = uc.reg_read(_arm.UC_ARM64_REG_LR)
                raise SAPError(f"execute SAP guest function at {pc:#x} from {lr:#x}: {exc}") from exc
        if self._fault is not None:
            raise self._fault
        if uc.query(UC_QUERY_TIMEOUT):
            raise SAPError(f"SAP guest timed out after {SAP_GUEST_TIMEOUT:g}s")
        pc = uc.reg_read(_arm.UC_ARM64_REG_PC)
        if pc != RETURN_ADDRESS:
            raise SAPError(f"SAP guest stopped unexpectedly at {pc:#x}")
        return uc.reg_read(_arm.UC_ARM64_REG_X0)

    # -- arm64 compatibility (arm64.go) ----------------------------------

    def _emulate_invalid_instruction(self) -> bool:
        uc = self._uc
        pc = uc.reg_read(_arm.UC_ARM64_REG_PC)
        try:
            instruction = struct.unpack("<I", bytes(uc.mem_read(pc, 4)))[0]
        except UcError:
            return False
        if instruction & _EOR3_MASK == _EOR3:
            destination = instruction & 31
            first = (instruction >> 5) & 31
            third = (instruction >> 10) & 31
            second = (instruction >> 16) & 31
            v0 = _arm.UC_ARM64_REG_V0
            value = uc.reg_read(v0 + first) ^ uc.reg_read(v0 + second) ^ uc.reg_read(v0 + third)
            uc.reg_write(v0 + destination, value)
            uc.reg_write(_arm.UC_ARM64_REG_PC, pc + 4)
            return True
        opcode = instruction & _ATOMIC_MASK
        if opcode in (_CASAL32, _SWPAL32):
            width = 4
        elif opcode in (_CASAL64, _SWPAL64):
            width = 8
        else:
            return False
        mask = (1 << (8 * width)) - 1
        source = (instruction >> 16) & 31
        base = (instruction >> 5) & 31
        destination = instruction & 31
        address = uc.reg_read(_arm.UC_ARM64_REG_SP if base == 31 else _general_register(base))
        try:
            old = int.from_bytes(bytes(uc.mem_read(address, width)), "little")
        except UcError as exc:
            raise SAPError(f"read arm64 atomic operand at {address:#x}: {exc}") from exc
        source_value = self._value_register(source) & mask
        if opcode in (_CASAL32, _CASAL64):
            new = self._value_register(destination) & mask
            if old == source_value:
                uc.mem_write(address, new.to_bytes(width, "little"))
            self._write_value_register(source, old)
        else:
            uc.mem_write(address, source_value.to_bytes(width, "little"))
            self._write_value_register(destination, old)
        uc.reg_write(_arm.UC_ARM64_REG_PC, pc + 4)
        return True

    def _value_register(self, index: int) -> int:
        return 0 if index == 31 else self._uc.reg_read(_general_register(index))

    def _write_value_register(self, index: int, value: int) -> None:
        if index != 31:
            self._uc.reg_write(_general_register(index), value & U64)

    # -- scratch ----------------------------------------------------------

    def _begin_call(self) -> None:
        self._scratch_cursor = 0

    def _scratch(self, data: Optional[bytes], size: int) -> int:
        reserved = _align(max(size, 1), 16)
        if self._scratch_cursor > SCRATCH_SIZE or reserved > SCRATCH_SIZE - self._scratch_cursor:
            raise SAPError("SAP guest scratch space exhausted")
        address = SCRATCH_BASE + self._scratch_cursor
        self._scratch_cursor += reserved
        if data:
            if len(data) > size:
                raise SAPError("scratch data exceeds reservation")
            self._uc.mem_write(address, bytes(data))
        elif size:
            self._uc.mem_write(address, b"\x00" * size)
        return address

    def _clear_scratch(self) -> None:
        if self._scratch_cursor and self._uc is not None and not self._closed:
            self._uc.mem_write(SCRATCH_BASE, b"\x00" * self._scratch_cursor)
        self._scratch_cursor = 0

    def _consume_output(self, pointer_field: int, length_field: int) -> bytes:
        pointer = self._read_u64(pointer_field)
        length = self._read_u64(length_field)
        output = b""
        error: Optional[Exception] = None
        if length > MAX_OUTPUT_SIZE:
            error = SAPError(f"SAP output is {length} bytes, maximum is {MAX_OUTPUT_SIZE}")
        elif length == 0:
            output = b""
        elif pointer == 0:
            error = SAPError("SAP returned a null output pointer")
        else:
            output = bytes(self._uc.mem_read(pointer, length))
        if pointer:
            try:
                self._dispose(pointer)
            except Exception as exc:  # noqa: BLE001
                if error is None:
                    error = exc
        if error is not None:
            raise error
        return output

    # -- StoreAgent (kbsync) ------------------------------------------------

    def _storeagent_global_init(self, hardware_id: bytes) -> int:
        hardware = _hardware_block(hardware_id)
        self._begin_call()
        try:
            hardware_address = self._scratch(hardware, len(hardware))
            path_address = self._scratch(_STOREAGENT_SC_INFO_PATH, len(_STOREAGENT_SC_INFO_PATH))
            context_field = self._scratch(None, 4)
            status = _to_i32(self._invoke(_STOREAGENT_GLOBAL_INIT, 0, hardware_address, path_address, context_field))
            if status != 0:
                raise SAPError(f"StoreAgent global initialization returned {status}")
            value = self._read_u32(context_field)
            if value == 0:
                raise SAPError("StoreAgent global initialization returned a null context")
            return value
        finally:
            self._clear_scratch()

    def _storeagent_global_close(self, global_context: int) -> None:
        status = _to_i32(self._invoke(_STOREAGENT_GLOBAL_CLOSE, global_context))
        if status != 0:
            raise SAPError(f"StoreAgent global context close returned {status}")

    def _storeagent_kbsync(self, global_context: int, dsid: int) -> bytes:
        self._begin_call()
        try:
            pointer_field = self._scratch(None, 8)
            # StoreAgent writes a uint32 length; the zeroed upper half lets the
            # shared bounds-checked output path read it as 64-bit.
            length_field = self._scratch(None, 8)
            status = _to_i32(self._invoke(_STOREAGENT_KBSYNC, global_context, dsid, 0, 1, pointer_field, length_field))
            output: Optional[bytes] = None
            output_error: Optional[Exception] = None
            try:
                output = self._consume_output(pointer_field, length_field)
            except Exception as exc:  # noqa: BLE001
                output_error = exc
            if status != 0:
                raise SAPError(f"StoreAgent kbsync returned {status}") from output_error
            if output_error is not None:
                raise output_error
            if not output:
                raise SAPError("StoreAgent kbsync returned an empty buffer")
            return output
        finally:
            self._clear_scratch()

    # -- memory helpers ---------------------------------------------------

    def _read_u32(self, address: int) -> int:
        return struct.unpack("<I", bytes(self._uc.mem_read(address, 4)))[0]

    def _read_u64(self, address: int) -> int:
        return struct.unpack("<Q", bytes(self._uc.mem_read(address, 8)))[0]

    def _write_u32(self, address: int, value: int) -> None:
        self._uc.mem_write(address, struct.pack("<I", value & U32))

    def _write_u64(self, address: int, value: int) -> None:
        self._uc.mem_write(address, struct.pack("<Q", value & U64))

    def _read_cstring(self, address: int, maximum: int = 4096) -> bytes:
        out = bytearray()
        while len(out) < maximum:
            chunk_size = min(256, PAGE_SIZE - (address + len(out)) % PAGE_SIZE)
            chunk = bytes(self._uc.mem_read(address + len(out), chunk_size))
            end = chunk.find(b"\x00")
            if end >= 0:
                out += chunk[:end]
                return bytes(out)
            out += chunk
        raise SAPError(f"guest string exceeds {maximum} bytes")

    def _read_text(self, address: int) -> str:
        return self._read_cstring(address).decode("utf-8", "replace")

    # -- shim registration (shims.go) ------------------------------------

    def _setup_shims(self) -> None:
        self._uc.mem_map(SHIM_BASE, SHIM_SIZE, UC_PROT_ALL)
        self._register_memory_shims()
        self._register_platform_shims()
        self._uc.hook_add(UC_HOOK_CODE, self._dispatch, None, SHIM_BASE, SHIM_BASE + SHIM_CODE_SIZE - 1)

    def _shim_resolve(self, name: str) -> int:
        if name in self._shim_symbols:
            return self._shim_symbols[name]

        def unsupported() -> None:
            raise SAPError(f"guest called unsupported import {name}")

        return self._add_function(name, unsupported)

    def _add_function(self, name: str, handler: Callable[[], None]) -> int:
        if name in self._shim_symbols:
            return self._shim_symbols[name]
        if self._code_cursor + SHIM_SLOT_SIZE > SHIM_BASE + SHIM_CODE_SIZE:
            raise SAPError("guest service code area is full")
        address = self._code_cursor
        self._code_cursor += SHIM_SLOT_SIZE
        self._uc.mem_write(address, _RET)
        self._shim_entries[address] = _Shim(name, handler)
        self._shim_symbols[name] = address
        return address

    def _add_data(self, name: str, data: bytes) -> int:
        if name in self._shim_symbols:
            return self._shim_symbols[name]
        self._data_cursor = _align(self._data_cursor, 8)
        if self._data_cursor + len(data) > SHIM_BASE + SHIM_SIZE:
            raise SAPError("guest service data area is full")
        address = self._data_cursor
        self._data_cursor += max(len(data), 8)
        self._uc.mem_write(address, data)
        self._shim_symbols[name] = address
        return address

    def _alias(self, names: List[str], handler: Callable[[], None]) -> None:
        for name in names:
            self._add_function(name, handler)

    def _dispatch(self, uc, address, size, user_data) -> None:
        shim = self._shim_entries.get(address)
        if shim is None:
            self._fail(SAPError(f"guest entered unknown service address {address:#x}"))
            return
        try:
            shim.handler()
        except Exception as exc:  # noqa: BLE001
            self._fail(SAPError(f"{shim.name}: {exc}"))

    def _fail(self, error: Exception) -> None:
        if self._fault is None:
            self._fault = error
        try:
            self._uc.emu_stop()
        except Exception:  # noqa: BLE001
            pass

    # -- argument / result helpers for shims -----------------------------

    def _argument(self, index: int) -> int:
        if 0 <= index < len(_ARG_REGISTERS):
            return self._uc.reg_read(_ARG_REGISTERS[index])
        if index < 0:
            raise SAPError("negative guest argument index")
        stack = self._uc.reg_read(_arm.UC_ARM64_REG_SP)
        return self._read_u64(stack + (index - len(_ARG_REGISTERS)) * 8)

    def _set_result(self, value: int) -> None:
        self._uc.reg_write(_arm.UC_ARM64_REG_X0, value & U64)

    def _checked_size(self, value: int) -> int:
        if value > MAX_GUEST_TRANSFER:
            raise SAPError(f"guest transfer size {value} exceeds limit")
        return value

    # -- memory shims (shim_memory.go) -----------------------------------

    def _register_memory_shims(self) -> None:
        self._alias(["_malloc"], self._sh_malloc)
        self._alias(["_malloc_good_size"], self._sh_malloc_good_size)
        self._alias(["_malloc_size"], self._sh_malloc_size)
        self._alias(["_calloc"], self._sh_calloc)
        self._alias(["_realloc", "_reallocf"], self._sh_realloc)
        self._alias(["_free"], self._sh_free)
        self._alias(["_mmap"], self._sh_mmap)
        self._alias(["_munmap"], self._sh_munmap)
        self._alias(["_vm_allocate"], self._sh_vm_allocate)
        self._alias(["_vm_deallocate"], self._sh_vm_deallocate)
        self._alias(["_memcpy", "_memmove"], self._sh_memmove)
        self._alias(["_memset"], self._sh_memset)
        self._alias(["___bzero"], self._sh_bzero)
        self._alias(["___memcpy_chk"], self._sh_checked_memcpy)
        self._alias(["___memset_chk"], self._sh_checked_memset)
        self._alias(["_memcmp"], self._sh_memcmp)
        self._alias(["_strcmp"], self._sh_strcmp)
        self._alias(["_strncmp"], self._sh_strncmp)
        self._alias(["_strlen"], self._sh_strlen)

    def _allocate(self, size: int) -> int:
        if size > MAX_GUEST_TRANSFER:
            raise SAPError(f"allocation size {size} exceeds limit")
        reserved = _align(max(size, 1), 16)
        for index, block in enumerate(self._free_blocks):
            if block[1] < reserved:
                continue
            address = block[0]
            if block[1] == reserved:
                self._free_blocks.pop(index)
            else:
                block[0] += reserved
                block[1] -= reserved
            self._allocations[address] = reserved
            self._alloc_sizes[address] = size
            return address
        if self._heap_cursor > HEAP_SIZE or reserved > HEAP_SIZE - self._heap_cursor:
            raise SAPError("guest heap exhausted")
        address = HEAP_BASE + self._heap_cursor
        self._heap_cursor += reserved
        self._allocations[address] = reserved
        self._alloc_sizes[address] = size
        return address

    def _allocate_aligned(self, size: int, alignment: int) -> int:
        if size > MAX_GUEST_TRANSFER:
            raise SAPError(f"allocation size {size} exceeds limit")
        reserved = _align(max(size, 1), alignment)
        cursor = _align(self._heap_cursor, alignment)
        if cursor > HEAP_SIZE or reserved > HEAP_SIZE - cursor:
            raise SAPError("guest heap exhausted")
        address = HEAP_BASE + cursor
        self._heap_cursor = cursor + reserved
        self._allocations[address] = reserved
        self._alloc_sizes[address] = size
        return address

    def _release(self, address: int) -> None:
        reserved = self._allocations.get(address)
        if reserved is None:
            raise SAPError(f"free unknown pointer {address:#x}")
        self._uc.mem_write(address, b"\x00" * reserved)
        del self._allocations[address]
        self._alloc_sizes.pop(address, None)
        self._free_blocks.append([address, reserved])
        self._coalesce_free_blocks()

    def _coalesce_free_blocks(self) -> None:
        self._free_blocks.sort(key=lambda b: b[0])
        merged: List[List[int]] = []
        for block in self._free_blocks:
            if merged and merged[-1][0] + merged[-1][1] == block[0]:
                merged[-1][1] += block[1]
            else:
                merged.append(list(block))
        self._free_blocks = merged
        while self._free_blocks:
            last = self._free_blocks[-1]
            if last[0] + last[1] != HEAP_BASE + self._heap_cursor:
                break
            self._heap_cursor -= last[1]
            self._free_blocks.pop()

    def _sh_malloc(self) -> None:
        self._set_result(self._allocate(self._argument(0)))

    def _sh_malloc_good_size(self) -> None:
        self._set_result(_align(max(self._argument(0), 1), 16))

    def _sh_malloc_size(self) -> None:
        self._set_result(self._allocations.get(self._argument(0), 0))

    def _sh_calloc(self) -> None:
        count = self._argument(0)
        size = self._argument(1)
        if count != 0 and size > U64 // count:
            raise SAPError("allocation size overflows")
        total = count * size
        address = self._allocate(total)
        if total:
            self._uc.mem_write(address, b"\x00" * total)
        self._set_result(address)

    def _sh_realloc(self) -> None:
        old = self._argument(0)
        new_size = self._argument(1)
        if old == 0:
            self._set_result(self._allocate(new_size))
            return
        reserved = self._allocations.get(old)
        if reserved is None:
            raise SAPError(f"reallocate unknown pointer {old:#x}")
        if new_size <= reserved:
            self._alloc_sizes[old] = new_size
            self._set_result(old)
            return
        new_address = self._allocate(new_size)
        data = bytes(self._uc.mem_read(old, self._alloc_sizes[old]))
        self._uc.mem_write(new_address, data)
        self._release(old)
        self._set_result(new_address)

    def _sh_free(self) -> None:
        address = self._argument(0)
        if address:
            self._release(address)
        self._set_result(0)

    def _sh_mmap(self) -> None:
        length = self._argument(1)
        try:
            address = self._allocate_aligned(length, PAGE_SIZE)
        except SAPError:
            self._sh_return_minus_one()
            return
        self._uc.mem_write(address, b"\x00" * length)
        self._set_result(address)

    def _sh_munmap(self) -> None:
        try:
            self._release(self._argument(0))
        except SAPError:
            self._set_result(U64)
            return
        self._set_result(0)

    def _sh_vm_allocate(self) -> None:
        field = self._argument(1)
        size = self._argument(2)
        try:
            address = self._allocate_aligned(size, PAGE_SIZE)
        except SAPError:
            self._set_result(3)  # KERN_NO_SPACE
            return
        self._uc.mem_write(address, b"\x00" * size)
        self._write_u64(field, address)
        self._set_result(0)

    def _sh_vm_deallocate(self) -> None:
        try:
            self._release(self._argument(1))
        except SAPError:
            self._set_result(1)  # KERN_INVALID_ADDRESS
            return
        self._set_result(0)

    def _sh_memmove(self) -> None:
        dst, src, length = self._argument(0), self._argument(1), self._argument(2)
        self._checked_size(length)
        if length:
            self._uc.mem_write(dst, bytes(self._uc.mem_read(src, length)))
        self._set_result(dst)

    def _sh_memset(self) -> None:
        dst, value, length = self._argument(0), self._argument(1), self._argument(2)
        size = self._checked_size(length)
        if size:
            self._uc.mem_write(dst, bytes([value & 0xFF]) * size)
        self._set_result(dst)

    def _sh_bzero(self) -> None:
        dst, length = self._argument(0), self._argument(1)
        size = self._checked_size(length)
        if size:
            self._uc.mem_write(dst, b"\x00" * size)
        self._set_result(dst)

    def _sh_checked_memcpy(self) -> None:
        if self._argument(2) > self._argument(3):
            raise SAPError("checked copy exceeds destination")
        self._sh_memmove()

    def _sh_checked_memset(self) -> None:
        if self._argument(2) > self._argument(3):
            raise SAPError("checked fill exceeds destination")
        self._sh_memset()

    def _sh_memcmp(self) -> None:
        left, right, length = self._argument(0), self._argument(1), self._argument(2)
        self._checked_size(length)
        a = bytes(self._uc.mem_read(left, length)) if length else b""
        b = bytes(self._uc.mem_read(right, length)) if length else b""
        self._set_result(_cmp(a, b))

    def _sh_strcmp(self) -> None:
        a = self._read_cstring(self._argument(0))
        b = self._read_cstring(self._argument(1))
        self._set_result(_cmp(a, b))

    def _sh_strncmp(self) -> None:
        left, right, length = self._argument(0), self._argument(1), self._argument(2)
        self._checked_size(length)
        offset = 0
        while offset < length:
            la, ra = left + offset, right + offset
            chunk = min(length - offset, PAGE_SIZE - la % PAGE_SIZE, PAGE_SIZE - ra % PAGE_SIZE)
            a = bytes(self._uc.mem_read(la, chunk))
            b = bytes(self._uc.mem_read(ra, chunk))
            for index in range(chunk):
                if a[index] != b[index]:
                    self._set_result((a[index] - b[index]) & U64)
                    return
                if a[index] == 0:
                    self._set_result(0)
                    return
            offset += chunk
        self._set_result(0)

    def _sh_strlen(self) -> None:
        self._set_result(len(self._read_cstring(self._argument(0))))

    # -- platform shims (shim_platform.go) -------------------------------

    def _register_platform_shims(self) -> None:
        self._alias(
            [
                "_CFBundleGetMainBundle", "_CFDataGetBytePtr", "_CFDataGetLength",
                "_CFStringGetLength", "_CFStringGetMaximumSizeForEncoding", "_CFUUIDCreateString",
                "_IORegistryEntryFromPath", "_IORegistryEntrySearchCFProperty", "_IOServiceMatching",
                "_getenv", "_pthread_self",
            ],
            self._sh_return_zero,
        )
        self._alias(
            [
                "_CFDictionaryGetValue", "_DADiskCopyDescription", "_DADiskCreateFromBSDName",
                "_DASessionCreate", "_IORegistryEntryCreateCFProperty",
            ],
            self._sh_return_fake_handle,
        )
        self._alias(
            [
                "_CFRelease", "_IOObjectRelease", "_close", "_close$UNIX2003",
                "_pthread_mutex_lock", "_pthread_mutex_unlock",
                "_pthread_rwlock_init", "_pthread_rwlock_init$UNIX2003",
                "_pthread_rwlock_unlock", "_pthread_rwlock_unlock$UNIX2003",
                "_pthread_rwlock_wrlock", "_pthread_rwlock_wrlock$UNIX2003",
            ],
            self._sh_return_zero,
        )
        self._alias(["_CFStringCreateWithCString"], self._sh_cfstring_create)
        self._alias(["_CFStringCreateWithCStringNoCopy"], self._sh_return_zero)
        self._alias(["_CFStringGetCString"], self._sh_cfstring_get_cstring)
        self._alias(["___chkstk_darwin", "____chkstk_darwin"], self._sh_return_unchanged)
        self._alias(["_IOIteratorNext"], self._sh_io_iterator_next)
        self._alias(["_IORegistryEntryGetParentEntry"], self._sh_io_registry_parent)
        self._alias(["_IOServiceGetMatchingServices"], self._sh_io_matching_services)
        self._alias(["_IOServiceGetMatchingService"], self._sh_return_u32_max)
        self._alias(["_OSAtomicCompareAndSwap32Barrier"], self._sh_cas32)
        self._alias(["___error"], self._sh_error_pointer)
        self._alias(["_abort", "___stack_chk_fail", "dyld_stub_binder"], self._sh_abort)
        self._alias(["_arc4random"], self._sh_arc4random)
        self._alias(["_basename"], self._sh_basename)
        self._alias(["_bootstrap_look_up"], self._sh_bootstrap_look_up)
        self._alias(["_dispatch_once"], self._sh_dispatch_once)
        self._alias(["_dlopen"], self._sh_dlopen)
        self._alias(["_dlsym"], self._sh_dlsym)
        self._alias(
            ["_fcntl", "_fcntl$UNIX2003", "_lstat$INODE64", "_statfs", "_statfs$INODE64"],
            self._sh_return_minus_one,
        )
        self._alias(["_gettimeofday"], self._sh_gettimeofday)
        self._alias(["_objc_msgSend"], self._sh_objc_msg_send)
        self._alias(["_open", "_open$UNIX2003"], self._sh_open)
        self._alias(["_pthread_once"], self._sh_pthread_once)
        self._alias(["_read", "_read$UNIX2003"], self._sh_read)
        self._alias(["_sysctl"], self._sh_return_minus_one)
        self._alias(["_sysctlbyname"], self._sh_sysctlbyname)
        self._alias(["_sysconf"], self._sh_sysconf)

        self._errno_addr = self._add_data("guest.errno", b"\x00" * 8)
        self._add_data("___stack_chk_guard", bytes([0xA5, 0x71, 0x3C, 0xD9, 0x86, 0x42, 0xEF, 0x10]))
        for name in ("_kCFAllocatorDefault", "_kCFAllocatorNull", "_kDADiskDescriptionVolumeUUIDKey", "_kIOMasterPortDefault"):
            self._add_data(name, b"\x00" * 8)
        self._add_function("callback.complete", self._sh_callback_complete)

    def _sh_return_zero(self) -> None:
        self._set_result(0)

    def _sh_return_unchanged(self) -> None:
        pass

    def _sh_return_fake_handle(self) -> None:
        self._set_result(_FAKE_HANDLE)

    def _sh_return_u32_max(self) -> None:
        self._set_result(U32)

    def _sh_return_minus_one(self) -> None:
        self._set_result(U64)

    def _sh_cfstring_create(self) -> None:
        value = self._read_text(self._argument(1))
        self._set_result(_FAKE_HANDLE if value in (_KEY_SERIAL, _KEY_UUID, _KEY_BOARD) else 0)

    def _sh_cfstring_get_cstring(self) -> None:
        buffer = self._argument(1)
        capacity = self._argument(2)
        if buffer == 0 or capacity == 0:
            self._set_result(0)
            return
        self._uc.mem_write(buffer, b"\x00")
        self._set_result(1)

    def _sh_io_iterator_next(self) -> None:
        self._iterator += 1
        self._set_result(self._iterator % 2)

    def _sh_io_registry_parent(self) -> None:
        parent = self._argument(2)
        if parent == 0:
            raise SAPError("parent registry entry output is null")
        self._write_u32(parent, U32)
        self._set_result(0)

    def _sh_io_matching_services(self) -> None:
        iterator = self._argument(2)
        if iterator == 0:
            raise SAPError("matching services iterator output is null")
        self._iterator = 0
        self._write_u32(iterator, U32)
        self._set_result(0)

    def _sh_cas32(self) -> None:
        old = self._argument(0) & U32
        new = self._argument(1) & U32
        address = self._argument(2)
        current = self._read_u32(address)
        if current != old:
            self._set_result(0)
            return
        self._write_u32(address, new)
        self._set_result(1)

    def _sh_error_pointer(self) -> None:
        self._set_result(self._errno_addr)

    def _sh_abort(self) -> None:
        raise SAPError("guest aborted")

    def _sh_arc4random(self) -> None:
        self._set_result(struct.unpack("<I", os.urandom(4))[0])

    def _sh_basename(self) -> None:
        address = self._argument(0)
        value = self._read_cstring(address).rstrip(b"/")
        index = value.rfind(b"/")
        self._set_result(address + index + 1 if index >= 0 else address)

    def _sh_bootstrap_look_up(self) -> None:
        service = self._argument(2)
        if service:
            self._write_u32(service, 0)
        self._set_result(5)  # KERN_FAILURE

    def _sh_dlopen(self) -> None:
        path = self._read_text(self._argument(0))
        self._set_result(_FAKE_HANDLE if path == _CORE_FP_PATH else 0)

    def _sh_dlsym(self) -> None:
        name = self._read_text(self._argument(1))
        self._set_result(self._core_exports.get("_" + name, 0))

    def _sh_gettimeofday(self) -> None:
        time_addr = self._argument(0)
        zone_addr = self._argument(1)
        now = time.time()
        if time_addr:
            seconds = int(now)
            micros = int((now - seconds) * 1_000_000)
            self._uc.mem_write(time_addr, struct.pack("<QI", seconds, micros) + b"\x00" * 4)
        if zone_addr:
            self._uc.mem_write(zone_addr, b"\x00" * 8)
        self._set_result(0)

    def _sh_objc_msg_send(self) -> None:
        selector = self._read_text(self._argument(1))
        self._set_result(_FAKE_HANDLE if selector == _KEYED_MESSAGE else 0)

    def _sh_open(self) -> None:
        path = self._read_text(self._argument(0))
        if path == _ICXS_PATH:
            self._icxs_offset = 0
            self._set_result(_CORE_FP_FILE)
            return
        self._sh_return_minus_one()

    def _sh_pthread_once(self) -> None:
        control = self._argument(0)
        initializer = self._argument(1)
        value = self._read_u64(control)
        if value in (0, _ONCE_DONE):
            self._set_result(0)
            return
        self._write_u64(control, _ONCE_DONE)
        self._invoke_callback(initializer)

    def _sh_dispatch_once(self) -> None:
        predicate = self._argument(0)
        block = self._argument(1)
        if self._read_u64(predicate) == U64:
            self._set_result(0)
            return
        self._write_u64(predicate, U64)
        initializer = self._read_u64(block + 16)
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
        if descriptor != _CORE_FP_FILE:
            self._sh_return_minus_one()
            return
        size = self._checked_size(requested)
        remaining = len(self._icxs) - self._icxs_offset
        size = min(size, remaining)
        if size:
            self._uc.mem_write(buffer, self._icxs[self._icxs_offset : self._icxs_offset + size])
            self._icxs_offset += size
        self._set_result(size)

    def _sh_sysctlbyname(self) -> None:
        length_addr = self._argument(2)
        if length_addr:
            self._write_u64(length_addr, 0)
        self._set_result(0)

    def _sh_sysconf(self) -> None:
        name = self._argument(0)
        if name == 29:  # _SC_PAGESIZE
            self._set_result(PAGE_SIZE)
        elif name in (57, 58):  # _SC_NPROCESSORS_CONF / _ONLN
            self._set_result(1)
        elif name == 200:  # _SC_PHYS_PAGES
            self._set_result(HEAP_SIZE // PAGE_SIZE)
        else:
            self._sh_return_minus_one()


class _Shim:
    __slots__ = ("name", "handler")

    def __init__(self, name: str, handler: Callable[[], None]) -> None:
        self.name = name
        self.handler = handler


def _hardware_block(hardware_id: bytes) -> bytes:
    if not hardware_id or len(hardware_id) > 20:
        raise SAPError("hardware ID must contain between 1 and 20 bytes")
    return struct.pack("<I", len(hardware_id)) + hardware_id + b"\x00" * (20 - len(hardware_id))


def generate_kbsync(bundle, hardware_id: bytes, dsid: int) -> bytes:
    """ipatool machine.GenerateKBSync: the account- and hardware-bound FairPlay
    blob for the bag's ent/download endpoint, computed by CommerceKit's
    StoreAgent code (no decryption session is opened)."""
    if not dsid:
        raise SAPError("kbsync requires a nonzero account DSID")
    machine = Machine(
        bundle,
        extra_images=[("commerce", bundle.commerce, STOREAGENT_BASE)],
        zero_return_aliases=_STOREAGENT_ZERO_RETURN_ALIASES,
    )
    try:
        global_context = machine._storeagent_global_init(hardware_id)
        try:
            return machine._storeagent_kbsync(global_context, dsid)
        finally:
            try:
                machine._storeagent_global_close(global_context)
            except SAPError:
                pass
    finally:
        machine.close()


def _to_i32(value: int) -> int:
    return ctypes.c_int32(value & U32).value


def _cmp(a: bytes, b: bytes) -> int:
    if a < b:
        return U64  # -1
    if a > b:
        return 1
    return 0
