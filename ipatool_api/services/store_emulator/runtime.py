"""The Objective-C/Swift runtime bridge for the pinned AppleMediaServices image.

Port of ipatool ``internal/store/emulator`` (runtime.go, metadata.go,
memory.go, callbacks.go; ipatool 2.8, MIT). AppleMediaServices and its
authentication plugin run in a Unicorn arm64 instance on top of a profile of
pre-initialized guest memory (``profile.py``). Every call the image makes
into another shared-cache library lands on a stub whose behaviour is
implemented here in Python: Objective-C messages to Foundation classes,
libdispatch, the Swift runtime and a few libSystem functions. Objects such
as strings, dictionaries and dates live on the host side (``Obj``); the
guest only sees their addresses.

Unlike upstream, the per-instruction hook is limited to code outside the
pinned image (where only stubs and host callbacks may execute), so the
image's own code runs at full emulator speed. The trace of recent calls and
the periodic cancellation check upstream keeps there are diagnostics only.
"""
from __future__ import annotations

import struct
from typing import Any, Callable, Dict, List, Optional, Tuple

from unicorn import UC_HOOK_CODE, UC_PROT_ALL, Uc, UcError
from unicorn import arm64_const as _arm

from ..sap import engine
from .bridge import BridgeMixin
from .swift import SwiftMixin

U64 = (1 << 64) - 1
HEAP_BASE = 0x400000000000
HEAP_SIZE = 64 << 20
STACK_BASE = 0x500000000000
STACK_SIZE = 8 << 20
RETURN_PC = 0x100000000
PAGE = 4096
_MAX_REGION_GAP = 1 << 20
_MAX_REGION_SIZE = 32 << 20
_MAX_PROFILE_SPAN = 1 << 30
_CALL_TIMEOUT = 120.0
_INSTRUCTION_LIMIT = 20_000_000
_RET = b"\xc0\x03\x5f\xd6"

REG_X0 = _arm.UC_ARM64_REG_X0
REG_X1 = _arm.UC_ARM64_REG_X1
REG_X2 = _arm.UC_ARM64_REG_X2
REG_X3 = _arm.UC_ARM64_REG_X3
REG_X8 = _arm.UC_ARM64_REG_X8
REG_X20 = _arm.UC_ARM64_REG_X20
REG_X22 = _arm.UC_ARM64_REG_X22
REG_X29 = _arm.UC_ARM64_REG_X29
REG_LR = _arm.UC_ARM64_REG_LR
REG_SP = _arm.UC_ARM64_REG_SP
REG_PC = _arm.UC_ARM64_REG_PC
REG_D0 = _arm.UC_ARM64_REG_D0


class EmulatorError(Exception):
    """The guest stopped, faulted, or used something this bridge doesn't model."""


class GuestPanic(Exception):
    """Raised inside a bridge handler (upstream's ``panic``); turned into an
    ``EmulatorError`` at the boundary."""


class Obj:
    """A host-side Foundation object: class name, value and properties."""

    __slots__ = ("cls", "value", "props")

    def __init__(self, cls: str, value: Any = None, props: Optional[Dict[str, int]] = None) -> None:
        self.cls = cls
        self.value = value
        self.props = props if props is not None else {}


class AsyncTask:
    __slots__ = ("continuation", "handle", "context", "entry", "closure", "result", "executor", "done")

    def __init__(self, handle: int, context: int, entry: int, closure: int) -> None:
        self.continuation = 0
        self.handle = handle
        self.context = context
        self.entry = entry
        self.closure = closure
        self.result = 0
        self.executor = (0, 0)
        self.done = False


def method_key(cls: str, selector: str, meta: bool) -> str:
    return ("+" if meta else "-") + "[" + cls + " " + selector + "]"


class Runtime(BridgeMixin, SwiftMixin):
    """One guest VM; used for a single request and then closed."""

    def __init__(self, image, profile) -> None:
        """``image``: the AppleMediaServices image (``sap.macho.PrelinkedImage``
        data from the asset bundle); ``profile``: ``profile.StoreProfile``."""
        meta = profile.metadata
        self.profile = profile
        self.classes = dict(meta.classes)
        self.class_names = dict(meta.class_names)
        self.methods = dict(meta.methods)
        self.calls = meta.calls
        self.selectors = dict(meta.selectors)
        self.selector_addresses = dict(meta.selector_addresses)
        self.objects: Dict[int, Obj] = meta.new_objects()
        self.pages: set = set()
        self.callbacks: Dict[int, Callable[[], None]] = {}
        self.cursor = 0
        self.allocations: Dict[int, int] = {}
        self.fault: Optional[BaseException] = None
        self.hardware_id = b""
        self.xpc_sync_handler: Optional[Callable[[str, bytes], bytes]] = None
        self.null_object = 0
        self.associations: Dict[int, Dict[int, int]] = {}
        self.current_queue = 0
        self.selected_queue = 0
        self.preferences: Dict[str, int] = {}
        self.notification_center = 0
        self.observers: Dict[int, Obj] = {}
        self.pending_queues: Dict[int, int] = {}
        self.pending: List[int] = []
        self.timers: List[Tuple[int, int]] = []
        self.inflaters: Dict[int, Any] = {}
        self.response_headers: Dict[int, Any] = {}
        self.tasks: Dict[int, AsyncTask] = {}
        self.current_task: Optional[AsyncTask] = None
        self.task_local_frames: Dict[int, List[Tuple[int, int]]] = {}
        self._hooked_addresses: set = set()
        self.uc: Optional[Uc] = engine.new_arm64_engine()
        try:
            self._open(image)
        except Exception:
            self.close()
            raise

    # -- set-up (runtime.go open) -----------------------------------------

    def _open(self, image) -> None:
        profile = self.profile
        meta = profile.metadata
        for address, size in ((HEAP_BASE, HEAP_SIZE), (STACK_BASE, STACK_SIZE), (RETURN_PC, PAGE)):
            self.mem_map(address, size)
        for address, size in meta.media_mappings:
            start = address - address % PAGE
            self.mem_map(start, ((address + size + PAGE - 1) & ~(PAGE - 1)) - start)
        for name, loadable in (("AppleMediaServices", image), ("AMSAccountAuthenticationPlugin", profile.plugin_image)):
            if loadable is None:
                continue
            for address, size, data in loadable:
                self.mem_map(address - address % PAGE, ((address + size + PAGE - 1) & ~(PAGE - 1)) - (address - address % PAGE))
                if data:
                    self.uc.mem_write(address, data)

        addresses = [page for page in meta.page_addresses if page not in self.pages]
        for address in meta.calls:
            page = address & ~(PAGE - 1)
            if page not in self.pages:
                addresses.append(page)
        for start, size in _group_pages(addresses):
            self.mem_map(start, size)
        pages = profile.pages
        for address, offset in meta.page_offsets:
            if offset + PAGE > len(pages):
                raise EmulatorError("profile page exceeds data")
            self.uc.mem_write(address, pages[offset:offset + PAGE])
        for address in meta.calls:
            page = address & ~(PAGE - 1)
            if page not in self.pages:
                self.mem_map(page, PAGE)
            self.uc.mem_write(address, _RET)
        for address, value in meta.ivar_offsets:
            self.uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))
        for address, data in meta.metadata_patches:
            self.uc.mem_write(address, data)

        # Host code may run only at stubs and host callbacks, which all lie
        # outside the pinned image's instruction sections: hook exactly that
        # complement, plus stubs that sit inside them.
        self.code_ranges = list(meta.code_ranges)
        cursor = 0
        for start, end in sorted(self.code_ranges):
            if start > cursor:
                self.uc.hook_add(UC_HOOK_CODE, self._step, None, cursor, start - 1)
            cursor = max(cursor, end)
        if cursor <= U64:
            self.uc.hook_add(UC_HOOK_CODE, self._step, None, cursor, U64)
        for address in meta.calls:
            if self._in_code(address):
                self._hook_address(address)

    def _hook_address(self, address: int) -> None:
        if address not in self._hooked_addresses:
            self._hooked_addresses.add(address)
            self.uc.hook_add(UC_HOOK_CODE, self._step, None, address, address)

    def _in_code(self, address: int) -> bool:
        return any(start <= address < end for start, end in self.code_ranges)

    def close(self) -> None:
        self.objects = {}
        self.callbacks = {}
        self.pending = []
        self.timers = []
        self.tasks = {}
        self.uc = None

    def mem_map(self, address: int, size: int) -> None:
        """Map pages not mapped yet; already-mapped pages are kept."""
        page = address
        end = address + size
        while page < end:
            if page in self.pages:
                page += PAGE
                continue
            stop = page + PAGE
            while stop < end and stop not in self.pages:
                stop += PAGE
            self.uc.mem_map(page, stop - page, UC_PROT_ALL)
            while page < stop:
                self.pages.add(page)
                page += PAGE

    def mem_write(self, address: int, data: bytes) -> None:
        if data:
            self.uc.mem_write(address, bytes(data))

    def mem_read(self, address: int, size: int) -> bytes:
        if size == 0:
            return b""
        try:
            return bytes(self.uc.mem_read(address, size))
        except UcError as exc:
            raise GuestPanic(f"read guest memory {address:#x}: {exc}") from exc

    # -- guest memory helpers ---------------------------------------------

    def alloc(self, size: int) -> int:
        if size > HEAP_SIZE:
            raise GuestPanic("guest allocation exceeds heap budget")
        size = (size + 15) & ~15
        if size == 0:
            size = 16
        if size > HEAP_SIZE - self.cursor:
            raise GuestPanic("guest heap exhausted")
        address = HEAP_BASE + self.cursor
        self.cursor += size
        self.allocations[address] = size
        return address

    def read64(self, address: int) -> int:
        try:
            return struct.unpack("<Q", bytes(self.uc.mem_read(address, 8)))[0]
        except UcError as exc:
            raise GuestPanic(f"read guest pointer {address:#x}: {exc}") from exc

    def write64(self, address: int, value: int) -> None:
        try:
            self.uc.mem_write(address, struct.pack("<Q", value & U64))
        except UcError as exc:
            raise GuestPanic(f"write guest memory {address:#x}: {exc}") from exc

    def write32(self, address: int, value: int) -> None:
        try:
            self.uc.mem_write(address, struct.pack("<I", value & 0xFFFFFFFF))
        except UcError as exc:
            raise GuestPanic(f"write guest memory {address:#x}: {exc}") from exc

    def reg(self, register: int) -> int:
        return self.uc.reg_read(register)

    def set_reg(self, register: int, value: int) -> None:
        self.uc.reg_write(register, value & U64)

    def arg(self, index: int) -> int:
        if index >= 8:
            return self.read64(self.uc.reg_read(REG_SP) + (index - 8) * 8)
        return self.uc.reg_read(REG_X0 + index)

    def set(self, value: int) -> None:
        self.uc.reg_write(REG_X0, value & U64)

    def cstring(self, address: int) -> str:
        if address == 0:
            return ""
        value = self.selectors.get(address)
        if value is not None:
            return value
        out = bytearray()
        while len(out) < 16384:
            chunk = min(256, PAGE - (address + len(out)) % PAGE, 16384 - len(out))
            try:
                data = bytes(self.uc.mem_read(address + len(out), chunk))
            except UcError as exc:
                raise GuestPanic(f"read C string {address:#x}: {exc}") from exc
            end = data.find(b"\0")
            if end >= 0:
                out += data[:end]
                return out.decode("utf-8", "surrogateescape")
            out += data
        raise GuestPanic("unterminated guest string")

    def selector(self, value: str) -> int:
        address = self.selector_addresses.get(value, 0)
        if address:
            return address
        encoded = value.encode("utf-8", "surrogateescape") + b"\0"
        address = self.alloc(len(encoded))
        self.mem_write(address, encoded)
        self.selector_addresses[value] = address
        self.selectors[address] = value
        return address

    def new(self, cls: str, value: Any = None) -> int:
        """runtime.go New: a host object whose guest storage carries the isa."""
        description = self.classes.get(cls)
        size = max(description.size, 16) if description is not None else 256
        address = self.alloc(size)
        self.objects[address] = Obj(cls, value)
        if description is not None:
            self.write64(address, description.address)
        return address

    def string(self, address: int) -> str:
        if address == 0:
            return ""
        obj = self.objects.get(address)
        if obj is None:
            raise GuestPanic(f"unknown string object {address:#x}")
        if not isinstance(obj.value, str):
            raise GuestPanic(f"object {obj.cls} is not a string")
        return obj.value

    def lookup(self, cls: str, selector: str, meta: bool) -> int:
        while cls:
            address = self.methods.get(method_key(cls, selector, meta), 0)
            if address:
                return address
            description = self.classes.get(cls)
            if description is None:
                break
            cls = description.super
        return 0

    def class_address(self, name: str) -> int:
        description = self.classes.get(name)
        return description.address if description is not None else 0

    # -- calls ------------------------------------------------------------

    def invoke(self, receiver: int, selector: str, *args: int) -> int:
        """Send an Objective-C message from the host (runtime.go Invoke)."""
        try:
            cls = self.class_names.get(receiver)
            meta = cls is not None
            if not meta:
                obj = self.objects.get(receiver)
                if obj is None:
                    raise EmulatorError(f"unknown receiver {receiver:#x} for {selector}")
                cls = obj.cls
            entry = self.lookup(cls, selector, meta)
            if entry == 0:
                block = self.host_block(lambda: self.message(receiver, selector, False))
                entry = self.read64(block + 16)
            arguments = [receiver, self.selector(selector)] + list(args)
        except GuestPanic as exc:
            raise EmulatorError(f"guest setup: {exc}") from exc
        return self.call(entry, *arguments)

    def call(self, entry: int, *arguments: int) -> int:
        uc = self.uc
        for index in range(8):
            uc.reg_write(REG_X0 + index, arguments[index] & U64 if index < len(arguments) else 0)
        sp = STACK_BASE + STACK_SIZE - 4096
        for index in range(8, len(arguments)):
            self.write64(sp + (index - 8) * 8, arguments[index])
        uc.reg_write(REG_SP, sp)
        uc.reg_write(REG_LR, RETURN_PC)
        self.fault = None
        error: Optional[Exception] = None
        try:
            with engine.emulation():
                uc.emu_start(entry, RETURN_PC, int(_CALL_TIMEOUT * 1_000_000), _INSTRUCTION_LIMIT)
        except UcError as exc:
            error = exc
        if self.fault is not None:
            fault = self.fault
            self.fault = None
            raise EmulatorError(str(fault)) from fault
        pc = uc.reg_read(REG_PC)
        if error is not None:
            lr = uc.reg_read(REG_LR)
            raise EmulatorError(f"guest stopped at {pc:#x} from {lr:#x}: {error}")
        if pc != RETURN_PC:
            raise EmulatorError(f"instruction budget exhausted at {pc:#x}")
        return uc.reg_read(REG_X0)

    def _step(self, uc, address, size, user_data) -> None:
        try:
            callback = self.callbacks.get(address)
            if callback is not None:
                callback()
                return
            call = self.calls.get(address)
            if call is None:
                if self._in_code(address):
                    return
                raise GuestPanic(f"execution outside the pinned image at {address:#x}")
            symbol, selector = call
            if selector:
                self.message(self.arg(0), selector, False)
                return
            self.symbol(symbol.lstrip("_"))
        except BaseException as exc:  # noqa: BLE001 - every failure must stop the guest
            if self.fault is None:
                self.fault = EmulatorError(f"guest bridge at {address:#x}: {exc}")
            try:
                uc.emu_stop()
            except Exception:  # noqa: BLE001
                pass

    def jump(self, entry: int, receiver: int, selector: str) -> None:
        self.uc.reg_write(REG_X0, receiver & U64)
        self.uc.reg_write(REG_X1, self.selector(selector))
        self.uc.reg_write(REG_PC, entry)

    # -- callbacks (callbacks.go) -----------------------------------------

    def callback(self, block: int, args: List[int], after: Callable[[], None]) -> None:
        self.callback_function(self.read64(block + 16), [block] + list(args), after)

    def callback_function(self, function: int, args: List[int], after: Callable[[], None]) -> None:
        link = self.uc.reg_read(REG_LR)
        resume = self.alloc(16)
        self.mem_write(resume, _RET)

        def done() -> None:
            self.callbacks.pop(resume, None)
            self.uc.reg_write(REG_LR, link)
            self.uc.reg_write(REG_PC, link)
            after()

        self.callbacks[resume] = done
        for index, value in enumerate(args):
            self.uc.reg_write(_x(index), value & U64)
        self.uc.reg_write(REG_LR, resume)
        self.uc.reg_write(REG_PC, function)

    def copy_block(self, block: int, after: Callable[[int], None]) -> None:
        if block == 0:
            after(0)
            return
        flags = self.read64(block + 8) & 0xFFFFFFFF
        if flags & (1 << 28):
            after(block)
            return
        descriptor = self.read64(block + 24)
        size = self.read64(descriptor + 8)
        if size < 32 or size > 1 << 20:
            raise GuestPanic("invalid guest block size")
        copied = self.alloc(size)
        self.mem_write(copied, self.mem_read(block, size))
        if flags & (1 << 25):
            self.callback_function(self.read64(descriptor + 16), [copied, block], lambda: after(copied))
            return
        after(copied)

    def copy_value(self, value: int, after: Callable[[int], None]) -> None:
        if value == 0:
            after(0)
            return
        obj = self.objects.get(value)
        if obj is not None:
            entry = self.lookup(obj.cls, "copyWithZone:", False)
            if entry:
                self.callback_function(entry, [value, self.selector("copyWithZone:"), 0], lambda: after(self.arg(0)))
                return
            after(value)
            return
        self.copy_block(value, after)

    def copy_byref(self, value: int, after: Callable[[int], None]) -> None:
        forwarded = self.read64(value + 8)
        if forwarded != 0 and forwarded != value:
            after(forwarded)
            return
        header = self.read64(value + 16)
        size = header >> 32
        flags = header & 0xFFFFFFFF
        if size < 24 or size > 1 << 20:
            raise GuestPanic("invalid byref capture size")
        copied = self.alloc(size)
        self.mem_write(copied, self.mem_read(value, size))
        self.write64(copied + 8, copied)
        self.write64(value + 8, copied)
        if flags & (1 << 25):
            self.callback_function(self.read64(value + 24), [copied, value], lambda: after(copied))
            return
        after(copied)

    def host_block(self, fn: Callable[[], None]) -> int:
        """network.go hostBlock: a guest block whose invoke function runs ``fn``."""
        function = self.alloc(16)
        self.mem_write(function, _RET)
        self.callbacks[function] = fn
        descriptor = self.alloc(16)
        self.write64(descriptor + 8, 32)
        block = self.alloc(32)
        self.write64(block + 8, 1 << 28)
        self.write64(block + 16, function)
        self.write64(block + 24, descriptor)
        return block

    def install_callback(self, address: int, callback: Callable[[], None]) -> None:
        """delegate.go install: a host function at a fixed shared-cache address."""
        page = address & ~(PAGE - 1)
        if page not in self.pages:
            self.mem_map(page, PAGE)
        self.mem_write(address, _RET)
        self.callbacks[address] = callback
        if self._in_code(address):
            self._hook_address(address)

    # -- queues -----------------------------------------------------------

    def queue_pending(self, block: int, queue: int) -> None:
        self.pending_queues[block] = queue
        self.pending.append(block)

    def next_pending(self) -> int:
        for index, block in enumerate(self.pending):
            queue = self.objects.get(self.pending_queues.get(block, 0))
            if queue is not None and queue.props.get("suspendCount", 0) != 0:
                continue
            del self.pending[index]
            self.selected_queue = self.pending_queues.pop(block, 0)
            return block
        return 0

    def pending_callback(self, block: int, after: Callable[[], None]) -> None:
        previous = self.current_queue
        self.current_queue = self.selected_queue

        def done() -> None:
            self.current_queue = previous
            after()

        self.callback(block, [], done)

    def queue_is_within(self, queue: int, target: int) -> bool:
        for _ in range(32):
            if queue == target:
                return True
            obj = self.objects.get(queue)
            if obj is None:
                return False
            queue = obj.props.get("targetQueue", 0)
            if queue == 0:
                return False
        raise GuestPanic("cyclic dispatch queue targets")

    # -- export -----------------------------------------------------------

    def export(self, address: int) -> Any:
        return self._export(address, set(), 0)

    def _export(self, address: int, active: set, depth: int) -> Any:
        if address == 0:
            return None
        if depth > 32 or address in active:
            raise EmulatorError("cyclic or excessively nested guest value")
        obj = self.objects.get(address)
        if obj is None:
            raise EmulatorError(f"unknown exported object {address:#x}")
        active.add(address)
        try:
            value = obj.value
            if isinstance(value, dict):
                return {key: self._export(item, active, depth + 1) for key, item in value.items()}
            if isinstance(value, list):
                return [self._export(item, active, depth + 1) for item in value]
            return value
        finally:
            active.discard(address)


def _x(index: int) -> int:
    """Upstream's ``RegX0 + i``: x0-x28 are consecutive in Unicorn's enum."""
    return REG_X0 + index


def _group_pages(addresses: List[int]) -> List[Tuple[int, int]]:
    """memory.go groupPages: nearby pages mapped as one region, bounded."""
    addresses = sorted(addresses)
    for address in addresses:
        if address % PAGE or address > U64 - PAGE:
            raise EmulatorError("invalid Store profile page address")
    regions = []
    total = 0
    start = 0
    while start < len(addresses):
        end = start + 1
        while (end < len(addresses) and addresses[end] - addresses[end - 1] <= _MAX_REGION_GAP
               and addresses[end] - addresses[start] + PAGE <= _MAX_REGION_SIZE):
            end += 1
        size = addresses[end - 1] - addresses[start] + PAGE
        if size > _MAX_PROFILE_SPAN - total:
            raise EmulatorError("store profile mapping exceeds size limit")
        total += size
        regions.append((addresses[start], size))
        start = end
    return regions


__all__ = ["Runtime", "Obj", "EmulatorError", "GuestPanic", "method_key"]
