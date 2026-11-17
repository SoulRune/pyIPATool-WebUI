"""The ADI (anisette) implementation of the pinned macOS 27 images.

Port of ipatool ``internal/sap/machine/modern_adi.go`` (ipatool 2.8, MIT).
Four emulators cooperate the way the processes do on a Mac:

* ``runtime``: AppleMediaServices/CoreFP plus CommerceKit's ``commerce``,
  whose ADI client entry points (start/end provisioning, OTP, keybag import)
  are called at fixed offsets;
* ``daemon``: CoreADI's ``adid``; the client's XPC requests are handed to the
  request handler the daemon installs, and its reply is fed back to the client;
* ``fairplay``: CoreFP's ``fairplayd``, which answers the daemon's IOKit calls;
* ``kernel``: the FairPlayIOKit kernel extension, which ``fairplayd`` talks to
  over Mach RPC.

The ADI state file (``adi.pb``) lives in the daemon's virtual file system; it
is what callers persist between runs.
"""
from __future__ import annotations

from typing import Optional, Tuple

from .errors import SAPError
from .machine import (
    STOREAGENT_BASE,
    STOREAGENT_GLOBAL_CLOSE,
    STOREAGENT_GLOBAL_INIT,
    STOREAGENT_SC_INFO_PATH,
    STOREAGENT_ZERO_RETURN_ALIASES,
    ImageSpec,
    Machine,
    hardware_block,
    to_i32,
)
from .shim_platform import ADI_STATE_PATH, FAKE_HANDLE

_START_ENTRY = STOREAGENT_BASE + 0x1B4400
_END_ENTRY = STOREAGENT_BASE + 0x1D5124
_OTP_ENTRY = STOREAGENT_BASE + 0x1DAB04
_KEYBAG_ENTRY = STOREAGENT_BASE + 0x16E0F8
ADID_BASE = 0x0000200000000000
_ADID_ENTRY = ADID_BASE + 0x11180
FAIRPLAYD_BASE = 0x0000600000000000
_FAIRPLAYD_ENTRY = FAIRPLAYD_BASE + 0x332040
# Keep the prelinked image's 0x510 page offset so its ADRP references retain
# the same slide as its data segments.
FAIRPLAY_KEXT_BASE = 0x0000700000000510
FAIRPLAY_KERNEL_BASE = 0xFFFFFE0007004000
_KEXT_START = FAIRPLAY_KEXT_BASE + 0x2BCA984
_KEXT_SETUP = FAIRPLAY_KEXT_BASE + 0x2C67E50
_KEXT_INIT = FAIRPLAY_KEXT_BASE + 0x2BCA714
_KEXT_ENTRY = FAIRPLAY_KEXT_BASE + 0x2CF978C
_KEXT_STACK_PROBE = FAIRPLAY_KEXT_BASE + 0xB8C028
_KEXT_STACK_PROBE_VALUE = FAIRPLAY_KEXT_BASE + 0x2C66248
_MAX_PAYLOAD = 1 << 20


class ModernADI:
    """machine.ModernADI. Close it after use (each instance holds four
    emulators and a few hundred MB of mapped images)."""

    def __init__(self, bundle, identifier: bytes, state: Optional[bytes] = None) -> None:
        if len(identifier) != 16:
            raise SAPError("modern ADI host UUID must be 16 bytes")
        self.runtime: Optional[Machine] = None
        self.daemon: Optional[Machine] = None
        self.fairplay: Optional[Machine] = None
        self.kernel: Optional[Machine] = None
        self._kernel_context = 0
        self._store_global = 0
        self._daemon_handler = 0
        try:
            self.runtime = Machine(bundle, extra_images=[ImageSpec("commerce", bundle.commerce, STOREAGENT_BASE)],
                                   zero_return_aliases=STOREAGENT_ZERO_RETURN_ALIASES)
            try:
                self.daemon = Machine(bundle, extra_images=[ImageSpec("adid", bundle.adid, ADID_BASE)],
                                      pause_run_loop=True)
            except SAPError as exc:
                raise SAPError(f"open modern ADI daemon: {exc}") from exc
            try:
                self.fairplay = Machine(bundle, extra_images=[ImageSpec("fairplayd", bundle.fairplayd, FAIRPLAYD_BASE)],
                                        pause_run_loop=True)
            except SAPError as exc:
                raise SAPError(f"open modern FairPlay daemon: {exc}") from exc
            for machine in (self.runtime, self.daemon, self.fairplay):
                machine.host_uuid = bytes(identifier)
            if state:
                self.daemon.adi_files[ADI_STATE_PATH] = bytes(state)
            if bundle.fairplay_kext:
                try:
                    self.kernel = Machine(bundle, extra_images=[
                        ImageSpec("FairPlayIOKit", bundle.fairplay_kext, FAIRPLAY_KEXT_BASE, FAIRPLAY_KERNEL_BASE)])
                except SAPError as exc:
                    raise SAPError(f"open modern FairPlay kernel client: {exc}") from exc
                self.kernel.host_uuid = bytes(identifier)
                self.kernel.mach_rpc_handler = self._handle_fairplay_mach_rpc
                self._initialize_fairplay_kernel()
            self.fairplay.fairplay_handler = self._handle_fairplay_message
            try:
                self.fairplay.invoke(_FAIRPLAYD_ENTRY, 0, 0, 0)
            except SAPError as exc:
                raise SAPError(f"initialize modern FairPlay daemon: {exc}") from exc
            self.daemon.fairplay_handler = self._handle_fairplay_message
            self.runtime.fairplay_handler = self._handle_fairplay_message
            self._initialize_daemon()
        except Exception:
            self.close()
            raise

    def __enter__(self) -> "ModernADI":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # -- set-up -----------------------------------------------------------

    def _initialize_fairplay_kernel(self) -> None:
        kernel = self.kernel
        kernel.begin_call()
        try:
            try:
                kernel.invoke(_KEXT_START)
            except SAPError as exc:
                raise SAPError(f"start modern FairPlay kernel: {exc}") from exc
            try:
                status = kernel.invoke(_KEXT_SETUP)
            except SAPError as exc:
                raise SAPError(f"set up modern FairPlay kernel: {exc}") from exc
            if to_i32(status) != 0:
                raise SAPError(f"set up modern FairPlay kernel: status {to_i32(status)}")
            output = kernel.scratch(None, 8)
            try:
                task = kernel.allocate(0x1000)
            except SAPError as exc:
                raise SAPError(f"allocate modern FairPlay kernel task: {exc}") from exc
            kernel.mem_write(task, b"\x00" * 0x1000)
            try:
                status = kernel.invoke(_KEXT_INIT, 0, output, 0, task)
            except SAPError as exc:
                raise SAPError(f"initialize modern FairPlay kernel session: {exc}") from exc
            if to_i32(status) != 0:
                raise SAPError(f"initialize modern FairPlay kernel session: status {to_i32(status)}")
            context = kernel.read_u64(output)
            if context == 0:
                raise SAPError("modern FairPlay kernel returned no session context")
            self._kernel_context = context
        finally:
            kernel.clear_scratch()

    def _initialize_daemon(self) -> None:
        daemon = self.daemon
        entry_error: Optional[Exception] = None
        try:
            daemon.invoke(_ADID_ENTRY, 0, 0, 0, 0)
        except SAPError as exc:
            entry_error = exc
        if daemon.xpc_event_handler == 0:
            raise SAPError(f"initialize modern ADI daemon: {entry_error}")
        listener = daemon.xpc_event_handler
        connection = daemon.new_xpc_object(None)
        try:
            self._invoke_daemon_block(listener, connection)
        except SAPError as exc:
            raise SAPError(f"accept modern ADI daemon connection: {exc}") from exc
        if daemon.xpc_event_handler == listener:
            raise SAPError("modern ADI daemon did not install a request handler")
        self._daemon_handler = daemon.xpc_event_handler

    def _invoke_daemon_block(self, block: int, argument: int) -> None:
        handler = self.daemon.read_u64(block + 16)
        self.daemon.invoke(handler, block, argument)

    # -- cross-process messages ---------------------------------------------

    def _handle_fairplay_message(self, data: bytes, indirect: bytes, output_size: int) -> Tuple[bytes, bytes, int]:
        if self.kernel is not None:
            kernel = self.kernel
            probe = 0
            try:
                probe = kernel.read_u64(_KEXT_STACK_PROBE)
            except Exception:  # noqa: BLE001 - reported below
                pass
            if probe != _KEXT_STACK_PROBE_VALUE:
                raise SAPError(f"modern FairPlay kernel stack probe is {probe:#x}")
            kernel.begin_call()
            try:
                message = kernel.scratch(indirect, len(indirect))
                try:
                    status = kernel.invoke(_KEXT_ENTRY, message, len(indirect), self._kernel_context)
                except SAPError as exc:
                    raise SAPError(f"run modern FairPlay kernel message: {exc}") from exc
                updated = kernel.mem_read(message, len(indirect))
            finally:
                kernel.clear_scratch()
            return bytes(data[:output_size]), updated, to_i32(status)

        fairplay = self.fairplay
        if fairplay.mach_port_callback == 0:
            raise SAPError("modern FairPlay daemon installed no message callback")
        fairplay.begin_call()
        try:
            message = fairplay.scratch(indirect, len(indirect))
            try:
                fairplay.invoke(fairplay.mach_port_callback, FAKE_HANDLE, message, len(indirect),
                                fairplay.mach_port_info)
            except SAPError as exc:
                raise SAPError(f"run modern FairPlay message callback: {exc}") from exc
            updated = fairplay.mem_read(message, len(indirect))
        finally:
            fairplay.clear_scratch()
        return bytes(data[:output_size]), updated, 0

    def _handle_fairplay_mach_rpc(self, request: bytes, receive_size: int) -> bytes:
        fairplay = self.fairplay
        if fairplay.mach_port_callback == 0:
            raise SAPError("modern FairPlay daemon installed no message callback")
        fairplay.begin_call()
        try:
            message = fairplay.scratch(request, max(len(request), receive_size))
            fairplay.mach_message_reply = b""
            try:
                fairplay.invoke(fairplay.mach_port_callback, FAKE_HANDLE, message, len(request),
                                fairplay.mach_port_info)
            except SAPError as exc:
                raise SAPError(f"run modern FairPlay Mach callback: {exc}") from exc
        finally:
            fairplay.clear_scratch()
        if not fairplay.mach_message_reply:
            raise SAPError("modern FairPlay daemon returned no Mach reply")
        return bytes(fairplay.mach_message_reply)

    def _invoke(self, function: int, *arguments: int) -> int:
        """The client builds its XPC request and fails waiting for the reply;
        the daemon answers the request; the client runs again with that
        reply available."""
        runtime, daemon = self.runtime, self.daemon
        runtime.xpc_data = b""
        runtime.xpc_sync_reply = None
        first_error: Optional[Exception] = None
        try:
            runtime.invoke(function, *arguments)
        except SAPError as exc:
            first_error = exc
        request = bytes(runtime.xpc_data)
        if not request:
            raise SAPError(f"modern ADI client created no daemon request: {first_error}")
        daemon.xpc_reply = b""
        daemon.xpc_replied = False
        request_object = daemon.new_xpc_object(request)
        try:
            self._invoke_daemon_block(self._daemon_handler, request_object)
        except SAPError as exc:
            raise SAPError(f"run modern ADI daemon request: {exc}") from exc
        if not daemon.xpc_replied or not daemon.xpc_reply:
            raise SAPError("modern ADI daemon returned no reply")
        runtime.xpc_sync_reply = bytes(daemon.xpc_reply)
        return runtime.invoke(function, *arguments)

    def exchange_xpc(self, request: bytes) -> bytes:
        """The opaque payload AppleMediaServices sends to com.apple.adid, and
        the daemon's opaque reply."""
        daemon = self.daemon
        if daemon is None or self._daemon_handler == 0:
            raise SAPError("modern ADI daemon is unavailable")
        if not request or len(request) > _MAX_PAYLOAD:
            raise SAPError("modern ADI XPC request is invalid")
        daemon.xpc_reply = b""
        daemon.xpc_replied = False
        request_object = daemon.new_xpc_object(bytes(request))
        try:
            self._invoke_daemon_block(self._daemon_handler, request_object)
        except SAPError as exc:
            raise SAPError(f"run modern ADI XPC request: {exc}") from exc
        if not daemon.xpc_replied or not daemon.xpc_reply:
            raise SAPError("modern ADI XPC service returned no reply")
        return bytes(daemon.xpc_reply)

    # -- ADI operations ---------------------------------------------------

    def _require_runtime(self) -> Machine:
        if self.runtime is None:
            raise SAPError("modern ADI runtime is unavailable")
        return self.runtime

    def start_provisioning(self, dsid: int, spim: bytes) -> Tuple[bytes, int]:
        runtime = self._require_runtime()
        runtime.begin_call()
        try:
            data = runtime.scratch(spim, len(spim))
            pointer_field = runtime.scratch(None, 8)
            length_field = runtime.scratch(None, 4)
            session_field = runtime.scratch(None, 4)
            status = self._invoke(_START_ENTRY, dsid, data, len(spim), pointer_field, length_field, session_field)
            if to_i32(status) != 0:
                raise SAPError(f"start modern ADI provisioning: status {to_i32(status)}")
            output = self._read_output(pointer_field, length_field)
            session = runtime.read_u32(session_field)
            return output, session
        finally:
            runtime.clear_scratch()

    def end_provisioning(self, session: int, setting_info: bytes, transport_key: bytes) -> None:
        runtime = self._require_runtime()
        runtime.begin_call()
        try:
            setting = runtime.scratch(setting_info, len(setting_info))
            key = runtime.scratch(transport_key, len(transport_key))
            status = self._invoke(_END_ENTRY, session, setting, len(setting_info), key, len(transport_key))
            if to_i32(status) != 0:
                raise SAPError(f"finish modern ADI provisioning: status {to_i32(status)}")
        finally:
            runtime.clear_scratch()

    def request_otp(self, dsid: int) -> Tuple[bytes, bytes]:
        """(machine id, one-time password)."""
        runtime = self._require_runtime()
        runtime.begin_call()
        try:
            mid_pointer = runtime.scratch(None, 8)
            mid_length = runtime.scratch(None, 4)
            otp_pointer = runtime.scratch(None, 8)
            otp_length = runtime.scratch(None, 4)
            status = self._invoke(_OTP_ENTRY, dsid, mid_pointer, mid_length, otp_pointer, otp_length)
            if to_i32(status) != 0:
                raise SAPError(f"request modern ADI OTP: status {to_i32(status)}")
            return self._read_output(mid_pointer, mid_length), self._read_output(otp_pointer, otp_length)
        finally:
            runtime.clear_scratch()

    def import_keybag(self, hardware_id: bytes, keybag: bytes) -> None:
        runtime = self._require_runtime()
        hardware = hardware_block(hardware_id)
        runtime.begin_call()
        try:
            hardware_address = runtime.scratch(hardware, len(hardware))
            path_address = runtime.scratch(STOREAGENT_SC_INFO_PATH, len(STOREAGENT_SC_INFO_PATH))
            context_field = runtime.scratch(None, 4)
            try:
                status = runtime.invoke(STOREAGENT_GLOBAL_INIT, 0, hardware_address, path_address, context_field)
            except SAPError as exc:
                raise SAPError(f"initialize FairPlay keybag context: {exc}") from exc
            if to_i32(status) != 0:
                raise SAPError(f"initialize FairPlay keybag context: status {to_i32(status)}")
            global_context = runtime.read_u32(context_field)
            if global_context == 0:
                raise SAPError("initialize FairPlay keybag context: null context")
            keybag_address = runtime.scratch(keybag, len(keybag))
            try:
                status = runtime.invoke(_KEYBAG_ENTRY, global_context, keybag_address, len(keybag))
            except SAPError as exc:
                raise SAPError(f"import FairPlay keybag: {exc}") from exc
            if to_i32(status) != 0:
                raise SAPError(f"import FairPlay keybag: status {to_i32(status)}")
            self._store_global = global_context
        finally:
            runtime.clear_scratch()

    def _read_output(self, pointer_field: int, length_field: int) -> bytes:
        runtime = self.runtime
        pointer = runtime.read_u64(pointer_field)
        length = runtime.read_u32(length_field)
        if pointer == 0 or length == 0 or length > _MAX_PAYLOAD:
            raise SAPError("modern ADI returned invalid output")
        return runtime.mem_read(pointer, length)

    def state(self) -> bytes:
        """The daemon's ``adi.pb``, to be persisted by the caller."""
        if self.runtime is None or self.daemon is None:
            raise SAPError("modern ADI runtime is unavailable")
        data = self.daemon.adi_files.get(ADI_STATE_PATH)
        if data:
            return bytes(data)
        for path, data in self.daemon.adi_files.items():
            if path.rsplit("/", 1)[-1] == "adi.pb" and data:
                return bytes(data)
        raise SAPError("modern ADI state was not created")

    def close(self) -> None:
        """Release the emulators. Like upstream's callers, a failure to close
        the keybag context is not reported: the emulators are discarded."""
        if self.runtime is not None and self._store_global:
            try:
                self.runtime.invoke(STOREAGENT_GLOBAL_CLOSE, self._store_global)
            except SAPError:
                pass
            self._store_global = 0
        for name in ("runtime", "daemon", "fairplay", "kernel"):
            machine = getattr(self, name, None)
            if machine is not None:
                machine.close()
                setattr(self, name, None)
