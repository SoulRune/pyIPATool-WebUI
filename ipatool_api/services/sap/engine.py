"""Creating and running Unicorn engines safely next to each other.

Port of ipatool ``internal/sap/unicorn`` clock.go and engine_config.go
(e4b0aae, 2029022; MIT).

* Unicorn 2.1's machine initialization calls ``init_get_clock`` for every
  engine, which on Unix briefly switches a process-wide flag from monotonic
  to wall time. An engine that is executing with a timeout at that moment
  can see its timeout expire at once. Engines are therefore initialized only
  while none is executing; initialized engines still run concurrently,
  including nested calls from guest callbacks.
* The JIT translation buffer is bounded on every host (Unicorn's default
  reserves about 1 GB per engine, too much for memory-limited containers);
  Unicorn flushes translated blocks when it fills.
"""
from __future__ import annotations

import threading
from contextlib import contextmanager

from unicorn import UC_ARCH_ARM64, UC_MODE_ARM, UC_QUERY_PAGE_SIZE, Uc
from unicorn import arm64_const as _arm

TCG_BUFFER_SIZE = 4 << 20

_condition = threading.Condition()
_active = 0


def new_arm64_engine() -> Uc:
    """An initialized arm64 engine with the most capable CPU model."""
    with _condition:
        while _active:
            _condition.wait()
        uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        try:
            uc.ctl_set_tcg_buffer_size(TCG_BUFFER_SIZE)
        except Exception:  # noqa: BLE001 - older bindings: keep Unicorn's default
            pass
        uc.ctl_set_cpu_model(_arm.UC_CPU_ARM64_MAX)
        # Engine set-up is lazy: force it here, so later memory or register
        # operations cannot reset the shared timeout clock.
        uc.query(UC_QUERY_PAGE_SIZE)
        return uc


@contextmanager
def emulation():
    """Held around ``emu_start``: new engines wait until no engine runs."""
    global _active
    with _condition:
        _active += 1
    try:
        yield
    finally:
        with _condition:
            _active -= 1
            if _active == 0:
                _condition.notify_all()
