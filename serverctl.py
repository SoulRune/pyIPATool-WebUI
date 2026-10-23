#!/usr/bin/env python3
"""Start pyIPATool WebUI in the background and stop it (POSIX and Windows).

    python serverctl.py                 # app.py --daemon with a PID and log file
    python serverctl.py --kill-server   # stop it

Other options go to app.py unchanged. Windows has no fork, so there the
server is started as a detached process instead.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
APP_PY = SCRIPT_DIR / "app.py"
DEFAULT_PID_FILE = SCRIPT_DIR / "ipatool-webui.pid"
DEFAULT_LOG_FILE = SCRIPT_DIR / "ipatool-webui.log"

IS_WINDOWS = os.name == "nt"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Start or stop pyIPATool WebUI as a background server. "
        "Unrecognised options are passed through to app.py.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--pid-file",
        default=str(DEFAULT_PID_FILE),
        help=f"PID file location (default: {DEFAULT_PID_FILE})",
    )
    parser.add_argument(
        "--log-file",
        default=str(DEFAULT_LOG_FILE),
        help=f"Log file location (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--kill-server",
        action="store_true",
        help="Stop a running background server (reads the PID from --pid-file) and exit.",
    )
    parser.add_argument("--status", action="store_true", help="Report whether the server is running and exit.")
    args, passthrough = parser.parse_known_args()
    if "--debug" in passthrough:
        # Debug mode means Werkzeug's interactive debugger - never something
        # to leave running unattended in the background.
        parser.error("--debug isn't supported for background runs; run app.py directly")
    args.passthrough = passthrough
    return args


def read_pid(pid_file: Path) -> int | None:
    if not pid_file.exists():
        return None
    try:
        return int(pid_file.read_text().strip())
    except (ValueError, OSError):
        return None


def _is_running_windows(pid: int) -> bool:
    # Ask the kernel directly instead of grepping `tasklist` output - the old
    # `str(pid) in stdout` check matched e.g. PID 144 inside "14144".
    import ctypes
    from ctypes import wintypes

    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    STILL_ACTIVE = 259
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        # ERROR_ACCESS_DENIED means it exists but belongs to someone else.
        return ctypes.get_last_error() == 5
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def is_running(pid: int) -> bool:
    if IS_WINDOWS:
        return _is_running_windows(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by another user
    except OSError:
        return False
    return True


def kill_server(pid_file: Path) -> None:
    pid = read_pid(pid_file)
    if pid is None:
        print(f"No (readable) PID file at {pid_file} - is the server running?")
        sys.exit(1)

    if not is_running(pid):
        print(f"PID {pid} (from {pid_file}) isn't running - stale PID file, cleaning up.")
        pid_file.unlink(missing_ok=True)
        return

    print(f"Stopping server (PID {pid})...")
    if IS_WINDOWS:
        subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)
    else:
        import signal

        os.kill(pid, signal.SIGTERM)
        for _ in range(20):  # give it up to ~5s to shut down cleanly
            if not is_running(pid):
                break
            time.sleep(0.25)
        else:
            print("Still running after SIGTERM, sending SIGKILL...")
            os.kill(pid, signal.SIGKILL)

    pid_file.unlink(missing_ok=True)
    print("Stopped.")


def build_common_flags(args: argparse.Namespace) -> list[str]:
    return list(args.passthrough)


def stdout_log_path(log_file: Path) -> Path:
    return log_file.with_name(log_file.stem + ".stdout" + (log_file.suffix or ".log"))


def start_posix(args: argparse.Namespace, pid_file: Path, log_file: Path) -> None:
    # app.py --daemon forks, logs and writes the PID file itself.
    cmd = [
        sys.executable,
        str(APP_PY),
        "--daemon",
        "--pid-file",
        str(pid_file),
        "--log-file",
        str(log_file),
        *build_common_flags(args),
    ]
    subprocess.run(cmd, check=True)

    # The PID file appears a moment after the command returns.
    pid = None
    for _ in range(30):
        pid = read_pid(pid_file)
        if pid:
            break
        time.sleep(0.1)

    if pid:
        print(f"Started (PID {pid}). Logs: {log_file}")
    else:
        print(f"Start command finished, but {pid_file} didn't appear within 3s - check {log_file}.")


def start_windows(args: argparse.Namespace, pid_file: Path, log_file: Path) -> None:
    # Windows has no fork: start a detached process; raw stdout/stderr go to a
    # separate file (Windows can't rotate a file held open elsewhere).
    cmd = [sys.executable, str(APP_PY), "--log-file", str(log_file), *build_common_flags(args)]

    creationflags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
    log_handle = open(stdout_log_path(log_file), "a")
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=log_handle,
            stderr=log_handle,
            stdin=subprocess.DEVNULL,
            creationflags=creationflags,
            close_fds=True,
        )
    finally:
        log_handle.close()

    pid_file.write_text(str(proc.pid))
    time.sleep(1.5)
    if proc.poll() is not None:
        pid_file.unlink(missing_ok=True)
        print(f"Server exited immediately (code {proc.returncode}) - see {stdout_log_path(log_file)}")
        sys.exit(1)
    print(f"Started (PID {proc.pid}). Logs: {log_file}")


def ask_master_password(args: argparse.Namespace) -> None:
    """Windows: the detached server has no console to ask for the master
    password, so ask here and hand it over in its environment."""
    if os.environ.get("IPATOOL_MASTER_PASSWORD") or "--master-password-file" in args.passthrough:
        return
    sys.path.insert(0, str(SCRIPT_DIR))
    from ipatool_api.services import vault

    if vault.status() != "on":
        return
    import getpass

    for _ in range(3):
        password = getpass.getpass("Master password: ")
        try:
            vault.unlock(password)
        except vault.VaultError as exc:
            print(exc)
            continue
        os.environ["IPATOOL_MASTER_PASSWORD"] = password
        return
    sys.exit("wrong master password")


def start_server(args: argparse.Namespace) -> None:
    pid_file = Path(args.pid_file)
    log_file = Path(args.log_file)

    existing_pid = read_pid(pid_file)
    if existing_pid and is_running(existing_pid):
        print(
            f"Server already running (PID {existing_pid}, from {pid_file}). "
            f"Use --kill-server first if you want to restart it."
        )
        sys.exit(1)

    if IS_WINDOWS:
        ask_master_password(args)
        start_windows(args, pid_file, log_file)
    else:
        start_posix(args, pid_file, log_file)


def main() -> None:
    args = parse_args()
    if args.kill_server:
        kill_server(Path(args.pid_file))
        return
    if args.status:
        pid = read_pid(Path(args.pid_file))
        if pid and is_running(pid):
            print(f"Running (PID {pid}).")
        else:
            print("Not running.")
            sys.exit(1)
        return
    start_server(args)


if __name__ == "__main__":
    main()
