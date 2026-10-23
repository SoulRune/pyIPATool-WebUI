# Python binding for Unicorn engine. Nguyen Anh Quynh <aquynh@gmail.com>

import glob
import logging
import os
import platform
import shutil
import subprocess
import sys
from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist

log = logging.getLogger(__name__)

# are we building from the repository or from a source distribution?
ROOT_DIR = os.path.dirname(os.path.realpath(__file__))
LIBS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'lib')
HEADERS_DIR = os.path.join(ROOT_DIR, 'unicorn', 'include')
SRC_DIR = os.path.join(ROOT_DIR, 'src')
UC_DIR = SRC_DIR if os.path.exists(SRC_DIR) else os.path.join(ROOT_DIR, '../..')
BUILD_DIR = os.path.join(UC_DIR, 'build_python')

# --- pyIPATool: jailbroken iOS and Android (Termux) support ------------------
# Procursus Python on iOS reports sys.platform "darwin", Termux Python "linux";
# official Python 3.13+ builds report "ios" / "android".
_MACHINE = platform.machine().lower()


def _detect_ios():
    if sys.platform == 'ios':
        return True
    if sys.platform != 'darwin':
        return False
    if _MACHINE.startswith(('iphone', 'ipad', 'ipod')):
        return True
    # Procursus Python reports machine "arm64" like an Apple Silicon Mac, so
    # look for things only iOS has.
    return (os.path.isdir('/var/mobile')
            or os.path.exists('/System/Library/CoreServices/SpringBoard.app'))


IS_IOS = _detect_ios()
IS_ANDROID = (sys.platform == 'android' or 'ANDROID_ROOT' in os.environ
              or 'com.termux' in os.environ.get('PREFIX', ''))
# pyIPATool only emulates arm64 (Apple's macOS 27 frameworks, ipatool 0259df3);
# building that one target instead of all ten is several times faster
# (seconds on a desktop, minutes on a phone).
UNICORN_ARCHS = os.getenv('UNICORN_ARCHS', 'aarch64')
ENTITLEMENTS = os.path.join(ROOT_DIR, 'ios', 'entitlements.plist')


def check_ios_dependencies():
    """Stop early, with a list of missing packages and where to get them,
    instead of failing minutes into the build (ios/check_deps.py)."""
    if not IS_IOS or os.getenv('UNICORN_SKIP_DEP_CHECK'):
        return
    import runpy
    checker = runpy.run_path(os.path.join(ROOT_DIR, 'ios', 'check_deps.py'))
    ok, text = checker['check']()
    if not ok:
        raise SystemExit(text + "\n\n(Set UNICORN_SKIP_DEP_CHECK=1 to build anyway.)")


def ios_runtime_dir():
    """Where the dylib must live on iOS: the sandbox refuses to load dylibs
    from /var/mobile itself. Rootless jailbreaks: /var/jb/var/mobile/.runtime."""
    override = os.getenv('UNICORN_RUNTIME_DIR')
    if override:
        return override
    return '/var/jb/var/mobile/.runtime' if os.path.isdir('/var/jb') else '/var/mobile/.runtime'


def ios_make_program():
    """iOS has no /bin/sh, and GNU make (and every Makefile CMake writes)
    runs recipes through /bin/sh - on rootless jailbreaks it's /var/jb/bin/sh.
    A command-line SHELL= overrides the Makefiles' own and is passed on to
    sub-makes, so CMake gets a tiny wrapper that adds it (also used by its
    compiler checks)."""
    shell = os.getenv('UNICORN_SHELL')
    if not shell:
        for candidate in ('/var/jb/bin/sh', '/var/jb/usr/bin/sh', '/var/jb/bin/dash',
                          '/var/jb/usr/bin/dash', '/bin/sh', shutil.which('sh'), shutil.which('dash')):
            if candidate and os.path.exists(candidate):
                shell = candidate
                break
    make = shutil.which('make') or shutil.which('gmake')
    if not shell or not make:
        return None
    if shell == '/bin/sh':
        return None  # rootful jailbreak with a real /bin/sh: nothing to fix
    os.makedirs(BUILD_DIR, exist_ok=True)
    wrapper = os.path.join(BUILD_DIR, 'make-ios.sh')
    with open(wrapper, 'w') as f:
        f.write('#!%s\nexec "%s" SHELL="%s" "$@"\n' % (shell, make, shell))
    os.chmod(wrapper, 0o755)
    return wrapper
# -----------------------------------------------------------------------------

if sys.platform in ('darwin', 'ios'):
    LIBRARY_FILE = "libunicorn.2.dylib"
    STATIC_LIBRARY_FILE = "libunicorn.a"
elif sys.platform in ('win32', 'cygwin'):
    LIBRARY_FILE = "unicorn.dll"
    STATIC_LIBRARY_FILE = "unicorn.lib"
else:
    LIBRARY_FILE = "libunicorn.so.2"
    STATIC_LIBRARY_FILE = "libunicorn.a"


def clean_bins():
    shutil.rmtree(LIBS_DIR, ignore_errors=True)
    shutil.rmtree(HEADERS_DIR, ignore_errors=True)


def copy_sources():
    """
    Copy the C sources into the source directory.
    This rearranges the source files under the python distribution
    directory.
    """
    shutil.rmtree(SRC_DIR, ignore_errors=True)
    os.mkdir(SRC_DIR)

    shutil.copytree(os.path.join(ROOT_DIR, '../../qemu'), os.path.join(SRC_DIR, 'qemu/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../msvc'), os.path.join(SRC_DIR, 'msvc/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../include'), os.path.join(SRC_DIR, 'include/'))
    # make -> configure -> clean -> clean tests fails unless tests is present
    shutil.copytree(os.path.join(ROOT_DIR, '../../tests'), os.path.join(SRC_DIR, 'tests/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../samples'), os.path.join(SRC_DIR, 'samples/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../glib_compat'), os.path.join(SRC_DIR, 'glib_compat/'))
    shutil.copytree(os.path.join(ROOT_DIR, '../../cmake'), os.path.join(SRC_DIR, 'cmake/'))

    try:
        # remove site-specific configuration file, might not exist
        os.remove(os.path.join(SRC_DIR, 'qemu/config-host.mak'))
    except OSError:
        pass

    src = []
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.[ch]")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.mk")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../LICENSE*")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../README.md")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../*.TXT")))
    src.extend(glob.glob(os.path.join(ROOT_DIR, "../../CMakeLists.txt")))

    for filename in src:
        outpath = os.path.join(SRC_DIR, os.path.basename(filename))
        log.info("%s -> %s" % (filename, outpath))
        shutil.copy(filename, outpath)


def build_libraries():
    """
    Prepare the unicorn directory for a binary distribution or installation.
    Builds shared libraries and copies header files.

    Will use a src/ dir if one exists in the current directory, otherwise assumes it's in the repo
    """
    check_ios_dependencies()  # pyIPATool
    clean_bins()
    os.mkdir(HEADERS_DIR)
    os.mkdir(LIBS_DIR)

    # copy public headers
    shutil.copytree(os.path.join(UC_DIR, 'include', 'unicorn'), os.path.join(HEADERS_DIR, 'unicorn'))

    # check if a prebuilt library exists and if so, use it instead of building
    if os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE)):
        shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', LIBRARY_FILE), LIBS_DIR)
        if STATIC_LIBRARY_FILE is not None and os.path.exists(os.path.join(ROOT_DIR, 'prebuilt', STATIC_LIBRARY_FILE)):
            shutil.copy(os.path.join(ROOT_DIR, 'prebuilt', STATIC_LIBRARY_FILE), LIBS_DIR)
        return

    # otherwise, build
    if not os.path.exists(BUILD_DIR):
        os.mkdir(BUILD_DIR)

    has_msbuild = shutil.which('msbuild') is not None
    conf = 'Debug' if int(os.getenv('DEBUG', 0)) else 'Release'
    cmake_args = ['cmake', '-B', BUILD_DIR, "-DCMAKE_BUILD_TYPE=" + conf, "-DUNICORN_BUILD_TESTS=off",
                  "-DUNICORN_ARCH=" + UNICORN_ARCHS]  # pyIPATool: arm64 only by default
    if IS_IOS:
        # pyIPATool (iOS): build for the phone itself (arm64), with clang from
        # the jailbreak toolchain; SDKROOT points at an iPhoneOS SDK if clang
        # can't find the system headers on its own.
        cmake_args += ["-DCMAKE_OSX_ARCHITECTURES=" + os.getenv('UNICORN_IOS_ARCH', 'arm64')]
        cmake_args += ["-DCMAKE_C_COMPILER=" + (os.getenv('CC') or shutil.which('clang') or 'clang')]
        sdk = os.getenv('SDKROOT')
        if not sdk:
            # build-essential (Procursus) ships the SDK here
            found = sorted(glob.glob('/var/jb/usr/share/SDKs/iPhoneOS*.sdk') + glob.glob('/usr/share/SDKs/iPhoneOS*.sdk'))
            sdk = found[-1] if found else None
        if sdk:
            cmake_args += ["-DCMAKE_OSX_SYSROOT=" + sdk]
        make_wrapper = ios_make_program()
        if make_wrapper:
            cmake_args += ["-G", "Unix Makefiles", "-DCMAKE_MAKE_PROGRAM=" + make_wrapper]
        # A configure that failed before (e.g. on the /bin/sh problem) leaves a
        # cache that would keep the broken settings.
        stale = os.path.join(BUILD_DIR, 'CMakeCache.txt')
        if os.path.exists(stale) and (not make_wrapper or make_wrapper not in open(stale, errors='replace').read()):
            os.remove(stale)
            shutil.rmtree(os.path.join(BUILD_DIR, 'CMakeFiles'), ignore_errors=True)
    if os.getenv("UNICORN_TRACER"):
        cmake_args += ["-DUNICORN_TRACER=on"]
    if conf == 'Debug':
        cmake_args += ["-DUNICORN_LOGGING=on"]

    if has_msbuild and sys.platform == 'win32':
        generators = os.getenv('GENERATORS') or 'Visual Studio 16 2019'
        plat = 'Win32' if platform.architecture()[0] == '32bit' else 'x64'
        cmake_args += ['-G', generators, "-A", plat]
        subprocess.check_call(cmake_args, cwd=UC_DIR)
        subprocess.check_call(['msbuild', 'unicorn.sln', '-m', '-p:Platform=' + plat, '-p:Configuration=' + conf],
                              cwd=BUILD_DIR)

        obj_dir = os.path.join(BUILD_DIR, conf)
        shutil.copy(os.path.join(obj_dir, LIBRARY_FILE), LIBS_DIR)
        shutil.copy(os.path.join(obj_dir, STATIC_LIBRARY_FILE), LIBS_DIR)
    else:
        cmake_args += ['-S', UC_DIR]
        subprocess.check_call(cmake_args, cwd=UC_DIR)
        threads = os.getenv("THREADS", "4")
        subprocess.check_call(["cmake", "--build", ".", "-j" + threads], cwd=BUILD_DIR)

        shutil.copy(os.path.join(BUILD_DIR, LIBRARY_FILE), LIBS_DIR)
        shutil.copy(os.path.join(BUILD_DIR, STATIC_LIBRARY_FILE), LIBS_DIR)

    finish_mobile_install(os.path.join(LIBS_DIR, LIBRARY_FILE))


# --- pyIPATool: post-build steps for iOS / Android ---------------------------

_SMOKE_TEST = r"""
import ctypes, sys
lib = ctypes.CDLL(sys.argv[1])
u64, vp = ctypes.c_uint64, ctypes.c_void_p
lib.uc_open.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(vp)]
lib.uc_mem_map.argtypes = [vp, u64, ctypes.c_size_t, ctypes.c_uint32]
lib.uc_mem_write.argtypes = [vp, u64, ctypes.c_char_p, ctypes.c_size_t]
lib.uc_emu_start.argtypes = [vp, u64, u64, u64, ctypes.c_size_t]
lib.uc_reg_read.argtypes = [vp, ctypes.c_int, vp]
lib.uc_close.argtypes = [vp]
uc = vp()
assert lib.uc_open(2, 0, ctypes.byref(uc)) == 0, "uc_open failed"          # UC_ARCH_ARM64, UC_MODE_ARM
assert lib.uc_mem_map(uc, 0x1000, 0x1000, 7) == 0, "uc_mem_map failed"     # UC_PROT_ALL
code = b"\x00\x04\x00\x91" * 3                                             # add x0, x0, #1 x3
assert lib.uc_mem_write(uc, 0x1000, code, len(code)) == 0
err = lib.uc_emu_start(uc, 0x1000, 0x1000 + len(code), 0, 0)
assert err == 0, "uc_emu_start failed with error %d" % err
x0 = ctypes.c_uint64()
lib.uc_reg_read(uc, 199, ctypes.byref(x0))                                  # UC_ARM64_REG_X0
assert x0.value == 3, x0.value
lib.uc_close(uc)
print("ok")
"""


def jit_smoke_test(library):
    """Run a few arm64 instructions through the JIT in a separate process: if
    the OS refuses executable memory the process may be killed outright."""
    try:
        result = subprocess.run([sys.executable, '-c', _SMOKE_TEST, library],
                                capture_output=True, text=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)
    if result.returncode == 0 and 'ok' in result.stdout:
        return True, ''
    return False, (result.stderr.strip().splitlines() or ['exit status %d' % result.returncode])[-1]


def finish_mobile_install(library):
    if not (IS_IOS or IS_ANDROID):
        return
    if IS_IOS:
        runtime = ios_runtime_dir()
        os.makedirs(runtime, exist_ok=True)
        target = os.path.join(runtime, LIBRARY_FILE)
        shutil.copy(library, target)
        ldid = shutil.which('ldid')
        if ldid:
            for path in (library, target):
                subprocess.call([ldid, '-S', path])
        else:
            log.warning("ldid not found - the dylib is unsigned and iOS may refuse to load it (apt install ldid)")
        print("unicorn: installed %s (the binding loads it from there)" % target)
        library = target

    ok, why = jit_smoke_test(library)
    if ok:
        print("unicorn: JIT works on this device")
        return
    print("unicorn: WARNING - the JIT test failed (%s)." % why)
    if IS_IOS:
        python = os.path.realpath(sys.executable)
        print("  iOS lets a process execute generated code only with the dynamic-codesigning")
        print("  entitlement. Sign this Python once (merging its existing entitlements), e.g.:")
        print("    sudo ldid -M -S%s %s" % (ENTITLEMENTS, python))
        print("  then reinstall or simply run pyIPATool - nothing else needs to change.")
# -----------------------------------------------------------------------------


class CustomSDist(sdist):
    def run(self):
        clean_bins()
        copy_sources()
        return super().run()


class CustomBuild(build_py):
    def run(self):
        if 'LIBUNICORN_PATH' in os.environ:
            log.info("Skipping building C extensions since LIBUNICORN_PATH is set")
        else:
            log.info("Building C extensions")
            build_libraries()
        return super().run()


setup(
    cmdclass={'build_py': CustomBuild, 'sdist': CustomSDist},
    has_ext_modules=lambda: True,  # It's not a Pure Python wheel,
    options={"bdist_wheel": {"py_limited_api": "cp37"}},  # to have ABI3 tagged wheel
)
