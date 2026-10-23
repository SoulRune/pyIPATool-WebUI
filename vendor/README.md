# vendor/

## unicorn/ - Unicorn Engine 2.1.4, modified for jailbroken iOS and Android

Source of the PyPI sdist `unicorn-2.1.4.tar.gz`
(sha256 `00567a70e323f749b419cd86bee4f9115beab7ebba32194581c090cbb7c59cff`),
with the changes below. Each change is marked `pyIPATool` in the code; the
git history has the unmodified import as its own commit, so `git diff` against
it shows exactly what was changed. Licenses: GPLv2 (C core), BSD (Python
binding) - see `src/COPYING` (GPLv2), `src/COPYING.LGPL2`, `src/COPYING_GLIB`
and `src/CREDITS.TXT` (taken from the unicorn-engine/unicorn 2.1.4 tag: the
PyPI sdist leaves them out). This folder is not covered by the AGPL of the
rest of the project.

Used by `requirements-ios.txt` and `requirements-android.txt`
(`pip install ./vendor/unicorn`). Windows, macOS and Linux use the regular
prebuilt wheels from PyPI instead.

| File | Change |
|---|---|
| `src/qemu/include/qemu/osdep.h` | iOS: request `MAP_JIT` memory for generated code. iOS only grants executable memory to `MAP_JIT` mappings of a process with the `dynamic-codesigning` entitlement; upstream enables `MAP_JIT` only together with macOS's `pthread_jit_write_protect_np()`, which the iOS SDK marks unavailable. |
| `src/CMakeLists.txt` | Use `/usr/bin/cc` on Apple only if it exists (rootless jailbreaks keep clang under `/var/jb/usr/bin`). Respect an explicitly requested `CMAKE_OSX_ARCHITECTURES` instead of forcing the macOS universal x86_64+arm64 build. |
| `setup.py` | Detects iOS (also Procursus Python, which says `darwin`) and Android (also Termux). Builds only the arm64 target (`UNICORN_ARCHS`, default `aarch64` - all pyIPATool needs since it emulates Apple's macOS 27 frameworks; several times faster). iOS: arm64 build with clang, honours `SDKROOT`, installs the dylib into `/var/jb/var/mobile/.runtime` (rootful: `/var/mobile/.runtime`; override `UNICORN_RUNTIME_DIR`) and ad-hoc signs it with `ldid`. Both: ends with a JIT smoke test in a separate process and, on iOS, prints the one-time `ldid` command if Python lacks the JIT entitlement. |
| `unicorn/unicorn_py3/unicorn.py` | The binding looks for the library in the iOS runtime directory first (the sandbox won't load dylibs from `/var/mobile`, where site-packages is), so no `LIBUNICORN_PATH` or launcher is needed. Library names for the `ios` and `android` platforms of official Python 3.13+. |
| `pyproject.toml` | Fixed version `2.1.4` instead of setuptools-scm: upstream's `root = '../../'` would read pyIPATool's own git history from inside this folder. |
| `ios/check_deps.py` | New: checks (via dpkg) the packages the iOS build needs - Procursus: clang, clangd, cmake, cmake-data, make, build-essential, libffi8, libffi-dev, dash, ldid, odcctools; CyPwn: python3.12 - and lists missing ones by repository with an `apt install` line. Run by `setup.py` before building on iOS (`UNICORN_SKIP_DEP_CHECK=1` skips it); also runnable by hand. |
| `ios/entitlements.plist` | New: `dynamic-codesigning` + `skip-library-validation` for Python, used by the printed `ldid` command. |
