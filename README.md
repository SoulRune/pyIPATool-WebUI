# IPATool WebUI Python

A web interface for the App Store: search apps (iPhone, iPad, Apple TV,
Apple Watch, Vision), list every version of an app with its details, get free
licenses and download IPA files, including older versions, Apple Arcade games
and tvOS builds, and install them over the air. Apple ID sign-in with
two-factor authentication, several saved accounts, a REST API. Python (Flask)
backend, plain JavaScript frontend, plus a separate UI for old browsers
(iOS 6).

<img width="2018" height="4448" alt="image" src="https://github.com/user-attachments/assets/ec40a529-51bb-4032-9ec5-6bce70532a71" />

<img width="1931" height="1145" alt="image" src="https://github.com/user-attachments/assets/362fdf7c-57df-435e-a386-78929d833e27" />

----
#### ATTENTION! For now, this repository contains a pre-added, semi-private repository with metadata for several Apple Arcade games (private version catalog testing).
#### Keeping the "token" and "repo" fields filled is allowed for personal use only. Sharing or hosting is strictly prohibited.
#### If this tool is used for sharing or hosting, you must clear the repo and token values in the BUILTIN_CATALOG constant located in the /ipatool_api/services/appstore.py file.
----
##### NOTE: The modified Unicorn emulator in the /vendor/ folder is currently not working. Development is still in progress to bring Android and iOS support to this tool.
##### Please do not use the tool on these platforms for now, and do not attempt to install "requirements-ios.txt" or "requirements-android.txt".
----

## Quick start

Python 3.9 or newer:

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt        # Windows: venv\Scripts\pip ...
venv/bin/python app.py
```

Open http://127.0.0.1:5002. Ready-made start scripts and server setups
(home network with HTTPS, nginx, Caddy, under a path of an existing site) are
in [DEPLOY](DEPLOY/README.md).

## Platforms

Everything is pure Python except **Unicorn**, the CPU emulator that runs
Apple's signing code. Without it the server runs, but signing in is
unavailable (the page says so).

| Platform | Server | Sign-in |
|---|---|---|
| Windows x64/x86, macOS, Linux x86_64/aarch64/i686 (glibc or musl) | yes | yes |
| Linux 32-bit ARM (old Raspberry Pi OS) | yes | Unicorn built from source (`apt install cmake build-essential`), untested |
| Android (Termux) | yes | `requirements-android.txt`, untested on a device |
| iOS 14+, jailbroken (Procursus Python) | yes | `requirements-ios.txt`, untested on a device |

To start without waiting for a Unicorn build: `pip install -r
requirements-core.txt` (everything except Unicorn).

### Jailbroken iOS and Android

```sh
# iOS 14+, jailbroken
python3 vendor/unicorn/ios/check_deps.py     # lists missing packages
pip install -r requirements-ios.txt
# Android (Termux)
pkg install python clang cmake make
pip install -r requirements-android.txt
```

Both build Unicorn from `vendor/unicorn` (2.1.4, arm64 only; changes in
`vendor/README.md`). iOS packages: from Procursus `clang` `clangd` `cmake`
`cmake-data` `make` `build-essential` `libffi8` `libffi-dev` `dash` `ldid`
`odcctools`, from CyPwn `python3.12`. On iOS the library goes to
`/var/jb/var/mobile/.runtime` (rootful: `/var/mobile/.runtime`) and is signed
with `ldid`; if the JIT test at the end fails, the build prints the `ldid`
command that gives Python the `dynamic-codesigning` entitlement.
`cryptography` isn't used there (it needs Rust); the built-in cipher is used
instead.

The devices you install apps on only need a browser.

## How it works

**Sign-in.** Since August 2026 Apple requires an `X-Apple-ActionSignature`
on sign-in, computed by Apple's own code. As in
[ipatool](https://github.com/majd/ipatool), the server reads four macOS
framework files from Apple's restore image on Apple's CDN at the first
sign-in (range requests, about 120-350 MB, once; checked against pinned
digests, cached in `~/.ipatool/sap/`) and runs them in Unicorn. Nothing
Apple-owned is shipped with this project.

**Downloads.** Apple's main download endpoint (`ent/download`) needs a
*kbsync* blob, computed by the same emulator (a few seconds, once per account
and device, then reused). If it can't serve a version, the older endpoints
are tried (volumeStore, redownload, updateProduct). The IPA gets
`iTunesMetadata.plist` and the SINF appended and the ZIP layout iOS needs for
over-the-air installs.

**Apple Arcade.** Arcade games go through the same flow. Their current
version comes from the App Store catalog API. Apple often refuses the version
list for the current version, so the server asks again pinned to older known
versions (catalog and community ids, newest first). apps.apple.com
rate-limits busy addresses; the server then pauses it for 3 minutes and uses
the last version id it saw (`~/.ipatool/known_versions.json`). The sign-in
must use the default User-Agent (the token is tied to it).

**Minimum iOS.** Each version shows the minimum OS from its own
`Info.plist`, read from the IPA on Apple's CDN with a few range requests
(cached for a week).

## Using it

- **Sign in** with Apple ID and password, then the 6-digit code from your
  device. No code appeared? Then the password is most likely wrong: Apple
  answers both the same way.
- **Several Apple IDs**: the account button lists saved sign-ins; switch
  without a password or code, "+ Add account" for another one (up to 6).
  Sign Out signs out the active one only.
- **Search** with a result limit, platform and **region** (another
  country's store, e.g. to find an app removed from yours; downloading is
  still up to Apple for your account). **Direct Lookup** takes an app id and
  optionally a version id.
- **Platforms**: iPhone + iPad, iPhone, iPad, Apple TV (the tvOS build is
  resolved through Apple's MDM lookup and the package is checked), Apple
  Watch (a search filter: watch apps ship inside iPhone packages).
- **Download IPA** runs as a background job with progress, then the browser
  saves the file. **Save on server** (local mode, or `--allow-server-save`)
  keeps it in `~/Downloads/IPATool/` instead, for browsers that can't save
  downloads (iOS 6).
- **Install on device** (OTA): open the page on the iPhone or iPad. Needs
  HTTPS with a certificate the device trusts (iOS 6 also works over HTTP).
  The banner warns when the device's iOS is too old for the version.
  Whether iOS installs an App Store package this way depends on the iOS
  version and the Apple ID on the device.
- **Licenses**: "license required" offers to get the app (free apps and
  Arcade games with a subscription).
- Other ways to install a downloaded IPA: iMazing, 3uTools, Sideloadly with
  "Normal Install", TrollStore or Filza. Don't re-sign it: it is already
  signed by Apple.

### Version catalogs

The versions list can be completed from catalogs: the project's own
(`BUILTIN_CATALOG` in `appstore.py`), one given with `--catalog-repo
owner/name` or `catalog.json` (a GitHub repository with `apps/<appId>.json`,
format in `ipatool_api/services/catalog.py`; token for a private one from
`--catalog-token-file`, `IPATOOL_CATALOG_TOKEN` or `catalog.json`) and the
community databases Timbrd and bilin. Catalog entries carry a status (`ok`,
`lost`, `unknown`) and which other catalogs list the same id.

- **Private catalog first**: show the catalog's versions without asking
  Apple; "Ask Apple" loads Apple's list.
- **Merge version catalogs**: Apple's ids plus ids only the catalogs know;
  Apple is asked about every one (slower).
- **Clear cache**: forget cached version data on the server (not sign-ins).

The catalog is filled by a separate collector tool.

## Running it

### Local mode and per-browser sessions

| | Local mode | Browser mode |
|---|---|---|
| Chosen when | `--host` is loopback (default `127.0.0.1`) | any other `--host`, or `--behind-proxy` |
| Who signs in | one shared account | every browser with its own Apple ID |
| Where the session lives | `~/.ipatool/keychain.json`, `cookies.lwp` | an encrypted HttpOnly cookie in that browser |
| Save on server | yes | only with `--allow-server-save` |

Override with `--session-mode local|browser`. Browser sessions are encrypted
with `~/.ipatool/session_secret.key` (AES-256-GCM with the `cryptography`
package, otherwise a standard-library cipher), expire after 30 days
(`--session-days`); deleting the key signs everyone out.

```bash
python app.py --host 0.0.0.0                                  # home network
python app.py --host 0.0.0.0 --cert cert.pem --key key.pem \
    --ca-file rootCA.pem                                      # same over HTTPS (OTA)
```

With `--ca-file` the page links the root certificate at `/ca.crt` for the
devices. A device that doesn't trust the certificate shows up in the log as
`TLS handshake failed: ...UNKNOWN_CA`.

### On the internet

The app listens on `127.0.0.1`, a reverse proxy does HTTPS; see
[DEPLOY](DEPLOY/README.md) for complete setups.

- `--behind-proxy`: trust the proxy's `X-Forwarded-*` headers (one hop).
  Plain-HTTP requests are then redirected or refused and answers carry HSTS
  (`--allow-http` turns that off). Also works under a path
  (`X-Forwarded-Prefix`).
- `--trusted-host NAME`: only this Host name is accepted.
- `--access-password-file FILE` (or `IPATOOL_ACCESS_PASSWORD`): a private
  server; every browser enters the password once (30-day cookie), 8 wrong
  tries per 15 min per address. OTA links and `/source` stay open.
- Always on: 10 Apple sign-ins per 10 min per address, per-browser and total
  download limits, a download is refused if it won't fit on the disk
  (`--min-free-disk`, default 1024 MB kept free).
- `--emulators N` (default 2) and `--max-downloads N`: on 1 GB of RAM use 1
  and 1. An emulation takes ~400 MB for a few seconds; the Apple files stay
  loaded (~140 MB).

### Proxy for traffic to Apple

```bash
python app.py --proxy 203.0.113.5:3128                          # HTTP
python app.py --proxy 127.0.0.1:1080 --proxy-type socks5         # SOCKS5, DNS through the proxy
python app.py --proxy ... --proxy-user alice                     # password asked or IPATOOL_PROXY_PASSWORD
```

Everything sent to Apple goes through it. The proxy is checked at startup
(the log shows the exit country or the error).

### Master password

The stored secrets in `~/.ipatool` (sign-ins, cookies, saved accounts, session
key, the collector's token) can be encrypted with a master password: scrypt
(N=2^17, r=8) or PBKDF2-SHA512 where Python lacks scrypt, standard library
only. The first interactive start offers it.

- `--encrypt-storage`, `--decrypt-storage`, `--change-master-password`
  (all ask for the password).
- `--reset-encrypted-storage`: forgotten password; deletes the encrypted
  files (sign in again).
- Without a terminal: `--master-password-file FILE` or
  `IPATOOL_MASTER_PASSWORD`. `serverctl.py` asks on Windows and hands it over.
- Shared with the collector (same vault, same password).

### In the background

```bash
python serverctl.py [app.py options]    # start detached (POSIX and Windows)
python serverctl.py --status
python serverctl.py --kill-server
```

`app.py --daemon --pid-file F --log-file L` detaches on POSIX. On macOS and
jailbroken iOS, `scripts/com.ipatool.webui.plist` is a launchd template
(restart on crash, start on boot). Logs rotate (5 x 2 MB).

### Old browsers

`--legacy` serves an ES5 interface (`legacy.js`, `legacy.css`) for old WebKit,
iOS 6 Safari in particular: same features and look, no modern JavaScript or
CSS.

### Diagnostics

- `python tools/diagnose_login.py [--email you@example.com]`: walks the
  sign-in step by step (network, TLS, bag, signature, Apple's answer); the
  report masks all secrets.
- `--trace FILE` (or `IPATOOL_TRACE`): every request to Apple as JSON lines,
  secrets replaced by their length.
- `--log-level DEBUG`: Apple's full answers in the log.

## Security

- Passwords and tokens are never sent to the browser. On Windows the stored
  secrets are encrypted with DPAPI, elsewhere they are owner-only files.
- Logs never contain passwords, tokens, cookies, DSIDs, e-mail addresses or
  OTA link tokens.
- CSRF protection (JSON-only requests and an Origin check), a strict
  Content-Security-Policy, Host checks against DNS rebinding, HTML escaping
  of everything that comes from the network.
- Behind a proxy: HTTPS only, the access password and rate limits above.
- The Apple ID password passes through the server: use a server you trust.

TLS to Apple: `IPATOOL_CA_BUNDLE=/path/ca.pem` or `~/.ipatool/ca-bundle.pem`
for a custom CA; `IPATOOL_SSL_NO_VERIFY=1` turns verification off (not
recommended).

## Storage (`~/.ipatool/`)

| | |
|---|---|
| `keychain.json`, `cookies.lwp`, `device_guid.txt` | local-mode sign-in |
| `accounts/` | saved sign-ins (local mode) |
| `session_secret.key` | key of the browser-session cookies |
| `vault.json` | master password settings (wrapped key, salt) |
| `sap/` | Apple's files for signing |
| `known_versions.json` | last version id seen per app |
| `temp_downloads/` | downloads waiting for the browser (cleared at start) |

## API

- `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/account`
- `GET /api/accounts`, `POST /api/accounts/add|switch|forget`
- `GET /api/search`, `GET /api/versions`, `GET /api/version-metadata`,
  `GET /api/versions/community`, `GET /api/versions/catalog`
- `POST /api/purchase`
- `POST /api/download-jobs`, `GET /api/download-jobs/<id>`,
  `GET /api/download-jobs/<id>/file`; `POST /api/download` saves on the server
- `GET /api/config`, `POST /api/cache/clear`

POST requests must be `Content-Type: application/json`; requests from other
origins are refused. In browser mode keep the session cookies (a cookie jar).

## Troubleshooting

- **Code asked after a wrong password**: Apple answers a wrong password like
  a request for the code. No code on your devices means the password is wrong.
- **"Password token expired"**: the server signs in again with the saved
  password; if that's not possible, sign out and in.
- **"License required"**: get the app (free apps, Arcade with a
  subscription); paid apps must be bought in the App Store first.
- **Sign-in fails with a network error**: check the connection, VPN or
  proxy; `tools/diagnose_login.py` shows where it stops.

## License

GNU Affero General Public License v3.0, see [LICENSE](LICENSE) and
[NOTICE](NOTICE). If you run a modified version for others over a network,
its users must be able to get its source: the page footer always links to
`/source`, a zip of the running copy (code only, never keys or sign-ins), and
with `--repo-url URL` (or `IPATOOL_REPO_URL`) also to the repository. `vendor/unicorn` keeps its
own licenses (GPLv2, BSD).

## Acknowledgments

Fork of [pyIPATool-WebUI by John Schmudde](https://github.com/jschmudd14/pyIPATool-WebUI),
published under the AGPL-3.0 with his permission.

Based on [ipatool by Majd Alfhaily](https://github.com/majd/ipatool) (MIT).
The signing code in `ipatool_api/services/sap/` is a Python port of ipatool's
`internal/sap`; sign-in, download endpoints and version lookup follow ipatool
`main` up to commit `b0fe32d`.
