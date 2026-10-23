# DEPLOY

Ready-made settings for running pyIPATool WebUI. Each folder has the files
and a short README; copy what you need and change the marked values.

| Folder | For |
|---|---|
| `LOCAL-WINDOWS` | Your own Windows PC: only this PC, or the home network over HTTPS |
| `LOCAL-LINUX-MACOS` | The same on Linux or macOS |
| `VPS-NGINX` | A server on the internet, nginx with its own domain |
| `VPS-NGINX-UNDER-PATH` | A server where nginx already serves a site (e.g. a VPN panel): the app at `https://domain/ipa/` |
| `VPS-CADDY` | A server on the internet with Caddy (gets the certificate by itself) |

Rules of thumb:

- At home: `python app.py` is enough. Add `--host 0.0.0.0` and a certificate
  only to use it from phones and tablets.
- On the internet: the app listens on `127.0.0.1` only, a reverse proxy in
  front does HTTPS, and `--access-password-file` keeps strangers out.
- On a small server (1 CPU, 1-2 GB RAM): `--emulators 1 --max-downloads 1`.
  A sign-in or download signature takes ~400 MB for a few seconds.
