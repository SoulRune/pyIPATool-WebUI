# VPS-NGINX-UNDER-PATH

For a server where nginx already serves a site with a certificate, for example
a VPN panel's site (3x-ui and similar). The app is added under a path,
`https://<domain>/ipa/`, and shares the site's certificate. The site's own
files are not edited except for one `include` line.

## Install (Debian 12 / Ubuntu 22.04+)

```sh
apt update && apt install -y python3 python3-venv unzip
useradd --system --home /var/lib/ipatool --create-home --shell /usr/sbin/nologin ipatool

cd /opt && unzip /root/pyIPATool-WebUI.zip        # -> /opt/pyIPATool-WebUI
cd /opt/pyIPATool-WebUI
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

mkdir -p /etc/pyipatool
(umask 077; read -rsp "Access password: " P; echo; printf "%s\n" "$P" > /etc/pyipatool/access)
chown ipatool /etc/pyipatool/access
```

## nginx

```sh
cp pyipatool.conf      /etc/nginx/snippets/
cp pyipatool-http.conf /etc/nginx/conf.d/
```

Add one line inside the site's `server { }` block (or in a file it already
includes, such as a snippets file):

```nginx
include /etc/nginx/snippets/pyipatool.conf;
```

then `nginx -t && systemctl reload nginx`. If the panel regenerates its files,
add the line again.

Notes for panel sites:

- The block turns off `proxy_intercept_errors` for `/ipa/`: panels often turn
  every error into a 404 page, which would hide the app's own messages.
- `X-Forwarded-Proto` is set to `https` directly: behind an SNI router nginx
  listens on an inner port, but users always come over HTTPS.
- In `pyipatool.service` use the site's domain for `--trusted-host`.

## Service

Copy `pyipatool.service` to `/etc/systemd/system/`, replace
`ipa.example.org` with your domain, then:

```sh
systemctl daemon-reload && systemctl enable --now pyipatool
journalctl -u pyipatool -f       # log
```

The first sign-in takes a minute or two: the server fetches Apple's files
once (~120 MB). Update later: unpack the new version over
`/opt/pyIPATool-WebUI`, then `systemctl restart pyipatool`.

## Check

- `https://<domain>/` asks for the access password, then shows the app.
- Behind the proxy the app accepts HTTPS only (plain HTTP pages are
  redirected) and only the name given with `--trusted-host`.
- No access password (an open service): remove `--access-password-file`
  from the service. Sign-ins stay limited per address.
