# VPS-CADDY

A server on the internet with Caddy, which gets and renews the certificate by
itself. Point the domain's A record to the server first; ports 80 and 443
must be free.

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

## Caddy

```sh
apt install -y caddy
cp Caddyfile /etc/caddy/Caddyfile     # replace ipa.example.org
systemctl reload caddy
```

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
