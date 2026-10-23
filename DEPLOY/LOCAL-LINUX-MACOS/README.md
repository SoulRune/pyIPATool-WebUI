# LOCAL-LINUX-MACOS

1. Python 3.9+ (Debian/Ubuntu: `sudo apt install python3 python3-venv`).
2. In the project folder:
   ```sh
   python3 -m venv venv
   venv/bin/pip install -r requirements.txt
   ```
3. Start:
   - `./DEPLOY/LOCAL-LINUX-MACOS/start-local.sh`: only this computer,
     http://127.0.0.1:5002
   - `./DEPLOY/LOCAL-LINUX-MACOS/start-lan-https.sh`: phones and tablets at
     home, `https://<this computer's IP>:5002`

On 32-bit ARM (old Raspberry Pi OS) pip builds Unicorn from source:
`sudo apt install cmake build-essential` first.

## Certificate for the home network

```sh
mkdir -p Certs
mkcert -install
mkcert -cert-file Certs/cert.pem -key-file Certs/key.pem localhost 127.0.0.1 192.168.0.10
cp "$(mkcert -CAROOT)/rootCA.pem" Certs/
```

On the iPhone open `https://<computer>:5002/ca.crt`, install the profile and
turn it on in Settings, General, About, Certificate Trust Settings.

## In the background

`python serverctl.py ...` / `python serverctl.py --kill-server`, or on macOS
and jailbroken iOS the launchd template `scripts/com.ipatool.webui.plist`.
