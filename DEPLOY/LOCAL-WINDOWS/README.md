# LOCAL-WINDOWS

1. Install Python 3.9+ from python.org (tick "Add python.exe to PATH").
2. In the project folder:
   ```bat
   python -m venv venv
   venv\Scripts\pip install -r requirements.txt
   ```
3. Start:
   - `start-local.bat`: only this PC, open http://127.0.0.1:5002
   - `start-lan-https.bat`: phones and tablets at home, open
     `https://<this PC's IP>:5002`

## Certificate for the home network

Installing apps on iOS (OTA) needs HTTPS with a certificate the device trusts.
With [mkcert](https://github.com/FiloSottile/mkcert):

```bat
mkdir Certs
mkcert -install
mkcert -cert-file Certs\cert.pem -key-file Certs\key.pem localhost 127.0.0.1 192.168.0.10
copy "%LOCALAPPDATA%\mkcert\rootCA.pem" Certs\
```

(put your PC's addresses instead of `192.168.0.10`). On the iPhone open
`https://<PC>:5002/ca.crt`, install the profile and turn it on in Settings,
General, About, Certificate Trust Settings.

Keys in `Certs\` never leave the PC: the source archive the server offers
(`/source`) contains code only.

## In the background

`python serverctl.py --host 0.0.0.0 ...` starts the server detached,
`python serverctl.py --kill-server` stops it.
