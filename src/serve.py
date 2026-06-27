import http.server as hs, os, json as _json
from urllib.parse import urlparse, unquote

_THIS = os.path.dirname(os.path.abspath(__file__))
try:
    with open(os.path.join(_THIS, "config.json"), encoding="utf-8") as _f:
        _cfg = _json.load(_f)
    _DEF_PORT = int(_cfg.get("file_port", 5513))
except:
    _DEF_PORT = 5513

class FileServer:
    def __init__(self, directory=None, port=_DEF_PORT):
        self.directory = os.path.abspath(directory or os.path.join(_THIS, "Payload", "bins"))
        self.port = port

    def start(self):
        root = self.directory
        class H(hs.SimpleHTTPRequestHandler):
            def do_GET(self):
                p = unquote(urlparse(self.path).path)
                if not p.startswith("/bin/"):
                    self.connection.close()
                    return
                fname = p[len("/bin/"):]
                fpath = os.path.join(root, fname)
                if not os.path.isfile(fpath):
                    self.connection.close()
                    return
                with open(fpath, "rb") as f:
                    self.send_response(200)
                    self.send_header("Content-type", "application/octet-stream")
                    self.end_headers()
                    self.wfile.write(f.read())
        srv = hs.HTTPServer(("0.0.0.0", self.port), H)
        import threading
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        return srv, t

if __name__ == "__main__":
    FileServer().start()[0].serve_forever()
