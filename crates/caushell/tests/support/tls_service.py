from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import ssl
import sys
import threading


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers["Content-Length"])
        if not 0 <= size <= 1024:
            self.send_error(413)
            return
        Path(sys.argv[3]).write_bytes(self.rfile.read(size))
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(sys.argv[1], sys.argv[2])
server.socket = context.wrap_socket(server.socket, server_side=True)
thread = threading.Thread(target=server.serve_forever)
thread.start()
print(server.server_port, flush=True)
try:
    sys.stdin.read()
finally:
    server.shutdown()
    server.server_close()
    thread.join()
