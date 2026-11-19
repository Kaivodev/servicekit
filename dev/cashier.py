"""Development TLS endpoint for the simulator's browser payment form."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import re
import ssl


class Cashier(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # The path contains the one-order cashier token.

    def forward(self):
        if not ((self.path == "/healthz" and self.command == "GET") or
                re.fullmatch(r"/cashier/[A-Za-z0-9_-]{1,128}", self.path)):
            self.send_error(404)
            return
        # The upstream form submits an empty POST. No client headers, credentials
        # or body need to be relayed to the fixed simulator.
        upstream = http.client.HTTPConnection(os.environ["CASHIER_SIM_HOST"], 9080, timeout=5)
        try:
            upstream.request(self.command, self.path)
            res = upstream.getresponse()
            body = res.read(65537)
            if len(body) > 65536:
                self.send_error(502)
                return
            self.send_response(res.status)
            for k in ("Content-Type", "Content-Security-Policy"):
                if res.getheader(k):
                    self.send_header(k, res.getheader(k))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (OSError, http.client.HTTPException):
            self.close_connection = True
        finally:
            upstream.close()

    do_GET = do_POST = forward


if __name__ == "__main__":
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(os.environ["CASHIER_CERT"], os.environ["CASHIER_KEY"])
    with ThreadingHTTPServer((os.environ["CASHIER_LISTEN_HOST"], 9443), Cashier) as server:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
