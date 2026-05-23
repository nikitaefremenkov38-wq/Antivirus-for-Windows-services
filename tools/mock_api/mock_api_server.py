import base64
import json
import ssl
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


HOST = "localhost"
PORT = 8443
VALID_USERS = {
    "demo": {
        "password": "demo",
        "activationCode": "DEMO-1234-5678",
    },
    "danil": {
        "password": "danil",
        "activationCode": "DANIL12345-6789",
    },
}


STATE = {
    "refresh_tokens": {},
    "license_by_user": {},
}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def create_jwt(subject: str, lifetime_seconds: int) -> str:
    now = int(time.time())
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": subject, "exp": now + lifetime_seconds}
    return f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(payload).encode())}.sig"


def json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict):
    body = json.dumps(payload).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def read_json(handler: BaseHTTPRequestHandler) -> dict:
    length = int(handler.headers.get("Content-Length", "0"))
    data = handler.rfile.read(length) if length else b"{}"
    return json.loads(data.decode("utf-8"))


def get_bearer_subject(handler: BaseHTTPRequestHandler):
    header = handler.headers.get("Authorization", "")
    if not header.startswith("Bearer "):
        return None

    token = header[len("Bearer "):]
    try:
        parts = token.split(".")
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        if payload.get("exp", 0) < int(time.time()):
            return None
        return payload.get("sub")
    except Exception:
        return None


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        return

    def do_POST(self):
        if self.path == "/api/v1/auth/login":
            payload = read_json(self)
            username = payload.get("username", "")
            password = payload.get("password", "")
            user_info = VALID_USERS.get(username)
            if not user_info or password != user_info["password"]:
                json_response(self, 401, {"error": "invalid_credentials"})
                return

            access_token = create_jwt(username, 300)
            refresh_token = create_jwt(username, 1800)
            STATE["refresh_tokens"][refresh_token] = username
            json_response(
                self,
                200,
                {
                    "accessToken": access_token,
                    "refreshToken": refresh_token,
                    "userName": username,
                },
            )
            return

        if self.path == "/api/v1/auth/refresh":
            payload = read_json(self)
            refresh_token = payload.get("refreshToken", "")
            username = STATE["refresh_tokens"].get(refresh_token)
            if not username:
                json_response(self, 401, {"error": "invalid_refresh"})
                return

            access_token = create_jwt(username, 300)
            new_refresh = create_jwt(username, 1800)
            del STATE["refresh_tokens"][refresh_token]
            STATE["refresh_tokens"][new_refresh] = username
            json_response(
                self,
                200,
                {
                    "accessToken": access_token,
                    "refreshToken": new_refresh,
                    "userName": username,
                },
            )
            return

        if self.path == "/api/v1/license/activate":
            subject = get_bearer_subject(self)
            if not subject:
                json_response(self, 401, {"error": "unauthorized"})
                return

            payload = read_json(self)
            user_info = VALID_USERS.get(subject)
            if not user_info or payload.get("activationCode") != user_info["activationCode"]:
                json_response(self, 400, {"error": "invalid_activation_code"})
                return

            expires_at = int(time.time()) + 3600
            STATE["license_by_user"][subject] = {
                "licenseTicket": f"ticket-{subject}-{expires_at}",
                "expiresAtUnix": expires_at,
            }
            json_response(self, 200, STATE["license_by_user"][subject])
            return

        json_response(self, 404, {"error": "not_found"})

    def do_GET(self):
        if self.path == "/api/v1/license/status":
            subject = get_bearer_subject(self)
            if not subject:
                json_response(self, 401, {"error": "unauthorized"})
                return

            license_info = STATE["license_by_user"].get(subject)
            if not license_info:
                json_response(self, 404, {"error": "no_license"})
                return

            json_response(self, 200, license_info)
            return

        json_response(self, 404, {"error": "not_found"})


def main():
    base_dir = Path(__file__).resolve().parent
    cert_file = base_dir / "localhost-cert.pem"
    key_file = base_dir / "localhost-key.pem"

    if not cert_file.exists() or not key_file.exists():
        raise SystemExit("TLS certificate files are missing. Run start_mock_api.ps1 first.")

    server = HTTPServer((HOST, PORT), MockHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"Mock API running on https://{HOST}:{PORT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
