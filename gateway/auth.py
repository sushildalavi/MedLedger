from functools import wraps

from flask import g, jsonify, request

from medcrypto.passwords import verify_password
from medcrypto.tokens import issue_token, verify_token


class AuthService:
    def __init__(self, users: dict, token_secret: bytes):
        self.users = users
        self.token_secret = token_secret

    def login(self, username: str, password: str) -> str | None:
        user = self.users.get(username)
        if not user:
            return None
        if not verify_password(password, user["password"]):
            return None
        return issue_token(self.token_secret, username, user["role"])

    def authenticate(self, token: str) -> dict | None:
        return verify_token(self.token_secret, token)


def require_roles(auth: AuthService, *roles: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify({"error": "missing bearer token"}), 401
            token = header[len("Bearer "):]
            payload = auth.authenticate(token)
            if not payload:
                return jsonify({"error": "invalid or expired token"}), 401
            if roles and payload["role"] not in roles:
                return jsonify({"error": "forbidden", "role": payload["role"]}), 403
            g.user = payload
            return fn(*args, **kwargs)
        return wrapper
    return decorator
