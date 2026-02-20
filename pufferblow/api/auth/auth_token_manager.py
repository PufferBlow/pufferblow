import base64
import datetime
import hashlib
import hmac
import json
import os
import random
import secrets
import string
from typing import Any

from loguru import logger

from pufferblow.api.database.database_handler import DatabaseHandler
from pufferblow.api.hasher.hasher import Hasher
from pufferblow.api.logger.msgs import debug


class AuthTokenManager:
    """Authentication token manager with JWT access + refresh token support."""

    def __init__(self, database_handler: DatabaseHandler, hasher: Hasher) -> None:
        self.database_handler = database_handler
        self.hasher = hasher
        config = self.database_handler.config
        self.jwt_secret = (
            os.getenv("PUFFERBLOW_JWT_SECRET")
            or os.getenv("JWT_SECRET")
            or getattr(config, "JWT_SECRET", "change-this-jwt-secret-in-production")
        )
        self.access_ttl_minutes = int(
            os.getenv(
                "PUFFERBLOW_JWT_ACCESS_TTL_MINUTES",
                str(getattr(config, "JWT_ACCESS_TTL_MINUTES", 15)),
            )
        )
        self.refresh_ttl_days = int(
            os.getenv(
                "PUFFERBLOW_JWT_REFRESH_TTL_DAYS",
                str(getattr(config, "JWT_REFRESH_TTL_DAYS", 30)),
            )
        )

    def _instance_id(self) -> str:
        config = self.database_handler.config
        return f"{config.API_HOST}:{config.API_PORT}"

    @staticmethod
    def _b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _b64url_decode(data: str) -> bytes:
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode((data + padding).encode("utf-8"))

    def _sign(self, signing_input: str) -> str:
        signature = hmac.new(
            self.jwt_secret.encode("utf-8"),
            signing_input.encode("utf-8"),
            hashlib.sha256,
        ).digest()
        return self._b64url_encode(signature)

    def create_access_token(self, user_id: str, origin_server: str) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(minutes=self.access_ttl_minutes)
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": str(user_id),
            "origin_server": str(origin_server),
            "iss": self._instance_id(),
            "iat": int(now.timestamp()),
            "exp": int(exp.timestamp()),
            "jti": secrets.token_hex(12),
        }

        header_segment = self._b64url_encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        payload_segment = self._b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )
        signing_input = f"{header_segment}.{payload_segment}"
        signature_segment = self._sign(signing_input)
        return f"{signing_input}.{signature_segment}"

    def decode_access_token(
        self, auth_token: str, verify_exp: bool = True
    ) -> dict[str, Any]:
        parts = auth_token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format")

        header_segment, payload_segment, signature_segment = parts
        signing_input = f"{header_segment}.{payload_segment}"
        expected_signature = self._sign(signing_input)

        if not hmac.compare_digest(signature_segment, expected_signature):
            raise ValueError("Invalid JWT signature")

        header = json.loads(self._b64url_decode(header_segment).decode("utf-8"))
        payload = json.loads(self._b64url_decode(payload_segment).decode("utf-8"))

        if header.get("alg") != "HS256" or header.get("typ") != "JWT":
            raise ValueError("Unsupported JWT header")

        token_origin_server = payload.get("origin_server")
        if not token_origin_server:
            raise ValueError("Missing origin_server claim")

        if token_origin_server != self._instance_id():
            raise ValueError("Token origin does not match current instance")

        if verify_exp:
            now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
            if int(payload.get("exp", 0)) <= now_ts:
                raise ValueError("JWT expired")

        return payload

    def create_refresh_token(self, user_id: str, origin_server: str) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        exp = now + datetime.timedelta(days=self.refresh_ttl_days)
        payload = {
            "uid": str(user_id),
            "origin_server": str(origin_server),
            "exp": int(exp.timestamp()),
            "rnd": secrets.token_urlsafe(32),
        }
        return self._b64url_encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        )

    def _hash_refresh_token(self, refresh_token: str) -> str:
        return hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()

    def save_refresh_token(self, user_id: str, refresh_token: str) -> None:
        token_hash = self._hash_refresh_token(refresh_token)
        expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=self.refresh_ttl_days
        )
        self.database_handler.save_refresh_token(
            user_id=str(user_id),
            token_hash=token_hash,
            expires_at=expires_at,
        )

    def validate_refresh_token(self, refresh_token: str) -> dict[str, Any]:
        try:
            payload = json.loads(self._b64url_decode(refresh_token).decode("utf-8"))
        except Exception as e:
            raise ValueError("Malformed refresh token") from e

        required = {"uid", "origin_server", "exp"}
        if not required.issubset(payload.keys()):
            raise ValueError("Refresh token missing required claims")

        if payload.get("origin_server") != self._instance_id():
            raise ValueError("Refresh token origin does not match current instance")

        now_ts = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if int(payload.get("exp", 0)) <= now_ts:
            raise ValueError("Refresh token expired")

        token_hash = self._hash_refresh_token(refresh_token)
        token_record = self.database_handler.get_refresh_token(token_hash=token_hash)
        if token_record is None:
            raise ValueError("Refresh token revoked or unknown")

        return payload

    def revoke_refresh_token(self, refresh_token: str) -> None:
        token_hash = self._hash_refresh_token(refresh_token)
        self.database_handler.delete_refresh_token(token_hash=token_hash)

    def issue_session_tokens(
        self, user_id: str, origin_server: str
    ) -> dict[str, Any]:
        access_token = self.create_access_token(
            user_id=str(user_id), origin_server=origin_server
        )
        refresh_token = self.create_refresh_token(
            user_id=str(user_id), origin_server=origin_server
        )
        self.save_refresh_token(user_id=str(user_id), refresh_token=refresh_token)

        now = datetime.datetime.now(datetime.timezone.utc)
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "Bearer",
            "access_token_expires_at": (
                now + datetime.timedelta(minutes=self.access_ttl_minutes)
            ).isoformat(),
            "refresh_token_expires_at": (
                now + datetime.timedelta(days=self.refresh_ttl_days)
            ).isoformat(),
        }

    def check_auth_token_format(self, auth_token: str) -> bool:
        if auth_token.count(".") == 2:
            return True
        if "." not in auth_token:
            return False

        user_id = auth_token.split(".")[0]
        token = auth_token.split(".")[1]
        return len(user_id) == 36 and len(token) == 41

    def check_users_auth_token(self, user_id: str, raw_auth_token: str) -> bool:
        # JWT path
        if raw_auth_token.count(".") == 2:
            try:
                payload = self.decode_access_token(raw_auth_token, verify_exp=True)
                return str(payload.get("sub")) == str(user_id)
            except Exception:
                return False

        # Legacy fallback path
        user_data = self.database_handler.get_user(user_id=user_id)
        ciphered_auth_token = base64.b64decode(user_data.auth_token)
        key = self.database_handler.get_keys(
            user_id=user_id, associated_to="auth_token"
        )
        auth_token = self.hasher.decrypt(
            ciphertext=ciphered_auth_token, key=key.key_value, iv=key.iv
        )
        return auth_token == raw_auth_token

    # Legacy methods kept for compatibility
    def token_exists(self, user_id: str, hashed_auth_token: str):
        return self.database_handler.check_auth_token(
            user_id=user_id, hashed_auth_token=hashed_auth_token
        )

    def is_token_valid(self, user_id: str, auth_token: str) -> bool:
        expire_time = self.database_handler.get_auth_token_expire_time(
            user_id=user_id, auth_token=auth_token
        )
        if expire_time is None:
            return False
        if hasattr(expire_time, "timestamp"):
            return expire_time.timestamp() > datetime.datetime.now(
                datetime.timezone.utc
            ).timestamp()
        try:
            parsed = datetime.datetime.fromisoformat(str(expire_time))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=datetime.timezone.utc)
            return parsed > datetime.datetime.now(datetime.timezone.utc)
        except Exception:
            return False

    def create_token(self) -> str:
        size = 41
        alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits
        token = "".join(random.choice(alphabet) for _ in range(size))
        logger.info(debug.DEBUG_NEW_AUTH_TOKEN_GENERATED(auth_token=token))
        return token

    def delete_token(self, user_id: str, auth_token: str) -> None:
        ciphered_auth_token, _key = self.hasher.encrypt(data=auth_token)
        self.database_handler.delete_auth_token(
            user_id=user_id, auth_token=ciphered_auth_token
        )

    def create_auth_token_expire_time(self):
        expire_time = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
            days=30
        )
        return expire_time.strftime("%Y-%m-%d")
