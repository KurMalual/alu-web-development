#!/usr/bin/env python3
"""
Basic auth class
"""

from api.v1.auth.auth import Auth
import base64
from typing import TypeVar, Optional, Tuple
from models.user import User


class BasicAuth(Auth):
    """ BasicAuth class
    """

    def extract_base64_authorization_header(
            self,
            authorization_header: str
            ) -> Optional[str]:
        """Extracts the Base64 part of the Authorization header."""
        if authorization_header is None or not isinstance(authorization_header, str):
            return None
        if not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str
            ) -> Optional[str]:
        """Decodes Base64 Authorization header."""
        if base64_authorization_header is None or not isinstance(base64_authorization_header, str):
            return None
        try:
            return base64.b64decode(
                base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str
            ) -> Tuple[Optional[str], Optional[str]]:
        """Extracts user credentials (email and password) from decoded header."""
        if decoded_base64_authorization_header is None or not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ":" not in decoded_base64_authorization_header:
            return None, None
        return tuple(decoded_base64_authorization_header.split(':', 1))

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str
            ) -> Optional[User]:
        """Gets a User object from credentials (email and password)."""
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({'email': user_email})

        if not users:  # No users found with this email
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> Optional[User]:
        """Returns the current User instance based on request's Authorization header."""
        header = self.authorization_header(request)
        if header is None:
            return None

        b64 = self.extract_base64_authorization_header(header)
        if b64 is None:
            return None

        decoded = self.decode_base64_authorization_header(b64)
        if decoded is None:
            return None

        user_info = self.extract_user_credentials(decoded)
        if user_info is None:
            return None

        email, pwd = user_info
        return self.user_object_from_credentials(email, pwd)
