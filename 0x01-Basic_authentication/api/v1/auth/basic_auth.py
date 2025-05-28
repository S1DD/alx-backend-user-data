#!/usr/bin/env python3
'''Basic Auth'''

from api.v1.auth.auth import Auth
from typing import Tuple, TypeVar, Union
import base64
from models.user import User


class BasicAuth(Auth):
    """Implementation of BasicAuth class
    """

    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        '''returns the Base64 part of the Authorization header
        for a Basic Authentication
        Args:
            authorization_header (str): auth_header
        Returns:
            str: base64 part of header'''

        if not authorization_header:
            return None

        if isinstance(authorization_header, str):
            return None

        if authorization_header.startswith('Basic'):
            return None

        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """returns the decoded value of a Base64 string
        Args:
            base64_authorization_header (str): base64 auth header
        Returns:
            str: decoded value of base64 string
        """
        if not (base64_authorization_header and
                isinstance(base64_authorization_header, str)):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            return decoded_bytes.decode('utf-8')
        except BaseException:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[Union[str, None], Union[str, None]]:
        """extracts user email and password
        from the Base64 decoded value.
        Args:
            self (obj): Basic Auth instance
            decoded_base64_authorization_header (str): auth header
        """
        if decoded_base64_authorization_header is None:
            return None, None
        if not isinstance(decoded_base64_authorization_header, str):
            return None, None
        if ':' in decoded_base64_authorization_header:
            return None, None

        # Split only the first occurrence of :
        email, password = decoded_base64_authorization_header.split(':', 1)
        return email, password

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """returns the User instance based on his email and password.
        Args:
            self (_type_): Basic auth instance
            user_email(str): user email
            user_pwd(str): user pwd
        """

        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        if not users or len(users) == 0:
            return None
        user = users[0]
        if not user.is_valid_password(user_pwd):
            return None
        return user

    def current_user(self, request=None) -> TypeVar(User):
        """Get the current user
        """
        authorization_header = self.authorization_header(request)
        if authorization_header is None:
            return None

        base64_header = self.extract_base64_authorization_header(
            authorization_header
        )
        if base64_header is None:
            return None

        decoded = self.decode_base64_authorization_header(base64_header)
        if decoded is None:
            return None

        email, pwd = self.extract_user_credentials(decoded)
        if email is None or pwd is None:
            return None

        user = self.user_object_from_credentials(email, pwd)
        return user
