#!/usr/bin/env python3
"""Auth class"""
from flask import Flask, request
from typing import List, TypeVar


class Auth:
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
    Checks if authentication is required for a given path.

    Parameters:
        path (str): The URL path to check.
        excluded_paths (List[str]): A list of paths that do not require authentication.
            - Paths may include a trailing '*' to indicate prefix matching.

    Returns:
        bool: True if authentication is required, False otherwise.

    Notes:
        - A trailing slash is appended to the path and excluded paths (if missing)
          to ensure consistent comparison.
        - If the path matches any excluded path or matches a prefix (when '*' is used),
          authentication is not required.
    """
        if path is None or excluded_paths is None or not excluded_paths:
            return True

        # Normalize path by ensuring it ends with '/'
        if not path.endswith('/'):
            path += '/'

        for excluded in excluded_paths:
            if excluded.endswith('*'):
                # Match prefix if wildcard present
                if path.startswith(excluded[:-1]):
                    return False
            else:
                # Normalize excluded path
                if not excluded.endswith('/'):
                    excluded += '/'
                if path == excluded:
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Gets the Authorization header if found otherwise returns None
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieves the current authenticated user"""
        return None
