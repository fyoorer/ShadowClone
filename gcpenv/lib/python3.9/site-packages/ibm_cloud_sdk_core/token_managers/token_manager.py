# coding: utf-8

# Copyright 2020 IBM All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import time
from abc import ABC, abstractmethod
from threading import Lock

import requests

from ..api_exception import ApiException


# pylint: disable=too-many-instance-attributes
class TokenManager(ABC):
    """An abstract class to contain functionality for parsing, storing, and requesting tokens.

    get_token will retrieve a new token from the url in case the that there is no existing token,
    or the previous token has expired. Child classes will implement request_token, which will do
    the actual acquisition of a new token.

    Args:
        url: The url to request tokens from.

    Keyword Args:
        disable_ssl_verification: A flag that indicates whether verification of
            the server's SSL certificate should be disabled or not. Defaults to False.

    Attributes:
        url (str): The url to request tokens from.
        disable_ssl_verification (bool): A flag that indicates whether verification of
        the server's SSL certificate should be disabled or not.
        expire_time (int): The time in epoch seconds when the current stored token will expire.
        refresh_time (int): The time in epoch seconds when the current stored token should be refreshed.
        request_time (int): The time the last outstanding token request was issued
        lock (Lock): Lock variable to serialize access to refresh/request times
        http_config (dict): A dictionary containing values that control the timeout, proxies, and etc of HTTP requests.
        access_token (str): The latest stored access token
    """

    def __init__(self, url: str, *, disable_ssl_verification: bool = False):
        self.url = url
        self.disable_ssl_verification = disable_ssl_verification
        self.expire_time = 0
        self.refresh_time = 0
        self.request_time = 0
        self.lock = Lock()
        self.http_config = {}
        self.access_token = None

    def get_token(self) -> str:
        """Get a token to be used for authentication.

        The source of the token is determined by the following logic:
        1.  a) If the current token is expired (or never fetched), make a request for one
            b) If the current token should be refreshed, issue a refresh request
        2. After any requests initiated above complete, return the stored token

        Returns:
            str: A valid access token
        """
        if self._is_token_expired():
            self.paced_request_token()

        if self._token_needs_refresh():
            token_response = self.request_token()
            self._save_token_info(token_response)

        return self.access_token

    def set_disable_ssl_verification(self, status: bool = False) -> None:
        """Sets the ssl verification to enabled or disabled.

        Args:
            status: the flag to be used for determining status.

        Raises:
            TypeError: The `status` is not a bool.
        """
        if isinstance(status, bool):
            self.disable_ssl_verification = status
        else:
            raise TypeError('status must be a bool')

    def paced_request_token(self) -> None:
        """
        Paces requests to request_token.

        This method pseudo-serializes requests for an access_token
        when the current token is expired (or has never been fetched).
        The first caller into this method records its `request_time` and
        then issues the token request. Subsequent callers will check the
        `request_time` to see if a request is active (has been issued within
        the past 60 seconds), and if so will sleep for a short time interval
        (currently 0.5 seconds) before checking again. The check for an active
        request and update of `request_time` are serailized by the `lock`
        variable so that only one caller can become the active requester
        with a 60 second interval.

        Threads that sleep waiting for the active request to complete will
        eventually find a newly valid token and return, or 60 seconds will
        elapse and a new thread will assume the role of the active request.
        """
        while self._is_token_expired():
            current_time = self._get_current_time()

            with self.lock:
                request_active = self.request_time > (current_time - 60)
                if not request_active:
                    self.request_time = current_time

            if not request_active:
                token_response = self.request_token()
                self._save_token_info(token_response)
                self.request_time = 0
                return

            # Sleep for 0.5 seconds before checking token again
            time.sleep(0.5)

    @abstractmethod  # pragma: no cover
    def request_token(self) -> None:
        """Should be overridden by child classes."""
        pass

    @staticmethod
    def _get_current_time() -> int:
        return int(time.time())

    def _is_token_expired(self) -> bool:
        """
        Check if currently stored token is expired.

        Returns
        -------
        bool
            True if token is expired; False otherwise
        """
        current_time = self._get_current_time()
        return self.expire_time < current_time

    def _token_needs_refresh(self) -> bool:
        """
        Check if currently stored token needs refresh.

        Returns
        -------
        bool
            True if token needs refresh; False otherwise
        """
        current_time = self._get_current_time()

        with self.lock:
            needs_refresh = self.refresh_time < current_time
            if needs_refresh:
                self.refresh_time = current_time + 60

        return needs_refresh

    @abstractmethod
    def _save_token_info(self, token_response: dict) -> None:  # pragma: no cover
        """
        Decode the access token and save the response from the service to the object's state

        Refresh time is set to approximately 80% of the token's TTL to ensure that
        the token refresh completes before the current token expires.

        Parameters
        ----------
        token_response : dict
            Response from token service
        """
        pass

    def _request(self, method, url, *, headers=None, params=None, data=None, auth_tuple=None, **kwargs):
        kwargs = dict({"timeout": 60}, **kwargs)
        kwargs = dict(kwargs, **self.http_config)

        if self.disable_ssl_verification:
            kwargs['verify'] = False

        response = requests.request(
            method=method, url=url, headers=headers, params=params, data=data, auth=auth_tuple, **kwargs
        )
        if 200 <= response.status_code <= 299:
            return response

        raise ApiException(response.status_code, http_response=response)
