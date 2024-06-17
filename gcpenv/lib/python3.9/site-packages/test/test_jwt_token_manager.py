# pylint: disable=missing-docstring,protected-access,abstract-class-instantiated
import time
import threading
from typing import Optional

import jwt
import pytest

from ibm_cloud_sdk_core import JWTTokenManager, DetailedResponse


class JWTTokenManagerMockImpl(JWTTokenManager):
    def __init__(self, url: Optional[str] = None, access_token: Optional[str] = None) -> None:
        self.url = url
        self.access_token = access_token
        self.request_count = 0  # just for tests to see how  many times request was called
        super().__init__(url, disable_ssl_verification=access_token, token_name='access_token')

    def request_token(self) -> DetailedResponse:
        self.request_count += 1
        current_time = int(time.time())
        token_layout = {
            "username": "dummy",
            "role": "Admin",
            "permissions": ["administrator", "manage_catalog"],
            "sub": "admin",
            "iss": "sss",
            "aud": "sss",
            "uid": "sss",
            "iat": current_time,
            "exp": current_time + 3600,
        }

        access_token = jwt.encode(
            token_layout, 'secret', algorithm='HS256', headers={'kid': '230498151c214b788dd97f22b85410a5'}
        )
        response = {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "expiration": current_time + 3600,
            "refresh_token": "jy4gl91BQ",
            "from_token_manager": True,
        }
        time.sleep(0.5)
        return response


def _get_current_time() -> int:
    return int(time.time())


def test_get_token():
    url = "https://iam.cloud.ibm.com/identity/token"
    token_manager = JWTTokenManagerMockImpl(url)
    old_token = token_manager.get_token()
    assert token_manager.token_info.get('expires_in') == 3600
    assert token_manager._is_token_expired() is False

    token_manager.token_info = {
        "access_token": "old_dummy",
        "token_type": "Bearer",
        "expires_in": 3600,
        "expiration": time.time(),
        "refresh_token": "jy4gl91BQ",
    }
    token = token_manager.get_token()
    assert token == old_token

    # expired token:
    token_manager.expire_time = _get_current_time() - 300
    token = token_manager.get_token()
    assert token != "old_dummy"
    assert token_manager.request_count == 2


def test_paced_get_token():
    url = "https://iam.cloud.ibm.com/identity/token"
    token_manager = JWTTokenManagerMockImpl(url)
    threads = []
    for _ in range(10):
        thread = threading.Thread(target=token_manager.get_token)
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
    assert token_manager.request_count == 1


def test_is_token_expired():
    token_manager = JWTTokenManagerMockImpl(None, access_token=None)
    assert token_manager._is_token_expired() is True
    token_manager.expire_time = _get_current_time() + 3600
    assert token_manager._is_token_expired() is False
    token_manager.expire_time = _get_current_time() - 3600
    assert token_manager._is_token_expired()


def test_abstract_class_instantiation():
    with pytest.raises(TypeError) as err:
        JWTTokenManager(None)
    assert str(err.value).startswith("Can't instantiate abstract class JWTTokenManager with abstract")


def test_disable_ssl_verification():
    token_manager = JWTTokenManagerMockImpl('https://iam.cloud.ibm.com/identity/token')
    token_manager.set_disable_ssl_verification(True)
    assert token_manager.disable_ssl_verification is True
