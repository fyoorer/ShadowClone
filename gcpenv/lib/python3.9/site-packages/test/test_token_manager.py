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

# pylint: disable=missing-docstring,protected-access,abstract-class-instantiated
from types import SimpleNamespace
from unittest import mock

import pytest

from ibm_cloud_sdk_core import ApiException
from ibm_cloud_sdk_core.token_managers.token_manager import TokenManager


class MockTokenManager(TokenManager):
    def request_token(self) -> None:
        response = self._request(method='GET', url=self.url)
        return response

    def _save_token_info(self, token_response: dict) -> None:
        pass


def test_abstract_class_instantiation():
    with pytest.raises(TypeError) as err:
        TokenManager(None)
    assert (
        str(err.value) == "Can't instantiate abstract class "
        "TokenManager with abstract methods "
        "_save_token_info, "
        "request_token"
    )


def requests_request_spy(*args, **kwargs):
    return SimpleNamespace(status_code=200, request_args=args, request_kwargs=kwargs)


@mock.patch('requests.request', side_effect=requests_request_spy)
def test_request_passes_disable_ssl_verification(request):  # pylint: disable=unused-argument
    mock_token_manager = MockTokenManager(url="https://example.com", disable_ssl_verification=True)
    assert mock_token_manager.request_token().request_kwargs['verify'] is False


def requests_request_error_mock(*args, **kwargs):  # pylint: disable=unused-argument
    return SimpleNamespace(status_code=300, headers={}, text="")


@mock.patch('requests.request', side_effect=requests_request_error_mock)
def test_request_raises_for_non_2xx(request):  # pylint: disable=unused-argument
    mock_token_manager = MockTokenManager(url="https://example.com", disable_ssl_verification=True)
    with pytest.raises(ApiException):
        mock_token_manager.request_token()


def test_set_disable_ssl_verification_success():
    token_manager = MockTokenManager(None)
    assert token_manager.disable_ssl_verification is False

    token_manager.set_disable_ssl_verification(True)
    assert token_manager.disable_ssl_verification is True


def test_set_disable_ssl_verification_fail():
    token_manager = MockTokenManager(None)

    with pytest.raises(TypeError) as err:
        token_manager.set_disable_ssl_verification('True')
    assert str(err.value) == 'status must be a bool'
    assert token_manager.disable_ssl_verification is False
