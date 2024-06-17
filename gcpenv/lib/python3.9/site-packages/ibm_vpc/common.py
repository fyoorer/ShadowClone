# coding: utf-8

# Copyright 2019 IBM All Rights Reserved.
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

"""
This module provides common methods for use across all service modules.
"""

import platform
from ibm_vpc.version import __version__

HEADER_NAME_USER_AGENT = 'User-Agent'
SDK_NAME = 'vpc-python-sdk'

def get_system_info():
    """
    Get information about the system to be inserted into the User-Agent header.
    """
    return 'lang={0}; arch={1}; os={2}; python.version={3}'.format('python',
                                platform.machine(), # Architecture
                                platform.system(), # OS
                                platform.python_version()) # Python version


def get_user_agent():
    """
    Get the value to be sent in the User-Agent header.
    """
    return USER_AGENT


USER_AGENT = '{0}/{1} ({2})'.format(SDK_NAME, __version__, get_system_info())


def get_sdk_headers(service_name, service_version, operation_id):
    # pylint: disable=unused-argument
    """
    Get the request headers to be sent in requests by the SDK.

    """
    headers = {}
    headers[HEADER_NAME_USER_AGENT] = get_user_agent()
    return headers
