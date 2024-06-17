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
"""The ibm_cloud_sdk_core project supports the following types of authentication:

  Basic Authentication
  Bearer Token
  Identity and Access Management (IAM)
  Cloud Pak for Data
  No Authentication

  The authentication types that are appropriate for a particular service may vary from service to service.
  Each authentication type is implemented as an Authenticator for consumption by a service.

classes:
  Authenticator: Abstract Base Class. Implement this interface to provide custom authentication schemes to services.
  BasicAuthenticator: Authenticator for passing supplied basic authentication information to service endpoint.
  BearerTokenAuthenticator: Authenticator for passing supplied bearer token to service endpoint.
  CloudPakForDataAuthenticator: Authenticator for passing CP4D authentication information to service endpoint.
  IAMAuthenticator: Authenticator for passing IAM authentication information to service endpoint.
  NoAuthAuthenticator: Performs no authentication. Useful for testing purposes.
"""

from .authenticator import Authenticator
from .basic_authenticator import BasicAuthenticator
from .bearer_token_authenticator import BearerTokenAuthenticator
from .container_authenticator import ContainerAuthenticator
from .cp4d_authenticator import CloudPakForDataAuthenticator
from .iam_authenticator import IAMAuthenticator
from .vpc_instance_authenticator import VPCInstanceAuthenticator
from .no_auth_authenticator import NoAuthAuthenticator
