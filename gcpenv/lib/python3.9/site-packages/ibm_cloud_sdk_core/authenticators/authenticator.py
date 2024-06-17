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

from abc import ABC, abstractmethod


class Authenticator(ABC):
    """This interface defines the common methods and constants associated with an Authenticator implementation."""

    # Constants representing the various authenticator types.
    AUTHTYPE_BASIC = 'basic'
    AUTHTYPE_BEARERTOKEN = 'bearerToken'
    AUTHTYPE_IAM = 'iam'
    AUTHTYPE_CONTAINER = 'container'
    AUTHTYPE_CP4D = 'cp4d'
    AUTHTYPE_VPC = 'vpc'
    AUTHTYPE_NOAUTH = 'noAuth'
    AUTHTYPE_UNKNOWN = 'unknown'

    @abstractmethod
    def authenticate(self, req: dict) -> None:
        """Perform the necessary authentication steps for the specified request.

        Attributes:
            req (dict): Will be modified to contain the appropriate authentication information.

        To be implemented by subclasses.
        """
        pass

    @abstractmethod
    def validate(self) -> None:
        """Validates the current set of configuration information in the Authenticator.

        Raises:
            ValueError: The configuration information is not valid for service operations.

        To be implemented by subclasses.
        """
        pass

    def authentication_type(self) -> str:
        """Returns the authenticator's type.  This method should be overridden by each authenticator implementation."""
        return self.AUTHTYPE_UNKNOWN
