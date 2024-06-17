# Copyright 2014 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# https://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.

# Copyright 2017 IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
import copy
import os

import ibm_botocore.session
from ibm_botocore.client import Config
from ibm_botocore.exceptions import DataNotFoundError, UnknownServiceError

import ibm_boto3
import ibm_boto3.utils
from ibm_boto3.exceptions import ResourceNotExistsError, UnknownAPIVersionError

from .resources.factory import ResourceFactory


class Session:
    """
    A session stores configuration state and allows you to create service
    clients and resources.

    :type aws_access_key_id: string
    :param aws_access_key_id: AWS access key ID

    :type aws_secret_access_key: string
    :param aws_secret_access_key: AWS secret access key

    :type aws_session_token: string
    :param aws_session_token: AWS temporary session token

    :type region_name: string
    :param region_name: Default region when creating new connections

    :type ibm_api_key_id: str
    :param ibm_api_key_id: IBM api key used for IAM authentication.

    :type ibm_service_instance_id: str
    :param ibm_service_instance_id: Service Instance ID used for
        PUT bucket and GET service requests.

    :type ibm_auth_endpoint: str
    :param ibm_auth_endpoint: URL used for IAM authentication.

    :type token_manager: TokenManager
    :param token_manager: custom token manager to use.

    :type auth_function: function
    :param auth_function: function that does custom authentication
        and returns json with token, refresh token, expiry time
        and token type.

    :type botocore_session: ibm_botocore.session.Session
    :param botocore_session: Use this Botocore session instead of creating
                             a new default one.

    :type profile_name: string
    :param profile_name: The name of a profile to use. If not given, then
                         the default profile is used.
    """
    def __init__(
        self,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        region_name=None,
        ibm_api_key_id=None,
        ibm_service_instance_id=None,
        ibm_auth_endpoint=None,
        auth_function=None,
        token_manager=None,
        botocore_session=None,
        profile_name=None,
    ):
        if botocore_session is not None:
            self._session = botocore_session
        else:
            # Create a new default session
            self._session = ibm_botocore.session.get_session()

        # Setup custom user-agent string if it isn't already customized
        if self._session.user_agent_name == 'ibm-cos-sdk-python-core':
            botocore_info = 'ibm-cos-sdk-python-core/{}'.format(
                self._session.user_agent_version
            )
            if self._session.user_agent_extra:
                self._session.user_agent_extra += ' ' + botocore_info
            else:
                self._session.user_agent_extra = botocore_info
            self._session.user_agent_name = 'ibm-cos-sdk-python'
            self._session.user_agent_version = ibm_boto3.__version__

        if profile_name is not None:
            self._session.set_config_variable('profile', profile_name)

        if ibm_api_key_id or auth_function or token_manager or aws_access_key_id or aws_secret_access_key or aws_session_token:
            self._session.set_credentials(
                access_key=aws_access_key_id, secret_key=aws_secret_access_key, token=aws_session_token,
                ibm_api_key_id=ibm_api_key_id, ibm_service_instance_id=ibm_service_instance_id,
                ibm_auth_endpoint=ibm_auth_endpoint,
                auth_function=auth_function, token_manager=token_manager
            )

        if region_name is not None:
            self._session.set_config_variable('region', region_name)

        self.resource_factory = ResourceFactory(
            self._session.get_component('event_emitter')
        )
        self._setup_loader()
        self._register_default_handlers()

    def __repr__(self):
        return '{}(region_name={})'.format(
            self.__class__.__name__,
            repr(self._session.get_config_variable('region')),
        )

    @property
    def profile_name(self):
        """
        The **read-only** profile name.
        """
        return self._session.profile or 'default'

    @property
    def region_name(self):
        """
        The **read-only** region name.
        """
        return self._session.get_config_variable('region')

    @property
    def events(self):
        """
        The event emitter for a session
        """
        return self._session.get_component('event_emitter')

    @property
    def available_profiles(self):
        """
        The profiles available to the session credentials
        """
        return self._session.available_profiles

    def _setup_loader(self):
        """
        Setup loader paths so that we can load resources.
        """
        self._loader = self._session.get_component('data_loader')
        self._loader.search_paths.append(
            os.path.join(os.path.dirname(__file__), 'data')
        )

    def get_available_services(self):
        """
        Get a list of available services that can be loaded as low-level
        clients via :py:meth:`Session.client`.

        :rtype: list
        :return: List of service names
        """
        return self._session.get_available_services()

    def get_available_resources(self):
        """
        Get a list of available services that can be loaded as resource
        clients via :py:meth:`Session.resource`.

        :rtype: list
        :return: List of service names
        """
        return self._loader.list_available_services(type_name='resources-1')

    def get_available_partitions(self):
        """Lists the available partitions

        :rtype: list
        :return: Returns a list of partition names (e.g., ["aws", "aws-cn"])
        """
        return self._session.get_available_partitions()

    def get_available_regions(
        self, service_name, partition_name='aws', allow_non_regional=False
    ):
        """Lists the region and endpoint names of a particular partition.

        :type service_name: string
        :param service_name: Name of a service to list endpoint for (e.g., s3).

        :type partition_name: string
        :param partition_name: Name of the partition to limit endpoints to.
            (e.g., aws for the public AWS endpoints, aws-cn for AWS China
            endpoints, aws-us-gov for AWS GovCloud (US) Endpoints, etc.)

        :type allow_non_regional: bool
        :param allow_non_regional: Set to True to include endpoints that are
             not regional endpoints (e.g., s3-external-1,
             fips-us-gov-west-1, etc).

        :return: Returns a list of endpoint names (e.g., ["us-east-1"]).
        """
        return self._session.get_available_regions(
            service_name=service_name,
            partition_name=partition_name,
            allow_non_regional=allow_non_regional,
        )

    def get_credentials(self):
        """
        Return the :class:`ibm_botocore.credentials.Credentials` object
        associated with this session.  If the credentials have not
        yet been loaded, this will attempt to load them.  If they
        have already been loaded, this will return the cached
        credentials.
        """
        return self._session.get_credentials()

    def get_partition_for_region(self, region_name):
        """Lists the partition name of a particular region.

        :type region_name: string
        :param region_name: Name of the region to list partition for (e.g.,
             us-east-1).

        :rtype: string
        :return: Returns the respective partition name (e.g., aws).
        """
        return self._session.get_partition_for_region(region_name)

    def client(
        self,
        service_name,
        region_name=None,
        api_version=None,
        use_ssl=True,
        verify=None,
        endpoint_url=None,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        ibm_api_key_id=None,
        ibm_service_instance_id=None,
        ibm_auth_endpoint=None,
        auth_function=None,
        token_manager=None,
        config=None,
    ):
        """
        Create a low-level service client by name.

        :type service_name: string
        :param service_name: The name of a service, e.g. 's3'. You can
            get a list of available services via
            :py:meth:`get_available_services`.

        :type region_name: string
        :param region_name: The name of the region associated with the client.
            A client is associated with a single region.

        :type api_version: string
        :param api_version: The API version to use.  By default, ibm_botocore will
            use the latest API version when creating a client.  You only need
            to specify this parameter if you want to use a previous API version
            of the client.

        :type use_ssl: boolean
        :param use_ssl: Whether or not to use SSL.  By default, SSL is used.
            Note that not all services support non-ssl connections.

        :type verify: boolean/string
        :param verify: Whether or not to verify SSL certificates.  By default
            SSL certificates are verified.  You can provide the following
            values:

            * False - do not validate SSL certificates.  SSL will still be
              used (unless use_ssl is False), but SSL certificates
              will not be verified.
            * path/to/cert/bundle.pem - A filename of the CA cert bundle to
              uses.  You can specify this argument if you want to use a
              different CA cert bundle than the one used by ibm_botocore.

        :type endpoint_url: string
        :param endpoint_url: The complete URL to use for the constructed
            client. Normally, ibm_botocore will automatically construct the
            appropriate URL to use when communicating with a service.  You
            can specify a complete URL (including the "http/https" scheme)
            to override this behavior.  If this value is provided,
            then ``use_ssl`` is ignored.

        :type aws_access_key_id: string
        :param aws_access_key_id: The access key to use when creating
            the client.  This is entirely optional, and if not provided,
            the credentials configured for the session will automatically
            be used.  You only need to provide this argument if you want
            to override the credentials used for this specific client.

        :type aws_secret_access_key: string
        :param aws_secret_access_key: The secret key to use when creating
            the client.  Same semantics as aws_access_key_id above.

        :type aws_session_token: string
        :param aws_session_token: The session token to use when creating
            the client.  Same semantics as aws_access_key_id above.

        :type ibm_api_key_id: str
        :param ibm_api_key_id: IBM api key used for IAM authentication.

        :type ibm_service_instance_id: str
        :param ibm_service_instance_id: Service Instance ID used for
            PUT bucket and GET service requests.

        :type ibm_auth_endpoint: str
        :param ibm_auth_endpoint: URL used for IAM authentication.

        :type token_manager: TokenManager
        :param token_manager: custom token manager to use.

        :type auth_function: function
        :param auth_function: function that does custom authentication
            and returns json with token, refresh token, expiry time
            and token type.

        :type config: ibm_botocore.client.Config
        :param config: Advanced client configuration options. If region_name
            is specified in the client config, its value will take precedence
            over environment variables and configuration values, but not over
            a region_name value passed explicitly to the method. See
            `ibm_botocore config documentation
            <https://botocore.readthedocs.io/en/stable/reference/config.html>`_
            for more details.

        :return: Service client instance

        """
        return self._session.create_client(
            service_name,
            region_name=region_name,
            api_version=api_version,
            use_ssl=use_ssl,
            verify=verify,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            ibm_api_key_id=ibm_api_key_id,
            ibm_service_instance_id=ibm_service_instance_id,
            ibm_auth_endpoint=ibm_auth_endpoint,
            auth_function=auth_function,
            token_manager=token_manager,
            config=config,
        )

    def resource(
        self,
        service_name,
        region_name=None,
        api_version=None,
        use_ssl=True,
        verify=None,
        endpoint_url=None,
        aws_access_key_id=None,
        aws_secret_access_key=None,
        aws_session_token=None,
        ibm_api_key_id=None,
        ibm_service_instance_id=None,
        ibm_auth_endpoint=None,
        auth_function=None,
        token_manager=None,
        config=None,
    ):
        """
        Create a resource service client by name.

        :type service_name: string
        :param service_name: The name of a service, e.g. 's3'.  You can
            get a list of available services via
            :py:meth:`get_available_resources`.

        :type region_name: string
        :param region_name: The name of the region associated with the client.
            A client is associated with a single region.

        :type api_version: string
        :param api_version: The API version to use.  By default, ibm_botocore will
            use the latest API version when creating a client.  You only need
            to specify this parameter if you want to use a previous API version
            of the client.

        :type use_ssl: boolean
        :param use_ssl: Whether or not to use SSL.  By default, SSL is used.
            Note that not all services support non-ssl connections.

        :type verify: boolean/string
        :param verify: Whether or not to verify SSL certificates.  By default
            SSL certificates are verified.  You can provide the following
            values:

            * False - do not validate SSL certificates.  SSL will still be
              used (unless use_ssl is False), but SSL certificates
              will not be verified.
            * path/to/cert/bundle.pem - A filename of the CA cert bundle to
              uses.  You can specify this argument if you want to use a
              different CA cert bundle than the one used by ibm_botocore.

        :type endpoint_url: string
        :param endpoint_url: The complete URL to use for the constructed
            client. Normally, ibm_botocore will automatically construct the
            appropriate URL to use when communicating with a service.  You
            can specify a complete URL (including the "http/https" scheme)
            to override this behavior.  If this value is provided,
            then ``use_ssl`` is ignored.

        :type aws_access_key_id: string
        :param aws_access_key_id: The access key to use when creating
            the client.  This is entirely optional, and if not provided,
            the credentials configured for the session will automatically
            be used.  You only need to provide this argument if you want
            to override the credentials used for this specific client.

        :type aws_secret_access_key: string
        :param aws_secret_access_key: The secret key to use when creating
            the client.  Same semantics as aws_access_key_id above.

        :type aws_session_token: string
        :param aws_session_token: The session token to use when creating
            the client.  Same semantics as aws_access_key_id above.

        :type ibm_api_key_id: string
        :param ibm_api_key_id: IBM api key used for IAM authentication.

        :type ibm_service_instance_id: string
        :param ibm_service_instance_id: Service Instance ID used for
            PUT bucket and GET service requests.

        :type ibm_auth_endpoint: string
        :param ibm_auth_endpoint: URL used for IAM authentication.

        :type token_manager: TokenManager
        :param token_manager: custom token manager to use.

        :type auth_function: function
        :param auth_function: function that does custom authentication
            and returns json with token, refresh token, expiry time
            and token type.

        :type config: ibm_botocore.client.Config
        :param config: Advanced client configuration options. If region_name
            is specified in the client config, its value will take precedence
            over environment variables and configuration values, but not over
            a region_name value passed explicitly to the method.  If
            user_agent_extra is specified in the client config, it overrides
            the default user_agent_extra provided by the resource API. See
            `ibm_botocore config documentation
            <https://botocore.readthedocs.io/en/stable/reference/config.html>`_
            for more details.

        :return: Subclass of :py:class:`~ibm_boto3.resources.base.ServiceResource`
        """
        try:
            resource_model = self._loader.load_service_model(
                service_name, 'resources-1', api_version
            )
        except UnknownServiceError:
            available = self.get_available_resources()
            has_low_level_client = (
                service_name in self.get_available_services()
            )
            raise ResourceNotExistsError(
                service_name, available, has_low_level_client
            )
        except DataNotFoundError:
            # This is because we've provided an invalid API version.
            available_api_versions = self._loader.list_api_versions(
                service_name, 'resources-1'
            )
            raise UnknownAPIVersionError(
                service_name, api_version, ', '.join(available_api_versions)
            )

        if api_version is None:
            # Even though ibm_botocore's load_service_model() can handle
            # using the latest api_version if not provided, we need
            # to track this api_version in ibm_boto3 in order to ensure
            # we're pairing a resource model with a client model
            # of the same API version.  It's possible for the latest
            # API version of a resource model in ibm_boto3 to not be
            # the same API version as a service model in ibm_botocore.
            # So we need to look up the api_version if one is not
            # provided to ensure we load the same API version of the
            # client.
            #
            # Note: This is relying on the fact that
            #   loader.load_service_model(..., api_version=None)
            # and loader.determine_latest_version(..., 'resources-1')
            # both load the same api version of the file.
            api_version = self._loader.determine_latest_version(
                service_name, 'resources-1'
            )

        # Creating a new resource instance requires the low-level client
        # and service model, the resource version and resource JSON data.
        # We pass these to the factory and get back a class, which is
        # instantiated on top of the low-level client.
        if config is not None:
            if config.user_agent_extra is None:
                config = copy.deepcopy(config)
                config.user_agent_extra = 'Resource'
        else:
            config = Config(user_agent_extra='Resource')
        client = self.client(
            service_name,
            region_name=region_name,
            api_version=api_version,
            use_ssl=use_ssl,
            verify=verify,
            endpoint_url=endpoint_url,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
            ibm_api_key_id=ibm_api_key_id,
            ibm_service_instance_id=ibm_service_instance_id,
            ibm_auth_endpoint=ibm_auth_endpoint,
            auth_function=auth_function,
            token_manager=token_manager,
            config=config,
        )
        service_model = client.meta.service_model

        # Create a ServiceContext object to serve as a reference to
        # important read-only information about the general service.
        service_context = ibm_boto3.utils.ServiceContext(
            service_name=service_name,
            service_model=service_model,
            resource_json_definitions=resource_model['resources'],
            service_waiter_model=ibm_boto3.utils.LazyLoadedWaiterModel(
                self._session, service_name, api_version
            ),
        )

        # Create the service resource class.
        cls = self.resource_factory.load_from_definition(
            resource_name=service_name,
            single_resource_json_definition=resource_model['service'],
            service_context=service_context,
        )

        return cls(client=client)

    def _register_default_handlers(self):

        # S3 customizations
        self._session.register(
            'creating-client-class.s3',
            ibm_boto3.utils.lazy_call(
                'ibm_boto3.s3.inject.inject_s3_transfer_methods'
            ),
        )
        self._session.register(
            'creating-resource-class.s3.Bucket',
            ibm_boto3.utils.lazy_call('ibm_boto3.s3.inject.inject_bucket_methods'),
        )
        self._session.register(
            'creating-resource-class.s3.Object',
            ibm_boto3.utils.lazy_call('ibm_boto3.s3.inject.inject_object_methods'),
        )
        self._session.register(
            'creating-resource-class.s3.ObjectSummary',
            ibm_boto3.utils.lazy_call(
                'ibm_boto3.s3.inject.inject_object_summary_methods'))
