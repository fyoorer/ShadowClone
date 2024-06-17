# coding: utf-8

# Copyright 2019, 2021 IBM All Rights Reserved.
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
# from ibm_cloud_sdk_core.authenticators import Authenticator
import datetime
import json as json_import
import re
import ssl
from os import getenv, environ, getcwd
from os.path import isfile, join, expanduser
from typing import List, Union
from urllib.parse import urlparse, parse_qs

from requests.adapters import HTTPAdapter
from urllib3.util.ssl_ import create_urllib3_context

import dateutil.parser as date_parser


class SSLHTTPAdapter(HTTPAdapter):
    """Wraps the original HTTP adapter and adds additional SSL context."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    # pylint: disable=arguments-differ
    def init_poolmanager(self, connections, maxsize, block):
        """Extends the parent's method by adding minimum SSL version to the args."""
        ssl_context = create_urllib3_context()
        ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        super().init_poolmanager(connections, maxsize, block, ssl_context=ssl_context)


def has_bad_first_or_last_char(val: str) -> bool:
    """Returns true if a string starts with any of: {," ; or ends with any of: },".

    Args:
        val: The string to be tested.

    Returns:
        Whether or not the string starts or ends with bad characters.
    """
    return val is not None and (val.startswith('{') or val.startswith('"') or val.endswith('}') or val.endswith('"'))


def remove_null_values(dictionary: dict) -> dict:
    """Create a new dictionary without keys mapped to null values.

    Args:
        dictionary: The dictionary potentially containing keys mapped to values of None.

    Returns:
        A dict with no keys mapped to None.
    """
    if isinstance(dictionary, dict):
        return {k: v for (k, v) in dictionary.items() if v is not None}
    return dictionary


def cleanup_values(dictionary: dict) -> dict:
    """Create a new dictionary with boolean values converted to strings.

    Ex. true -> 'true', false -> 'false'.
    { 'key': true } -> { 'key': 'true' }

    Args:
        dictionary: The dictionary with keys mapped to booleans.

    Returns:
        The dictionary with certain keys mapped to s and not booleans.
    """
    if isinstance(dictionary, dict):
        return {k: cleanup_value(v) for (k, v) in dictionary.items()}
    return dictionary


def cleanup_value(value: any) -> any:
    """Convert a boolean value to string."""
    if isinstance(value, bool):
        return 'true' if value else 'false'
    return value


def strip_extra_slashes(value: str) -> str:
    """Combine multiple trailing slashes to a single slash"""
    if value.endswith('//'):
        return value.rstrip('/') + '/'
    return value


def datetime_to_string(val: datetime.datetime) -> str:
    """Convert a datetime object to string.

    If the supplied datetime does not specify a timezone,
    it is assumed to be UTC.

    Args:
        val: The datetime object.

    Returns:
        datetime serialized to iso8601 format.
    """
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            return val.isoformat() + 'Z'
        val = val.astimezone(datetime.timezone.utc)
        return val.isoformat().replace('+00:00', 'Z')
    return val


def string_to_datetime(string: str) -> datetime.datetime:
    """De-serializes string to datetime.

    Args:
        string: string containing datetime in iso8601 format.

    Returns:
        the de-serialized string as a datetime object.
    """
    val = date_parser.parse(string)
    if val.tzinfo is not None:
        return val
    return val.replace(tzinfo=datetime.timezone.utc)


def string_to_datetime_list(string_list: List[str]) -> List[datetime.datetime]:
    """De-serializes each string in a list to a datetime.

    Args:
        string_list: list of strings containing datetime in iso8601 format.

    Returns:
        the de-serialized list of strings as a list of datetime objects.
    """
    if not isinstance(string_list, list):
        raise ValueError(
            "Invalid argument type: " + str(type(string_list)) + ". Argument string_list must be of type List[str]"
        )
    datetime_list = []
    for string_val in string_list:
        datetime_list.append(string_to_datetime(string_val))
    return datetime_list


def datetime_to_string_list(datetime_list: List[datetime.datetime]) -> List[str]:
    """Convert a list of datetime objects to a list of strings.

    Args:
        datetime_list: The list of datetime objects.

    Returns:
        list of datetimes serialized as strings in iso8601 format.
    """
    if not isinstance(datetime_list, list):
        raise ValueError(
            "Invalid argument type: "
            + str(type(datetime_list))
            + ". Argument datetime_list must be of type List[datetime.datetime]"
        )
    string_list = []
    for datetime_val in datetime_list:
        string_list.append(datetime_to_string(datetime_val))
    return string_list


def date_to_string(val: datetime.date) -> str:
    """Convert a date object to string.

    Args:
        val: The date object.

    Returns:
        date serialized to `YYYY-MM-DD` format.
    """
    if isinstance(val, datetime.date):
        return str(val)
    return val


def string_to_date(string: str) -> datetime.date:
    """De-serializes string to date.

    Args:
        string: string containing date in 'YYYY-MM-DD' format.

    Returns:
        the de-serialized string as a date object.
    """
    return date_parser.parse(string).date()


def get_query_param(url_str: str, param: str) -> str:
    """Return a query parameter value from url_str

    Args:
        url_str: the URL from which to extract the query
            parameter value
        param: the name of the query parameter whose value
            should be returned

    Returns:
        the value of the `param` query parameter as a string

    Raises:
        ValueError: if errors are encountered parsing `url_str`
    """
    if not url_str:
        return None
    url = urlparse(url_str)
    if not url.query:
        return None
    query = parse_qs(url.query, strict_parsing=True)
    values = query.get(param)
    return values[0] if values else None


def convert_model(val: any) -> dict:
    """Convert a model object into an equivalent dict.

    Arguments:
        val: A dict or a model object

    Returns:
        A dict representation of the input object.
    """
    if isinstance(val, dict):
        return val
    if hasattr(val, "to_dict"):
        return val.to_dict()
    # Consider raising a ValueError here in the next major release
    return val


def convert_list(val: Union[str, List[str]]) -> str:
    """Convert a list of strings into comma-separated string.

    Arguments:
        val: A string or list of strings

    Returns:
        A comma-separated string of the items in the input list.
    """
    if isinstance(val, str):
        return val
    if isinstance(val, list) and all(isinstance(x, str) for x in val):
        return ",".join(val)
    # Consider raising a ValueError here in the next major release
    return val


def read_external_sources(service_name: str) -> dict:
    """Look for external configuration of a service.

    Try to get config from external sources, with the following priority:
    1. Credentials file(ibm-credentials.env)
    2. Environment variables
    3. VCAP Services(Cloud Foundry)

    Args:
        service_name: The service name

    Returns:
        A dictionary containing relevant configuration for the service if found.
    """
    config = {}

    config = __read_from_credential_file(service_name)

    if not config:
        config = __read_from_env_variables(service_name)

    if not config:
        config = __read_from_vcap_services(service_name)

    return config


def __read_from_env_variables(service_name: str) -> dict:
    """Return a config object based on environment variables for a service.

    Args:
        service_name: The name of the service to look for in env variables.

    Returns:
        A set of service configuration key-value pairs.
    """
    config = {}
    for key, value in environ.items():
        _parse_key_and_update_config(config, service_name, key, value)
    return config


def __read_from_credential_file(service_name: str, *, separator: str = '=') -> dict:
    """Return a config object based on credentials file for a service.

    Args:
        service_name: The name of the service to look for in env variables.

    Keyword Args:
        separator: The character to split on to de-serialize a line into a key-value pair.

    Returns:
        A set of service configuration key-value pairs.
    """
    default_credentials_file_name = 'ibm-credentials.env'

    # 1. ${IBM_CREDENTIALS_FILE}
    credential_file_path = getenv('IBM_CREDENTIALS_FILE')

    # 2. <current-working-directory>/ibm-credentials.env
    if credential_file_path is None:
        file_path = join(getcwd(), default_credentials_file_name)
        if isfile(file_path):
            credential_file_path = file_path

    # 3. <user-home-directory>/ibm-credentials.env
    if credential_file_path is None:
        file_path = join(expanduser('~'), default_credentials_file_name)
        if isfile(file_path):
            credential_file_path = file_path

    config = {}
    if credential_file_path is not None:
        try:
            with open(credential_file_path, 'r', encoding='utf-8') as fobj:
                for line in fobj:
                    key_val = line.strip().split(separator, 1)
                    if len(key_val) == 2:
                        key = key_val[0]
                        value = key_val[1]
                        _parse_key_and_update_config(config, service_name, key, value)
        except OSError:
            # just absorb the exception and make sure we return an empty response
            config = {}

    return config


def _parse_key_and_update_config(config: dict, service_name: str, key: str, value: str) -> None:
    service_name = service_name.replace(' ', '_').replace('-', '_').upper()
    if key.startswith(service_name):
        config[key[len(service_name) + 1 :]] = value


def __read_from_vcap_services(service_name: str) -> dict:
    """Return a config object based on the vcap services environment variable.

    Args:
        service_name: The name of the service to look for in the vcap.

    Returns:
        A set of service configuration key-value pairs.
    """
    vcap_services = getenv('VCAP_SERVICES')
    vcap_service_credentials = {}
    if vcap_services:
        services = json_import.loads(vcap_services)
        for key in services.keys():
            for i in range(len(services[key])):
                if vcap_service_credentials and isinstance(vcap_service_credentials, dict):
                    break
                if services[key][i].get('name') == service_name:
                    vcap_service_credentials = services[key][i].get('credentials', {})
        if not vcap_service_credentials:
            if service_name in services.keys():
                service = services.get(service_name)
                if service:
                    vcap_service_credentials = service[0].get('credentials', {})

        if vcap_service_credentials and isinstance(vcap_service_credentials, dict):
            new_vcap_creds = {}
            # cf
            if vcap_service_credentials.get('username') and vcap_service_credentials.get('password'):
                new_vcap_creds['AUTH_TYPE'] = 'basic'
                new_vcap_creds['USERNAME'] = vcap_service_credentials.get('username')
                new_vcap_creds['PASSWORD'] = vcap_service_credentials.get('password')
                vcap_service_credentials = new_vcap_creds
            elif vcap_service_credentials.get('iam_apikey'):
                new_vcap_creds['AUTH_TYPE'] = 'iam'
                new_vcap_creds['APIKEY'] = vcap_service_credentials.get('iam_apikey')
                vcap_service_credentials = new_vcap_creds
            elif vcap_service_credentials.get('apikey'):
                new_vcap_creds['AUTH_TYPE'] = 'iam'
                new_vcap_creds['APIKEY'] = vcap_service_credentials.get('apikey')
                vcap_service_credentials = new_vcap_creds
    return vcap_service_credentials


# A regex that matches an "application/json" mimetype.
json_mimetype_pattern = re.compile('^application/json(\\s*;.*)?$')


def is_json_mimetype(mimetype: str) -> bool:
    """Returns true if 'mimetype' is a JSON-like mimetype, false otherwise.

    Args:
        mimetype: The mimetype to check.

    Returns:
        true if mimetype is a JSON-line mimetype, false otherwise.
    """
    return mimetype is not None and json_mimetype_pattern.match(mimetype) is not None
