#
# (C) Copyright IBM Corp. 2020
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import json
import shutil
import logging
import requests
from lithops.storage.utils import StorageNoSuchKeyError
from lithops.utils import sizeof_fmt
from lithops.constants import STORAGE_CLI_MSG

logger = logging.getLogger(__name__)


class StorageBackend:
    """
    A wrap-up around OpenStack Swift APIs.
    """

    def __init__(self, swift_config):
        logger.debug("Creating OpenStack Swift client")
        self.auth_url = swift_config['swift_auth_url']
        self.user_id = swift_config['swift_user_id']
        self.project_id = swift_config['swift_project_id']
        self.password = swift_config['swift_password']
        self.region = swift_config['swift_region']
        self.endpoint = None

        if 'token' in swift_config:
            self.token = swift_config['token']
            self.endpoint = swift_config['endpoint']
        else:
            self.token = self.generate_swift_token()
            swift_config['token'] = self.token
            swift_config['endpoint'] = self.endpoint

        self.session = requests.session()
        self.session.headers.update({'X-Auth-Token': self.token})
        adapter = requests.adapters.HTTPAdapter(pool_maxsize=64, max_retries=3)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

        msg = STORAGE_CLI_MSG.format('OpenStack Swift')
        logger.info("{} - Region: {}".format(msg, self.region))

    def generate_swift_token(self):
        """
        Generates new token for accessing to Swift.
        :return: token
        """
        url = self.auth_url+"/v3/auth/tokens"
        headers = {'Content-Type': 'application/json'}
        data = {"auth": {"identity": {"methods": ["password"],
                                      "password": {"user": {"id": self.user_id, "password": self.password}}},
                         "scope": {"project": {"id": self.project_id}}}}
        json_data = json.dumps(data)

        r = requests.post(url, data=json_data, headers=headers)

        if r.status_code == 201:
            backend_info = json.loads(r.text)

            for service in backend_info['token']['catalog']:
                if service['name'] == 'swift':
                    for endpoint in service['endpoints']:
                        if endpoint['region'] == self.region:
                            if endpoint['interface'] == 'public':
                                self.endpoint = endpoint['url'].replace('https:', 'http:')

            if not self.endpoint:
                raise Exception('Invalid region name')

            return r.headers['X-Subject-Token']
        else:
            message = json.loads(r.text)['error']['message']
            raise Exception("{} - {} - {}".format(r.status_code, r.reason, message))

    def put_object(self, container_name, key, data):
        """
        Put an object in Swift. Override the object if the key already exists.
        :param key: key of the object.
        :param data: data of the object
        :type data: str/bytes
        :return: None
        """
        url = '/'.join([self.endpoint, container_name, key])
        try:
            res = self.session.put(url, data=data)
            status = 'OK' if res.status_code == 201 else 'Error'
            try:
                logger.debug('PUT Object {} - Size: {} - {}'.format(key, sizeof_fmt(len(data)), status))
            except Exception:
                logger.debug('PUT Object {} - {}'.format(key, status))
        except Exception as e:
            print(e)

    def get_object(self, container_name, key, stream=False, extra_get_args={}):
        """
        Get object from Swift with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """
        if not container_name:
            container_name = self.storage_container
        url = '/'.join([self.endpoint, container_name, key])
        headers = {'X-Auth-Token': self.token}
        headers.update(extra_get_args)
        try:
            res = self.session.get(url, headers=headers, stream=stream)
            if res.status_code == 200 or res.status_code == 206:
                if stream:
                    data = res.raw
                else:
                    data = res.content
                return data
            elif res.status_code == 404:
                raise StorageNoSuchKeyError(container_name, key)
            else:
                raise Exception('{} - {}'.format(res.status_code, key))
        except StorageNoSuchKeyError:
            raise StorageNoSuchKeyError(container_name, key)
        except Exception as e:
            print(e)
            raise StorageNoSuchKeyError(container_name, key)

    def upload_file(self, file_name, bucket, key=None, extra_args={}):
        """Upload a file

        :param file_name: File to upload
        :param bucket: Bucket to upload to
        :param key: S3 object name. If not specified then file_name is used
        :return: True if file was uploaded, else False
        """
        # If S3 key was not specified, use file_name
        if key is None:
            key = os.path.basename(file_name)

        # Upload the file
        try:
            with open(file_name, 'rb') as in_file:
                self.put_object(bucket, key, in_file)
        except Exception as e:
            logging.error(e)
            return False
        return True

    def download_file(self, bucket, key, file_name=None, extra_args={}):
        """Download a file

        :param bucket: Bucket to download from
        :param key: S3 object name. If not specified then file_name is used
        :param file_name: File to upload
        :return: True if file was downloaded, else False
        """
        # If file_name was not specified, use S3 key
        if file_name is None:
            file_name = key

        # Download the file
        try:
            dirname = os.path.dirname(file_name)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname)
            with open(file_name, 'wb') as out:
                data_stream = self.get_object(bucket, key, stream=True)
                shutil.copyfileobj(data_stream, out)
        except Exception as e:
            logging.error(e)
            return False
        return True

    def head_object(self, container_name, key):
        """
        Head object from Swift with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """
        url = '/'.join([self.endpoint, container_name, key])
        try:
            res = self.session.head(url)
            if res.status_code == 200:
                return res.headers
            elif res.status_code == 404:
                raise StorageNoSuchKeyError(container_name, key)
            else:
                raise Exception('{} - {}'.format(res.status_code, key))
        except Exception as e:
            raise StorageNoSuchKeyError(container_name, key)

    def delete_object(self, container_name, key):
        """
        Delete an object from Swift.
        :param bucket: bucket name
        :param key: data key
        """
        url = '/'.join([self.endpoint, container_name, key])
        return self.session.delete(url)

    def delete_objects(self, container_name, key_list):
        """
        Delete a list of objects from Swift.
        :param bucket: bucket name
        :param key: data key
        """
        headers={'X-Auth-Token': self.token,
                 'X-Bulk-Delete': 'True'}

        keys_to_delete = []
        for key in key_list:
            keys_to_delete.append('/{}/{}'.format(container_name, key))

        keys_to_delete = '\n'.join(keys_to_delete)
        url = '/'.join([self.endpoint, '?bulk-delete'])
        return self.session.delete(url, data=keys_to_delete, headers=headers)

    def list_objects(self, container_name, prefix='', match_pattern = None):
        """
        Lists the objects in a bucket. Throws StorageNoSuchKeyError if the given bucket does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """
        if prefix:
            url = '/'.join([self.endpoint, container_name, '?format=json&prefix='+prefix])
        else:
            url = '/'.join([self.endpoint, container_name, '?format=json'])
        try:
            res = self.session.get(url)
            objects = res.json()

            # TODO: Adapt to Key and Size
            return objects
        except Exception as e:
            raise e

    def list_keys(self, container_name, prefix):
        """
        Return a list of keys for the given prefix.
        :param prefix: Prefix to filter object names.
        :return: List of keys in bucket that match the given prefix.
        :rtype: list of str
        """
        try:
            objects = self.list_objects(container_name, prefix)
            object_keys = [r['name'] for r in objects]
            return object_keys
        except Exception as e:
            raise(e)
