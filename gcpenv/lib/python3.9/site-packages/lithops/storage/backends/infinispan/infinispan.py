#
# (C) Copyright IBM Corp. 2019
# (C) Copyright RedHat Inc. 2021
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
import shutil
import logging
import requests
import json
import base64
import io
from requests.auth import HTTPBasicAuth
from requests.auth import HTTPDigestAuth
from lithops.constants import STORAGE_CLI_MSG
from lithops.storage.utils import StorageNoSuchKeyError

logger = logging.getLogger(__name__)


class InfinispanBackend:
    """
    Infinispan backend
    """

    def __init__(self, infinispan_config):
        logger.debug("Creating Infinispan storage client")
        self.infinispan_config = infinispan_config
        self.mech = infinispan_config.get('auth_mech', 'DIGEST')
        if self.mech == 'DIGEST':
            self.auth = HTTPDigestAuth(infinispan_config.get('username'),
                                       infinispan_config.get('password'))
        elif self.mech == 'BASIC':
            self.auth = HTTPBasicAuth(infinispan_config.get('username'),
                                       infinispan_config.get('password'))
        self.endpoint = infinispan_config.get('endpoint')
        self.cache_names = infinispan_config.get('cache_names', ['storage'])
        self.cache_type = infinispan_config.get('cache_type', 'org.infinispan.DIST_SYNC')
        self.infinispan_client = requests.session()

        self.__is_server_version_supported()
        self.caches = {}
        for cache_name in self.cache_names:
            self.__create_cache(cache_name, self.cache_type)

        self.headers = {"Content-Type": "application/octet-stream",
                        "Key-Content-Type": "application/octet-stream;encoding=base64"}

        msg = STORAGE_CLI_MSG.format('Infinispan')
        logger.info("{} - Endpoint: {}".format(msg, self.endpoint))

    def __create_cache(self, cache_name, cache_type):
        url = self.endpoint + '/rest/v2/caches/' + cache_name
        res = self.infinispan_client.head(url, auth=self.auth)

        if res.status_code == 404:
            logger.debug('going to create new Infinispan cache {}'.format(cache_name))
            url = self.endpoint+'/rest/v2/caches/'+cache_name+'?template='+cache_type
            res = self.infinispan_client.post(url, auth=self.auth)
            logger.debug('New Infinispan cache {} created with '
                         'status {}'.format(cache_name, res.status_code))

    def __key_url(self, bucket_name, key):
        keySafeEncodedBytes = base64.urlsafe_b64encode(key.encode("utf-8"))
        keySafeEncodedStr = str(keySafeEncodedBytes, "utf-8")
        url = self.endpoint + '/rest/v2/caches/' + bucket_name + '/' + keySafeEncodedStr
        return url

    def __is_server_version_supported(self):
        url = self.endpoint + '/rest/v2/cache-managers/default'
        res = self.infinispan_client.get(url, auth=self.auth)
        json_resp = json.loads(res.content.decode('utf-8'))
        server_version = json_resp['version'].split('.')
        if (int(server_version[0]) < 10 or (int(server_version[0]) == 10 and int(server_version[1]) < 1)):
            raise Exception('Infinispan versions 10.1 and up supported')

    def get_client(self):
        """
        Get infinispan client.
        :return: infinispan_client
        """
        return self.infinispan_client

    def put_object(self, bucket_name, key, data):
        """
        Put an object in Infinispan. Override the object if the key already exists.
        :param key: key of the object.
        :param data: data of the object
        :type data: str/bytes
        :return: None
        """
        url = self.__key_url(bucket_name, key)
        resp = self.infinispan_client.put(url, data=data,
                                          auth=self.auth,
                                          headers=self.headers)
        logger.debug(resp)

    def get_object(self, bucket_name, key, stream=False, extra_get_args={}):
        """
        Get object from COS with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """
        url = self.__key_url(bucket_name, key)
        res = self.infinispan_client.get(url, headers=self.headers, auth=self.auth)
        data = res.content
        if data is None or len(data) == 0:
            raise StorageNoSuchKeyError(bucket_name, key)
        if 'Range' in extra_get_args:
            byte_range = extra_get_args['Range'].replace('bytes=', '')
            first_byte, last_byte = map(int, byte_range.split('-'))
            data = data[first_byte:last_byte+1]
        if stream:
            return io.BytesIO(data)
        return data

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

    def head_object(self, bucket_name, key):
        """
        Head object from COS with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """
        obj = self.get_object(bucket_name, key)
        if obj is None:
            raise StorageNoSuchKeyError(bucket=bucket_name, key=key)
        return {'content-length': str(len(obj))}

    def delete_object(self, bucket_name, key):
        """
        Delete an object from storage.
        :param bucket: bucket name
        :param key: data key
        """
        url = self.__key_url(bucket_name, key)
        return self.infinispan_client.delete(url, headers=self.headers, auth=self.auth)

    def delete_objects(self, bucket_name, key_list):
        """
        Delete a list of objects from storage.
        :param bucket: bucket name
        :param key_list: list of keys
        """
        result = []
        for key in key_list:
            self.delete_object(bucket_name, key)
        return result

    def head_bucket(self, bucket_name):
        """
        Head bucket from COS with a name. Throws StorageNoSuchKeyError if the given bucket does not exist.
        :param bucket_name: name of the bucket
        :return: Metadata of the bucket
        :rtype: str/bytes
        """
        raise NotImplementedError

    def list_objects(self, bucket_name, prefix=None, match_pattern = None):
        """
        Return a list of objects for the given bucket and prefix.
        :param bucket_name: Name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of objects in bucket that match the given prefix.
        :rtype: list of str
        """
        url = self.endpoint + '/rest/v2/caches/' + bucket_name + '?action=keys'
        res = self.infinispan_client.get(url, auth=self.auth)
        data = res.content
        if data is None:
            return None
        j = json.loads(data)
        result = []
        if prefix is None:
            pref = ""
        else:
            pref = prefix
        for k in j:
            if len(k) > 0:
                key = k
                if key.startswith(pref):
                    h = self.get_object(bucket_name, key)
                    d = {'Key': key, 'Size': len(h)}
                    result.append(d)
        return result

    def list_keys(self, bucket_name, prefix=None):
        """
        Return a list of keys for the given prefix.
        :param bucket_name: Name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of keys in bucket that match the given prefix.
        :rtype: list of str
        """
        url = self.endpoint + '/rest/v2/caches/' + bucket_name + '?action=keys'
        res = self.infinispan_client.get(url, auth=self.auth)
        data = res.content
        if data is None:
            return None
        j = json.loads(data)
        result = []
        if prefix is None:
            pref = ""
        else:
            pref = prefix
        for k in j:
            if len(k) > 0:
                key = k
                if key.startswith(pref):
                    result.append(k)
        return result
