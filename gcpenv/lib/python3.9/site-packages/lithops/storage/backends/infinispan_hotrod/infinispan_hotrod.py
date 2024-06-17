#
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
import io
import shutil
import logging
import requests
from requests.auth import HTTPDigestAuth
from lithops.constants import STORAGE_CLI_MSG
from lithops.storage.utils import StorageNoSuchKeyError
from Infinispan import Infinispan
logger = logging.getLogger(__name__)


class InfinispanHotrodBackend:
    """
    Infinispan Hotrod backend
    """

    def __init__(self, infinispan_config):
        logger.debug("Creating Infinispan Hotrod storage client")
        self.infinispan_config = infinispan_config
        conf = Infinispan.Configuration()
        connConf = infinispan_config.get('endpoint').split(":")
        conf.addServer(connConf[0], int(connConf[1]) if len(connConf) > 1 else 11222)
        conf.setProtocol("2.8")
        conf.setSasl("DIGEST-MD5", "node0", infinispan_config.get('username'), infinispan_config.get('password'))
        self.conf = conf
        self.cacheManager = Infinispan.RemoteCacheManager(conf)
        self.cacheManager.start()
        self.cacheManagerAdmin = Infinispan.RemoteCacheManagerAdmin(self.cacheManager)
        self.basicAuth = HTTPDigestAuth(infinispan_config.get('username'),
                                        infinispan_config.get('password'))
        self.cache_names = infinispan_config.get('cache_names', ['storage'])
        self.cache_type = infinispan_config.get('cache_type', 'org.infinispan.DIST_SYNC')
        self.infinispan_client = requests.session()

        self.caches = {}
        for cache_name in self.cache_names:
            self.__create_cache(cache_name, self.cache_type)

        msg = STORAGE_CLI_MSG.format('Infinispan_hotrod')
        logger.info("{} - Endpoint: {}".format(msg, self.endpoint))

    def __create_cache(self, cache_name, cache_type):
            self.caches[cache_name] = self.cacheManagerAdmin.getOrCreateCache(cache_name, cache_type)

    def __key(self, key):
        return key

    def put_object(self, bucket_name, key, data):
        """
        Put an object in Infinispan. Override the object if the key already exists.
        :param key: key of the object.
        :param data: data of the object
        :type data: str/bytes/io.BytesIO
        :return: None
        """
        keyEncoded = self.__key(key)
        keyVect = Infinispan.Util.fromString(keyEncoded)
        if isinstance(data, str):
            dataVec = Infinispan.Util.fromString(data)
        elif isinstance(data, io.BytesIO):
            r = data.read()
            dataVec = Infinispan.UCharVector(r)
        elif isinstance(data, bytes):
            dataVec = Infinispan.UCharVector(data)
        resp = self.caches[bucket_name].put(keyVect, dataVec)
        logger.debug(resp)

    def get_object(self, bucket_name, key, stream=False, extra_get_args={}):
        """
        Get object from COS with a key. Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """
        keyEncoded = self.__key(key)
        keyVect = Infinispan.Util.fromString(keyEncoded)
        resp = self.caches[bucket_name].get(keyVect)
        if resp is None:
            raise StorageNoSuchKeyError(bucket=bucket_name, key=key)
        r = Infinispan.pvuc_value(resp)
        b = bytes(r)
        if 'Range' in extra_get_args:
            byte_range = extra_get_args['Range'].replace('bytes=', '')
            first_byte, last_byte = map(int, byte_range.split('-'))
            b = b[first_byte:last_byte+1]
        if stream:
            return io.BytesIO(b)
        return b

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
        fullKey = self.__key(key)
        keyVect = Infinispan.Util.fromString(fullKey)
        obj = self.caches[bucket_name].get(keyVect)
        if obj is None:
            raise StorageNoSuchKeyError(bucket=bucket_name, key=key)
        return {'content-length': str(obj.size())}

    def delete_object(self, bucket_name, key):
        """
        Delete an object from storage.
        :param bucket: bucket name
        :param key: data key
        """
        fullKey = self.__key(key)
        self.caches[bucket_name].remove(Infinispan.Util.fromString(fullKey))
        return None

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
        keyListAsVec = self.caches[bucket_name].keys()
        keyList = []
        if prefix is None:
            pref = ""
        else:
            pref = prefix
        for k in keyListAsVec:
            if len(k) > 0:
                if Infinispan.Util.toString(k).startswith(pref):
                    o = self.caches[bucket_name].get(k)
                    if o is not None:
                        size = len(self.caches[bucket_name].get(k))
                        keyList.append({'Key': Infinispan.Util.toString(k), 'Size': size})
        return keyList

    def list_keys(self, bucket_name, prefix=None):
        """
        Return a list of keys for the given prefix.
        :param bucket_name: Name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of keys in bucket that match the given prefix.
        :rtype: list of str
        """
        keyListAsVec = self.caches[bucket_name].keys()
        keyList = []
        if prefix is None:
            pref = ""
        else:
            pref = prefix
        for k in keyListAsVec:
            if len(k) > 0:
                if Infinispan.Util.toString(k).startswith(pref):
                    keyList.append(Infinispan.Util.toString(k))
        return keyList
