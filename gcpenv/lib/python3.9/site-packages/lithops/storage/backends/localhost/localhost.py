#
# (C) Copyright Cloudlab URV 2020
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
import glob
import shutil
import logging
from lithops.storage.utils import StorageNoSuchKeyError
from lithops.constants import LITHOPS_TEMP_DIR
from lithops.constants import STORAGE_CLI_MSG


logger = logging.getLogger(__name__)


class LocalhostStorageBackend:
    """
    A wrap-up around Localhost filesystem APIs.
    """

    def __init__(self, localhost_config):
        logger.debug("Creating Localhost storage client")
        self.localhost_config = localhost_config

        logger.info(STORAGE_CLI_MSG.format('Localhost storage'))

    def get_client(self):
        # Simulate boto3 client
        class LocalhostBoto3Client():
            def __init__(self, backend):
                self.backend = backend

            def put_object(self, Bucket, Key, Body, **kwargs):
                self.backend.put_object(Bucket, Key, Body)

            def get_object(self, Bucket, Key, **kwargs):
                body = self.backend.get_object(Bucket, Key, stream=True, extra_get_args=kwargs)
                return {'Body': body}

            def list_objects(self, Bucket, Prefix=None, **kwargs):
                return self.backend.list_objects(Bucket, Prefix)

            def list_objects_v2(self, Bucket, Prefix=None, **kwargs):
                return self.backend.list_objects(Bucket, Prefix)

        return LocalhostBoto3Client(self)

    def put_object(self, bucket_name, key, data):
        """
        Put an object in localhost filesystem.
        Override the object if the key already exists.
        :param key: key of the object.
        :param data: data of the object
        :type data: str/bytes
        :return: None
        """
        data_type = type(data)
        file_path = os.path.join(LITHOPS_TEMP_DIR, bucket_name, key)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        if data_type == bytes:
            with open(file_path, "wb") as f:
                f.write(data)
        elif hasattr(data, 'read'):
            with open(file_path, "wb") as f:
                shutil.copyfileobj(data, f, 1024 * 1024)
        else:
            with open(file_path, "w") as f:
                f.write(data)

    def get_object(self, bucket_name, key, stream=False, extra_get_args={}):
        """
        Get object from localhost filesystem with a key.
        Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: Data of the object
        :rtype: str/bytes
        """
        buffer = None
        try:
            file_path = os.path.join(LITHOPS_TEMP_DIR, bucket_name, key)
            with open(file_path, "rb") as f:
                if 'Range' in extra_get_args:
                    byte_range = extra_get_args['Range'].replace('bytes=', '')
                    first_byte, last_byte = map(int, byte_range.split('-'))
                    f.seek(first_byte)
                    buffer = io.BytesIO(f.read(last_byte - first_byte + 1))
                else:
                    buffer = io.BytesIO(f.read())
            if stream:
                return buffer
            else:
                return buffer.read()
        except Exception:
            raise StorageNoSuchKeyError(os.path.join(LITHOPS_TEMP_DIR, bucket_name), key)

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
        Head object from local filesystem with a key.
        Throws StorageNoSuchKeyError if the given key does not exist.
        :param key: key of the object
        :return: metadata of the object
        """
        file_path = os.path.join(LITHOPS_TEMP_DIR, bucket_name, key)
        if os.path.isfile(file_path):
            # Imitate the COS/S3 response
            return {
                'content-length': str(os.stat(file_path).st_size)
            }

        raise StorageNoSuchKeyError(os.path.join(LITHOPS_TEMP_DIR, bucket_name), key)

    def delete_object(self, bucket_name, key):
        """
        Delete an object from storage.
        :param bucket: bucket name
        :param key: data key
        """
        base_dir = os.path.join(LITHOPS_TEMP_DIR, bucket_name, '')
        file_path = os.path.join(base_dir, key)
        try:
            if os.path.exists(file_path):
                os.remove(file_path)

            # Recursively clean up empty parent directories, but not the bucket itself
            parent_dir = os.path.dirname(file_path)
            while parent_dir.startswith(base_dir) and len(parent_dir) > len(base_dir):
                try:
                    os.rmdir(parent_dir)
                    parent_dir = os.path.abspath(os.path.join(parent_dir, '..'))
                except OSError:
                    break
        except Exception:
            pass

    def delete_objects(self, bucket_name, key_list):
        """
        Delete a list of objects from storage.
        :param bucket: bucket name
        :param key_list: list of keys
        """
        dirs = set()
        for key in key_list:
            file_dir = os.path.dirname(key)
            dirs.add(file_dir)
            # dirs.add("/".join(file_dir.split("/", 2)[:2]))
            self.delete_object(bucket_name, key)

    def head_bucket(self, bucket_name):
        """
        Head localhost dir with a name.
        Throws StorageNoSuchKeyError if the given bucket does not exist.
        :param bucket_name: name of the bucket
        """
        if os.path.isdir(os.path.join(LITHOPS_TEMP_DIR, bucket_name)):
            return {'ResponseMetadata': {'HTTPStatusCode': 200}}
        else:
            raise StorageNoSuchKeyError(os.path.join(LITHOPS_TEMP_DIR, bucket_name), '')

    def list_objects(self, bucket_name, prefix=None, match_pattern = None):
        """
        Return a list of objects for the prefix.
        :param bucket_name: Name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of objects in bucket that match the given prefix.
        :rtype: list of str
        """
        obj_list = []
        base_dir = os.path.join(LITHOPS_TEMP_DIR, bucket_name, '')

        for key in self.list_keys(bucket_name, prefix):
            file_name = os.path.join(base_dir, key)
            size = os.stat(file_name).st_size
            obj_list.append({'Key': key, 'Size': size})

        return obj_list

    def list_keys(self, bucket_name, prefix=None):
        """
        Return a list of keys for the given prefix.
        :param bucket_name: Name of the bucket.
        :param prefix: Prefix to filter object names.
        :return: List of keys in bucket that match the given prefix.
        :rtype: list of str
        """
        key_list = []
        base_dir = os.path.join(LITHOPS_TEMP_DIR, bucket_name, '')

        if prefix:
            if prefix.endswith('/'):
                roots = [os.path.join(base_dir, prefix, '**')]
            else:
                roots = [
                    os.path.join(base_dir, prefix + '*'),
                    os.path.join(base_dir, prefix + '*', '**'),
                ]
        else:
            roots = [os.path.join(base_dir, '**')]

        for root in roots:
            for file_name in glob.glob(root, recursive=True):
                if os.path.isfile(file_name):
                    key_list.append(file_name.replace(base_dir, '').replace('\\', '/'))

        return key_list
