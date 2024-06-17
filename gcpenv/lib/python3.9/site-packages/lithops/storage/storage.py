
# (C) Copyright IBM Corp. 2020
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
import json
import logging
import itertools
import importlib
from typing import Optional, List, Union, Tuple, Dict, TextIO, BinaryIO

from lithops.constants import CACHE_DIR, RUNTIMES_PREFIX, JOBS_PREFIX, TEMP_PREFIX
from lithops.utils import is_lithops_worker
from lithops.storage import utils
from lithops.config import extract_storage_config, default_storage_config

logger = logging.getLogger(__name__)


RUNTIME_META_CACHE = {}


class Storage:
    """
    An Storage object is used by partitioner and other components to access
    underlying storage backend without exposing the the implementation details.
    """
    def __init__(self, config=None, backend=None, storage_config=None):
        """ Creates an Storage instance

        :param config: lithops configuration dict
        :param backend: storage backend name
        :param storage_config: storage configuration dict

        :return: Storage instance.
        """

        if storage_config:
            self.config = storage_config
        else:
            storage_config = default_storage_config(config, backend)
            self.config = extract_storage_config(storage_config)

        self.backend = self.config['backend']
        self.bucket = self.config['bucket']

        try:
            module_location = f'lithops.storage.backends.{self.backend}'
            sb_module = importlib.import_module(module_location)
            StorageBackend = getattr(sb_module, 'StorageBackend')
            self.storage_handler = StorageBackend(self.config[self.backend])
        except Exception as e:
            logger.error("An exception was produced trying to create the "
                         f"'{self.backend}' storage backend")
            raise e

        self._created_cobjects_n = itertools.count()

    def get_client(self) -> object:
        """
        Retrieves the underlying storage client.

        :return: Storage backend client
        """
        return self.storage_handler.get_client()

    def get_storage_config(self) -> Dict:
        """
        Retrieves the configuration of this storage handler.

        :return: Storage configuration
        """
        return self.config

    def put_object(self, bucket: str, key: str, body: Union[str, bytes, TextIO, BinaryIO]):
        """
        Adds an object to a bucket of the storage backend.

        :param bucket: Name of the bucket
        :param key: Key of the object
        :param body: Object data
        """
        return self.storage_handler.put_object(bucket, key, body)

    def get_object(self, bucket: str, key: str,
                   stream: Optional[bool] = False,
                   extra_get_args: Optional[Dict] = {}) -> Union[str, bytes, TextIO, BinaryIO]:
        """
        Retrieves objects from the storage backend.

        :param bucket: Name of the bucket
        :param key: Key of the object
        :param stream: Get the object data or a file-like object
        :param extra_get_args: Extra get arguments to be passed to the underlying backend implementation (dict). For example, to specify the byte-range to read: ``extra_get_args={'Range': 'bytes=0-100'}``.

        :return: Object, as a binary array or as a file-like stream if parameter `stream` is enabled
        """
        return self.storage_handler.get_object(bucket, key, stream, extra_get_args)

    def upload_file(self, file_name: str, bucket: str, key: Optional[str] = None,
                    extra_args: Optional[Dict] = {}) -> Union[str, bytes, TextIO, BinaryIO]:
        """
        Upload a file to a bucket of the storage backend. (Multipart upload)

        :param file_name: Name of the file to upload
        :param bucket: Name of the bucket
        :param key: Key of the object
        :param extra_args: Extra get arguments to be passed to the underlying backend implementation (dict).
        """
        return self.storage_handler.upload_file(file_name, bucket, key, extra_args)

    def download_file(self, bucket: str, key: str, file_name: Optional[str] = None,
                      extra_args: Optional[Dict] = {}) -> Union[str, bytes, TextIO, BinaryIO]:
        """
        Download a file from the storage backend. (Multipart download)

        :param bucket: Name of the bucket
        :param key: Key of the object
        :param file_name: Name of the file to save the object data
        :param extra_args: Extra get arguments to be passed to the underlying backend implementation (dict).

        :return: Object, as a binary array or as a file-like stream if parameter `stream` is enabled
        """
        return self.storage_handler.download_file(bucket, key, file_name, extra_args)

    def head_object(self, bucket: str, key: str) -> Dict:
        """
        The HEAD operation retrieves metadata from an object without returning the object itself. This operation is
        useful if you're only interested in an object's metadata.

        :param bucket: Name of the bucket
        :param key: Key of the object

        :return: Object metadata
        """
        return self.storage_handler.head_object(bucket, key)

    def delete_object(self, bucket: str, key: str):
        """
        Removes objects from the storage backend.

        :param bucket: Name of the bucket
        :param key: Key of the object
        """
        return self.storage_handler.delete_object(bucket, key)

    def delete_objects(self, bucket: str, key_list: List[str]):
        """
        This operation enables you to delete multiple objects from a bucket using a single HTTP request.
        If you know the object keys that you want to delete, then this operation provides a suitable alternative
        to sending individual delete requests, reducing per-request overhead.

        :param bucket: Name of the bucket
        :param key_list: List of object keys
        """
        return self.storage_handler.delete_objects(bucket, key_list)

    def head_bucket(self, bucket: str) -> Dict:
        """
        This operation is useful to determine if a bucket exists and you have permission to access it.
        The operation returns a 200 OK if the bucket exists and you have permission to access it.
        Otherwise, the operation might return responses such as 404 Not Found and 403 Forbidden.

        :param bucket: Name of the bucket

        :return: Request response
        """
        return self.storage_handler.head_bucket(bucket)

    def list_objects(self, bucket: str, prefix: Optional[str] = None, match_pattern: Optional[str] = None) -> List[Tuple[str, int]]:
        """
        Returns all of the object keys in a bucket. For each object, the list contains the name
        of the object (key) and the size.

        :param bucket: Name of the bucket
        :param prefix: Key prefix for filtering

        :return: List of tuples containing the object key and size in bytes
        """

        return self.storage_handler.list_objects(bucket, prefix, match_pattern)

    def list_keys(self, bucket, prefix=None) -> List[str]:
        """
        Similar to list_objects(), it returns all of the object keys in a bucket.
        For each object, the list contains only the names of the objects (keys).

        :param bucket: Name of the bucket
        :param prefix: Key prefix for filtering

        :return: List of object keys
        """
        return self.storage_handler.list_keys(bucket, prefix)

    def put_cloudobject(self, body: Union[str, bytes, TextIO, BinaryIO],
                        bucket: Optional[str] = None, key: Optional[str] = None) -> utils.CloudObject:
        """
        Put a CloudObject into storage.

        :param body: Data content, can be a string or byte array or a text/bytes file-like object
        :param bucket: Destination bucket
        :param key: Destination key

        :return: CloudObject instance
        """
        prefix = os.environ.get('__LITHOPS_SESSION_ID', '')
        coid = hex(next(self._created_cobjects_n))[2:]
        coname = 'cloudobject_{}'.format(coid)
        name = '/'.join([prefix, coname]) if prefix else coname
        key = key or '/'.join([TEMP_PREFIX, name])
        bucket = bucket or self.bucket
        self.storage_handler.put_object(bucket, key, body)

        return utils.CloudObject(self.backend, bucket, key)

    def get_cloudobject(self, cloudobject: utils.CloudObject,
                        stream: Optional[bool] = False) -> Union[str, bytes, TextIO, BinaryIO]:
        """
        Get a CloudObject's content from storage.

        :param cloudobject: CloudObject instance
        :param stream: Get the object data or a file-like object

        :return: Cloud object content
        """
        if cloudobject.backend == self.backend:
            bucket = cloudobject.bucket
            key = cloudobject.key
            return self.storage_handler.get_object(bucket, key, stream=stream)
        else:
            raise Exception("CloudObject: Invalid Storage backend")

    def delete_cloudobject(self, cloudobject: utils.CloudObject):
        """
        Delete a CloudObject from storage.

        :param cloudobject: CloudObject instance
        """
        if cloudobject.backend == self.backend:
            bucket = cloudobject.bucket
            key = cloudobject.key
            return self.storage_handler.delete_object(bucket, key)
        else:
            raise Exception("CloudObject: Invalid Storage backend")

    def delete_cloudobjects(self, cloudobjects: List[utils.CloudObject]):
        """
        Delete multiple CloudObjects from storage.

        :param cloudobjects: List of CloudObject instances
        """
        cobjs = {}
        for co in cloudobjects:
            if co.backend not in cobjs:
                cobjs[co.backend] = {}
            if co.bucket not in cobjs[co.backend]:
                cobjs[co.backend][co.bucket] = []
            cobjs[co.backend][co.bucket].append(co.key)

        for backend in cobjs:
            if backend == self.backend:
                for bucket in cobjs[backend]:
                    self.storage_handler.delete_objects(bucket, cobjs[backend][co.bucket])
            else:
                raise Exception("CloudObject: Invalid Storage backend")


class InternalStorage:
    """
    An InternalStorage object is used by executors and other components to access
    underlying storage backend without exposing the the implementation details.
    """

    def __init__(self, storage_config):
        """ Creates an InternalStorage instance
        :param storage_config: Storage config dictionary

        :return: InternalStorage instance
        """
        self.storage = Storage(storage_config=storage_config)
        self.backend = self.storage.backend
        self.bucket = self.storage.bucket

        if not self.bucket:
            raise Exception(f"'storage_bucket' is mandatory under '{self.backend}'"
                            " section of the configuration")

    def get_client(self):
        """
        Retrieves the underlying storage client.
        :return: storage backend client
        """
        return self.storage.get_client()

    def get_storage_config(self):
        """
        Retrieves the configuration of this storage handler.
        :return: storage configuration
        """
        return self.storage.get_storage_config()

    def put_data(self, key, data):
        """
        Put data object into storage.
        :param key: data key
        :param data: data content
        :return: None
        """
        return self.storage.put_object(self.bucket, key, data)

    def put_func(self, key, func):
        """
        Put serialized function into storage.
        :param key: function key
        :param func: serialized function
        :return: None
        """
        return self.storage.put_object(self.bucket, key, func)

    def get_data(self, key, stream=False, extra_get_args={}):
        """
        Get data object from storage.
        :param key: data key
        :return: data content
        """
        return self.storage.get_object(self.bucket, key, stream, extra_get_args)

    def get_func(self, key):
        """
        Get serialized function from storage.
        :param key: function key
        :return: serialized function
        """
        return self.storage.get_object(self.bucket, key)

    def del_data(self, key):
        """
        Deletes data from storage.
        :param key: data key
        :return: None
        """
        return self.storage.delete_object(self.bucket, key)

    def get_job_status(self, executor_id):
        """
        Get the status of a callset.
        :param executor_id: executor's ID
        :return: A list of call IDs that have updated status.
        """
        callset_prefix = '/'.join([JOBS_PREFIX, executor_id])
        keys = self.storage.list_keys(self.bucket, callset_prefix)

        running_keys = [k.split('/') for k in keys if utils.init_key_suffix in k]
        running_callids = [(tuple(k[1].rsplit("-", 1) + [k[2]]),
                            k[3].replace(utils.init_key_suffix, ''))
                           for k in running_keys]

        done_keys = [k.split('/')[1:] for k in keys if utils.status_key_suffix in k]
        done_callids = [tuple(k[0].rsplit("-", 1) + [k[1]]) for k in done_keys]

        return set(running_callids), set(done_callids)

    def get_call_status(self, executor_id, job_id, call_id):
        """
        Get status of a call.
        :param executor_id: executor ID of the call
        :param call_id: call ID of the call
        :return: A dictionary containing call's status, or None if no updated status
        """
        status_key = utils.create_status_key(executor_id, job_id, call_id)
        try:
            data = self.storage.get_object(self.bucket, status_key)
            return json.loads(data.decode('ascii'))
        except utils.StorageNoSuchKeyError:
            return None

    def get_call_output(self, executor_id, job_id, call_id):
        """
        Get the output of a call.
        :param executor_id: executor ID of the call
        :param call_id: call ID of the call
        :return: Output of the call.
        """
        output_key = utils.create_output_key(executor_id, job_id, call_id)
        try:
            return self.storage.get_object(self.bucket, output_key)
        except utils.StorageNoSuchKeyError:
            return None

    def get_runtime_meta(self, key):
        """
        Get the metadata given a runtime name.
        :param runtime: name of the runtime
        :return: runtime metadata
        """

        global RUNTIME_META_CACHE

        path = [RUNTIMES_PREFIX, key + ".meta.json"]
        filename_local_path = os.path.join(CACHE_DIR, *path)

        if '/'.join(path) in RUNTIME_META_CACHE:
            logger.debug("Runtime metadata found in local memory cache")
            return RUNTIME_META_CACHE['/'.join(path)]

        elif not is_lithops_worker() and os.path.exists(filename_local_path):
            logger.debug("Runtime metadata found in local disk cache")
            with open(filename_local_path, "r") as f:
                runtime_meta = json.loads(f.read())
            RUNTIME_META_CACHE['/'.join(path)] = runtime_meta
            return runtime_meta

        else:
            logger.debug("Runtime metadata not found in local cache. Retrieving it from storage")
            try:
                obj_key = '/'.join(path).replace('\\', '/')
                logger.debug('Trying to download runtime metadata from: {}://{}/{}'
                             .format(self.backend, self.bucket, obj_key))
                json_str = self.storage.get_object(self.bucket, obj_key)
                logger.debug('Runtime metadata found in storage')
                runtime_meta = json.loads(json_str.decode("ascii"))

                # Save runtime meta to cache
                try:
                    if not os.path.exists(os.path.dirname(filename_local_path)):
                        os.makedirs(os.path.dirname(filename_local_path))

                    with open(filename_local_path, "w") as f:
                        f.write(json.dumps(runtime_meta))
                except Exception as e:
                    logger.error("Could not save runtime meta to local cache: {}".format(e))

                RUNTIME_META_CACHE['/'.join(path)] = runtime_meta
                return runtime_meta
            except utils.StorageNoSuchKeyError:
                logger.debug('Runtime metadata not found in storage')
                return None

    def put_runtime_meta(self, key, runtime_meta):
        """
        Put the metadata given a runtime config.
        :param runtime: name of the runtime
        :param runtime_meta metadata
        """
        path = [RUNTIMES_PREFIX, key + ".meta.json"]
        obj_key = '/'.join(path).replace('\\', '/')
        logger.debug("Uploading runtime metadata to: {}://{}/{}"
                     .format(self.backend, self.bucket, obj_key))
        self.storage.put_object(self.bucket, obj_key, json.dumps(runtime_meta))

        if not is_lithops_worker():
            filename_local_path = os.path.join(CACHE_DIR, *path)
            logger.debug("Storing runtime metadata into local cache: {}".format(filename_local_path))

            if not os.path.exists(os.path.dirname(filename_local_path)):
                os.makedirs(os.path.dirname(filename_local_path))

            with open(filename_local_path, "w") as f:
                f.write(json.dumps(runtime_meta))

    def delete_runtime_meta(self, key):
        """
        Put the metadata given a runtime config.
        :param runtime: name of the runtime
        :param runtime_meta metadata
        """
        path = [RUNTIMES_PREFIX, key + ".meta.json"]
        obj_key = '/'.join(path).replace('\\', '/')
        filename_local_path = os.path.join(CACHE_DIR, *path)
        if os.path.exists(filename_local_path):
            os.remove(filename_local_path)
        self.storage.delete_object(self.bucket, obj_key)
