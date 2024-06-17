#
# Copyright Cloudlab URV 2020
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

import io
import os as base_os
from functools import partial
from lithops.storage import Storage
from lithops.utils import is_lithops_worker
from lithops.config import default_storage_config, load_yaml_config, extract_storage_config
from lithops.constants import JOBS_PREFIX, TEMP_PREFIX, LOGS_PREFIX, RUNTIMES_PREFIX


def remove_lithops_keys(keys):
    return list(filter(lambda key: not any([key.startswith(prefix) for prefix in
                                            [JOBS_PREFIX, TEMP_PREFIX, LOGS_PREFIX, RUNTIMES_PREFIX]]), keys))


#
# Picklable cloud object storage client
#

class CloudStorage(Storage):
    def __init__(self, config=None):
        if isinstance(config, str):
            config = load_yaml_config(config)
            self._config = extract_storage_config(config)
        elif isinstance(config, dict):
            if 'lithops' in config:
                self._config = extract_storage_config(config)
            else:
                self._config = config
        else:
            self._config = extract_storage_config(default_storage_config())
        super().__init__(storage_config=self._config)

    def __getstate__(self):
        return self._config

    def __setstate__(self, state):
        self.__init__(state)

    def put_data(self, key, data):
        return self.put_object(self.bucket, key, data)

    def get_data(self, key):
        return self.get_object(self.bucket, key)

    def delete_data(self, key):
        self.delete_object(self.bucket, key)

    def list_bucket_keys(self, prefix=None):
        return self.list_keys(self.bucket, prefix)


class CloudFileProxy:
    def __init__(self, cloud_storage=None):
        self._storage = cloud_storage or CloudStorage()
        self.path = _path(self._storage)

    def __getattr__(self, name):
        # we only reach here if the attr is not defined
        return getattr(base_os, name)

    def open(self, filename, mode='r'):
        return cloud_open(filename, mode=mode, cloud_storage=self._storage)

    def listdir(self, path='', suffix_dirs=False):
        if path == '':
            prefix = '/'
        elif path.startswith('/'):
            prefix = path[1:]
        else:
            prefix = path if path.endswith('/') else path + '/'

        paths = self._storage.list_bucket_keys(prefix=prefix)
        names = set()
        for p in paths:
            if any([p.startswith(prefix) for prefix in [JOBS_PREFIX, TEMP_PREFIX, LOGS_PREFIX, RUNTIMES_PREFIX]]):
                continue
            p = p[len(prefix):] if p.startswith(prefix) else p
            if p.startswith('/'):
                p = p[1:]
            splits = p.split('/')
            name = splits[0] + '/' if suffix_dirs and len(splits) > 1 else splits[0]
            names |= {name}
        return list(names)

    def walk(self, top, topdown=True, onerror=None, followlinks=False):
        dirs = []
        files = []

        for path in self.listdir(top, suffix_dirs=True):
            if path.endswith('/'):
                dirs.append(path[:-1])
            else:
                files.append(path)

        if dirs == [] and files == [] and not self.path.exists(top):
            raise StopIteration
        elif topdown:
            yield top, dirs, files
            for dir_name in dirs:
                for result in self.walk(base_os.path.join(top, dir_name), topdown, onerror, followlinks):
                    yield result
        else:
            for dir_name in dirs:
                for result in self.walk(base_os.path.join(top, dir_name), topdown, onerror, followlinks):
                    yield result
            yield top, dirs, files

    def remove(self, path):
        self._storage.delete_data(path)

    def mkdir(self, *args, **kwargs):
        pass

    def makedirs(self, *args, **kwargs):
        pass


class _path:
    def __init__(self, cloud_storage=None):
        self._storage = cloud_storage or CloudStorage()

    def __getattr__(self, name):
        # we only reach here if the attr is not defined
        return getattr(base_os.path, name)

    def isfile(self, path):
        prefix = path
        if path.startswith('/'):
            prefix = path[1:]

        keys = remove_lithops_keys(self._storage.list_bucket_keys(prefix=prefix))
        if len(keys) == 1:
            key = keys.pop()
            key = key[len(prefix):]
            return key == ''
        else:
            return False

    def isdir(self, path):
        prefix = path
        if path.startswith('/'):
            prefix = path[1:]

        if prefix != '' and not prefix.endswith('/'):
            prefix = prefix + '/'

        keys = remove_lithops_keys(self._storage.list_bucket_keys(prefix=prefix))
        return bool(keys)

    def exists(self, path):
        dirpath = path if path.endswith('/') else path + '/'
        for key in self._storage.list_bucket_keys(prefix=path):
            if key.startswith(dirpath) or key == path:
                return True
        return False


class DelayedBytesBuffer(io.BytesIO):
    def __init__(self, action, initial_bytes=None):
        super().__init__(initial_bytes)
        self._action = action

    def close(self):
        self._action(self.getvalue())
        io.BytesIO.close(self)


class DelayedStringBuffer(io.StringIO):
    def __init__(self, action, initial_value=None):
        super().__init__(initial_value)
        self._action = action

    def close(self):
        self._action(self.getvalue())
        io.StringIO.close(self)


def cloud_open(filename, mode='r', cloud_storage=None):
    storage = cloud_storage or CloudStorage()
    if 'r' in mode:
        if 'b' in mode:
            # we could get_data(stream=True) but some streams are not seekable
            return io.BytesIO(storage.get_data(filename))
        else:
            return io.StringIO(storage.get_data(filename).decode())

    if 'w' in mode:
        action = partial(storage.put_data, filename)
        if 'b' in mode:
            return DelayedBytesBuffer(action)
        else:
            return DelayedStringBuffer(action)


if not is_lithops_worker():
    try:
        _storage = CloudStorage()
    except FileNotFoundError:
        # should never happen unless we are using
        # this module classes for other purposes
        os = None
        open = None
    else:
        os = CloudFileProxy(_storage)
        open = partial(cloud_open, cloud_storage=_storage)
else:
    # should never be used unless we explicitly import
    # inside a function, which is not a good practice
    os = None
    open = None
