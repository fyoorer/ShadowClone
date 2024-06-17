#
# (C) Copyright Cloudlab URV 2021
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
import gc
import logging
import pickle
import diskcache

from joblib._parallel_backends import ParallelBackendBase, PoolManagerMixin
from joblib.parallel import register_parallel_backend
from numpy import ndarray
from concurrent.futures import ThreadPoolExecutor

from lithops.multiprocessing import Pool
from lithops.storage import Storage

logger = logging.getLogger(__name__)


def register_lithops():
    """ Register Lithops Backend to be called with parallel_backend("lithops"). """
    register_parallel_backend("lithops", LithopsBackend)


class LithopsBackend(ParallelBackendBase, PoolManagerMixin):
    """A ParallelBackend which will use a multiprocessing.Pool.
    Will introduce some communication and memory overhead when exchanging
    input and output data with the with the worker Python processes.
    However, does not suffer from the Python Global Interpreter Lock.
    """

    def __init__(self, nesting_level=None, inner_max_num_threads=None, **pool_kwargs):
        super().__init__(nesting_level, inner_max_num_threads, **{})
        self.__pool_kwargs = pool_kwargs

    # Environment variables to protect against bad situations when nesting
    JOBLIB_SPAWNED_PROCESS = "__JOBLIB_SPAWNED_PARALLEL__"

    supports_timeout = True
    supports_sharedmem = False

    def effective_n_jobs(self, n_jobs):
        """Determine the number of jobs which are going to run in parallel.
        This also checks if we are attempting to create a nested parallel
        loop.
        """
        # this must be 1 as we only want to create 1 LithopsExecutor()
        return 1

    def configure(self, n_jobs=1, parallel=None, prefer=None, require=None,
                  **memmappingpool_args):
        """Build a process or thread pool and return the number of workers"""

        n_jobs = self.effective_n_jobs(n_jobs)

        already_forked = int(os.environ.get(self.JOBLIB_SPAWNED_PROCESS, 0))
        if already_forked:
            raise ImportError(
                '[joblib] Attempting to do parallel computing '
                'without protecting your import on a system that does '
                'not support forking. To use parallel-computing in a '
                'script, you must protect your main loop using "if '
                "__name__ == '__main__'"
                '". Please see the joblib documentation on Parallel '
                'for more information')
        # Set an environment variable to avoid infinite loops
        os.environ[self.JOBLIB_SPAWNED_PROCESS] = '1'

        # Make sure to free as much memory as possible before forking
        gc.collect()
        self._pool = Pool()
        self.parallel = parallel

        return n_jobs

    def terminate(self):
        """Shutdown the process or thread pool"""
        super().terminate()
        if self.JOBLIB_SPAWNED_PROCESS in os.environ:
            del os.environ[self.JOBLIB_SPAWNED_PROCESS]

    def compute_batch_size(self):
        return int(1e6)

    def apply_async(self, func, callback=None):
        """Schedule a func to be run"""
        # return self._get_pool().map_async(handle_call, func.items, callback=callback) # bypass

        mem_opt_calls = find_shared_objects(func.items)
        return self._get_pool().starmap_async(handle_call, mem_opt_calls)


def find_shared_objects(calls):
    # find and annotate repeated arguments
    record = {}
    for i, call in enumerate(calls):
        for j, arg in enumerate(call[1]):
            if id(arg) in record:
                record[id(arg)].append((i, j))
            else:
                record[id(arg)] = [arg, (i, j)]

        for k, v in call[2].items():
            if id(v) in record:
                record[id(v)].append((i, k))
            else:
                record[id(v)] = [v, (i, k)]

    # If we found multiple occurrences of one object, then
    # store it in shared memory, pass a proxy as a value
    calls = [list(item) for item in calls]

    storage = Storage()
    thread_pool = ThreadPoolExecutor(max_workers=len(record))

    def put_arg_obj(positions):
        obj = positions.pop(0)
        if len(positions) > 1 and consider_sharing(obj):
            logger.debug('Proxying {}'.format(type(obj)))
            obj_bin = pickle.dumps(obj)
            cloud_object = storage.put_cloudobject(obj_bin)

            for pos in positions:
                call_n, idx_or_key = pos
                call = calls[call_n]

                if isinstance(idx_or_key, str):
                    call[2][idx_or_key] = cloud_object
                else:
                    args_as_list = list(call[1])
                    args_as_list[idx_or_key] = cloud_object
                    call[1] = tuple(args_as_list)

                try:
                    call[3].append(idx_or_key)
                except IndexError:
                    call.append([idx_or_key])

    fut = []
    for positions in record.values():
        f = thread_pool.submit(put_arg_obj, positions)
        fut.append(f)
    [f.result() for f in fut]

    return [tuple(item) for item in calls]


def handle_call(func, args, kwargs, proxy_positions=[]):
    if len(proxy_positions) > 0:
        args, kwargs = replace_with_values(args, kwargs, proxy_positions)

    return func(*args, **kwargs)


def replace_with_values(args, kwargs, proxy_positions):
    args_as_list = list(args)
    thread_pool = ThreadPoolExecutor(max_workers=len(proxy_positions))
    cache = diskcache.Cache('/tmp/lithops/cache')

    def get_arg_obj(idx_or_key):
        if isinstance(idx_or_key, str):
            obj_id = kwargs[idx_or_key]
        else:
            obj_id = args_as_list[idx_or_key]

        if obj_id in cache:
            logger.debug('Get {} (arg {}) from cache'.format(obj_id, idx_or_key))
            obj = cache[obj_id]
        else:
            logger.debug('Get {} (arg {}) from storage'.format(obj_id, idx_or_key))
            storage = Storage()
            obj_bin = storage.get_cloudobject(obj_id)
            obj = pickle.loads(obj_bin)
            cache[obj_id] = obj

        if isinstance(idx_or_key, str):
            kwargs[idx_or_key] = obj
        else:
            args_as_list[idx_or_key] = obj

    fut = []
    for idx_or_key in proxy_positions:
        f = thread_pool.submit(get_arg_obj, idx_or_key)
        fut.append(f)
    [f.result() for f in fut]
    return args_as_list, kwargs


def consider_sharing(obj):
    if isinstance(obj, (ndarray, list)):  # TODO: some heuristic
        return True
    return False
