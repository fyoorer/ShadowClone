#
# Copyright 2018 PyWren Team
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
import time
import hashlib
import inspect
import pickle
import logging
from types import SimpleNamespace

from lithops import utils
from lithops.job.partitioner import create_partitions
from lithops.storage.utils import create_func_key, create_data_key,\
    create_job_key, func_key_suffix
from lithops.job.serialize import SerializeIndependent, create_module_data
from lithops.constants import MAX_AGG_DATA_SIZE, LOCALHOST,\
    SERVERLESS, STANDALONE, CUSTOM_RUNTIME_DIR, FAAS_BACKENDS


logger = logging.getLogger(__name__)

FUNCTION_CACHE = set()


def create_map_job(
    config,
    internal_storage,
    executor_id,
    job_id,
    map_function,
    iterdata,
    runtime_meta,
    runtime_memory,
    extra_env,
    include_modules,
    exclude_modules,
    execution_timeout,
    chunksize=None,
    extra_args=None,
    obj_chunk_size=None,
    obj_newline='\n',
    obj_chunk_number=None
):
    """
    Wrapper to create a map job. It integrates COS logic to process objects.
    """
    host_job_meta = {'host_job_create_tstamp': time.time()}
    map_iterdata = utils.verify_args(map_function, iterdata, extra_args)

    # Object processing functionality
    ppo = None
    if utils.is_object_processing_function(map_function):
        create_partitions_start = time.time()
        # Create partitions according chunk_size or chunk_number
        logger.debug('ExecutorID {} | JobID {} - Calling map on partitions '
                     'from object storage flow'.format(executor_id, job_id))
        map_iterdata, ppo = create_partitions(
            config, internal_storage, map_iterdata,
            obj_chunk_size, obj_chunk_number, obj_newline
        )
        host_job_meta['host_job_create_partitions_time'] = round(time.time() - create_partitions_start, 6)
    # ########

    job = _create_job(
        config=config,
        internal_storage=internal_storage,
        executor_id=executor_id,
        job_id=job_id,
        func=map_function,
        iterdata=map_iterdata,
        chunksize=chunksize,
        runtime_meta=runtime_meta,
        runtime_memory=runtime_memory,
        extra_env=extra_env,
        include_modules=include_modules,
        exclude_modules=exclude_modules,
        execution_timeout=execution_timeout,
        host_job_meta=host_job_meta
    )

    if ppo:
        job.parts_per_object = ppo

    return job


def create_reduce_job(
    config,
    internal_storage,
    executor_id,
    reduce_job_id,
    reduce_function,
    map_job,
    map_futures,
    runtime_meta,
    runtime_memory,
    obj_reduce_by_key,
    extra_env,
    include_modules,
    exclude_modules,
    execution_timeout=None,
    extra_args=None
):
    """
    Wrapper to create a reduce job. Apply a function across all map futures.
    """
    host_job_meta = {'host_job_create_tstamp': time.time()}

    iterdata = [(map_futures, )]

    if hasattr(map_job, 'parts_per_object') and obj_reduce_by_key:
        prev_total_partitons = 0
        iterdata = []
        for total_partitions in map_job.parts_per_object:
            iterdata.append((map_futures[prev_total_partitons:prev_total_partitons + total_partitions],))
            prev_total_partitons += total_partitions

    reduce_job_env = {'__LITHOPS_REDUCE_JOB': True}
    if extra_env is None:
        ext_env = reduce_job_env
    else:
        ext_env = extra_env.copy()
        ext_env.update(reduce_job_env)

    iterdata = utils.verify_args(reduce_function, iterdata, extra_args)

    return _create_job(
        config=config,
        internal_storage=internal_storage,
        executor_id=executor_id,
        job_id=reduce_job_id,
        func=reduce_function,
        iterdata=iterdata,
        runtime_meta=runtime_meta,
        runtime_memory=runtime_memory,
        extra_env=ext_env,
        include_modules=include_modules,
        exclude_modules=exclude_modules,
        execution_timeout=execution_timeout,
        host_job_meta=host_job_meta
    )


def _create_job(
    config,
    internal_storage,
    executor_id,
    job_id,
    func,
    iterdata,
    runtime_meta,
    runtime_memory,
    extra_env,
    include_modules,
    exclude_modules,
    execution_timeout,
    host_job_meta,
    chunksize=None
):
    """
    Creates a new Job
    """
    global FUNCTION_CACHE

    ext_env = {} if extra_env is None else extra_env.copy()
    if ext_env:
        ext_env = utils.convert_bools_to_string(ext_env)
        logger.debug("Extra environment vars {}".format(ext_env))

    mode = config['lithops']['mode']
    backend = config['lithops']['backend']

    job = SimpleNamespace()
    job.chunksize = chunksize or config['lithops']['chunksize']
    job.worker_processes = config[backend]['worker_processes']
    job.execution_timeout = execution_timeout or config['lithops']['execution_timeout']
    job.executor_id = executor_id
    job.job_id = job_id
    job.job_key = create_job_key(job.executor_id, job.job_id)
    job.extra_env = ext_env
    job.function_name = func.__name__ if inspect.isfunction(func) or inspect.ismethod(func) else type(func).__name__
    job.total_calls = len(iterdata)

    if mode == SERVERLESS:
        job.runtime_memory = runtime_memory or config[backend]['runtime_memory']
        job.runtime_timeout = runtime_meta['runtime_timeout']
        if job.execution_timeout >= job.runtime_timeout:
            job.execution_timeout = job.runtime_timeout - 5

    elif mode in STANDALONE:
        job.runtime_memory = None
        runtime_timeout = config[STANDALONE]['hard_dismantle_timeout']
        if job.execution_timeout >= runtime_timeout:
            job.execution_timeout = runtime_timeout - 10

    elif mode == LOCALHOST:
        job.runtime_memory = None
        job.runtime_timeout = None

    exclude_modules_cfg = config['lithops'].get('exclude_modules', [])
    include_modules_cfg = config['lithops'].get('include_modules', [])

    exc_modules = set()
    inc_modules = set()
    if exclude_modules_cfg:
        exc_modules.update(exclude_modules_cfg)
    if exclude_modules:
        exc_modules.update(exclude_modules)
    if include_modules_cfg is not None:
        inc_modules.update(include_modules_cfg)
    if include_modules_cfg is None and not include_modules:
        inc_modules = None
    if include_modules is not None and include_modules:
        inc_modules.update(include_modules)
    if include_modules is None:
        inc_modules = None

    logger.debug('ExecutorID {} | JobID {} - Serializing function and data'.format(executor_id, job_id))
    job_serialize_start = time.time()
    serializer = SerializeIndependent(runtime_meta['preinstalls'])
    func_and_data_ser, mod_paths = serializer([func] + iterdata, inc_modules, exc_modules)
    data_strs = func_and_data_ser[1:]
    data_size_bytes = sum(len(x) for x in data_strs)
    module_data = create_module_data(mod_paths)
    func_str = func_and_data_ser[0]
    func_module_str = pickle.dumps({'func': func_str, 'module_data': module_data}, -1)
    func_module_size_bytes = len(func_module_str)

    host_job_meta['host_job_serialize_time'] = round(time.time() - job_serialize_start, 6)
    host_job_meta['func_data_size_bytes'] = data_size_bytes
    host_job_meta['func_module_size_bytes'] = func_module_size_bytes

    # Check data limit
    if 'data_limit' in config['lithops']:
        data_limit = config['lithops']['data_limit']
    else:
        data_limit = MAX_AGG_DATA_SIZE
    if data_limit and data_size_bytes > data_limit * 1024**2:
        log_msg = ('ExecutorID {} | JobID {} - Total data exceeded maximum size '
                   'of {}'.format(executor_id, job_id, utils.sizeof_fmt(data_limit * 1024**2)))
        raise Exception(log_msg)

    # Upload function and data
    upload_function = not config['lithops'].get('customized_runtime', False)
    upload_data = not (len(str(data_strs[0])) * job.chunksize < 8 * 1204 and backend in FAAS_BACKENDS)

    # Upload function and modules
    if upload_function:
        function_hash = hashlib.md5(func_module_str).hexdigest()
        job.func_key = create_func_key(executor_id, function_hash)
        if job.func_key not in FUNCTION_CACHE:
            logger.debug('ExecutorID {} | JobID {} - Uploading function and modules '
                         'to the storage backend'.format(executor_id, job_id))
            func_upload_start = time.time()
            internal_storage.put_func(job.func_key, func_module_str)
            func_upload_end = time.time()
            host_job_meta['host_func_upload_time'] = round(func_upload_end - func_upload_start, 6)
            FUNCTION_CACHE.add(job.func_key)
        else:
            logger.debug('ExecutorID {} | JobID {} - Function and modules '
                         'found in local cache'.format(executor_id, job_id))
            host_job_meta['host_func_upload_time'] = 0

    else:
        # Prepare function and modules locally to store in the runtime image later
        function_file = func.__code__.co_filename
        function_hash = hashlib.md5(open(function_file, 'rb').read()).hexdigest()[:16]
        mod_hash = hashlib.md5(repr(sorted(mod_paths)).encode('utf-8')).hexdigest()[:16]
        job.func_key = func_key_suffix
        job.ext_runtime_uuid = '{}{}'.format(function_hash, mod_hash)
        job.local_tmp_dir = os.path.join(CUSTOM_RUNTIME_DIR, job.ext_runtime_uuid)
        _store_func_and_modules(job.local_tmp_dir, job.func_key, func_str, module_data)
        host_job_meta['host_func_upload_time'] = 0

    # upload data
    if upload_data:
        # Upload iterdata to COS only if a single element is greater than 8KB
        logger.debug('ExecutorID {} | JobID {} - Uploading data to the storage backend'
                     .format(executor_id, job_id))
        # pass_iteradata through an object storage file
        data_key = create_data_key(executor_id, job_id)
        job.data_key = data_key
        data_bytes, data_byte_ranges = utils.agg_data(data_strs)
        job.data_byte_ranges = data_byte_ranges
        data_upload_start = time.time()
        internal_storage.put_data(data_key, data_bytes)
        data_upload_end = time.time()
        host_job_meta['host_data_upload_time'] = round(data_upload_end - data_upload_start, 6)

    else:
        # pass iteradata as part of the invocation payload
        logger.debug('ExecutorID {} | JobID {} - Data per activation is < '
                     '{}. Passing data through invocation payload'
                     .format(executor_id, job_id, utils.sizeof_fmt(8 * 1024)))
        job.data_key = None
        job.data_byte_ranges = None
        job.data_byte_strs = data_strs
        host_job_meta['host_data_upload_time'] = 0

    host_job_meta['host_job_created_time'] = round(time.time() - host_job_meta['host_job_create_tstamp'], 6)

    job.metadata = host_job_meta

    return job


def _store_func_and_modules(
    job_tmp_dir,
    func_key,
    func_str,
    module_data
):
    ''' stores function and modules in temporary directory to be
    used later in optimized runtime
    '''
    # save function
    os.makedirs(job_tmp_dir, exist_ok=True)

    with open(os.path.join(job_tmp_dir, func_key), "wb") as f:
        pickle.dump({'func': func_str}, f, -1)

    # save modules
    if module_data:
        logger.debug("Writing Function dependencies to local disk")

        modules_path = '/'.join([job_tmp_dir, 'modules'])

        for m_filename, m_data in module_data.items():
            m_path = os.path.dirname(m_filename)

            if len(m_path) > 0 and m_path[0] == "/":
                m_path = m_path[1:]
            to_make = os.path.join(modules_path, m_path)
            try:
                os.makedirs(to_make)
            except OSError as e:
                if e.errno == 17:
                    pass
                else:
                    raise e
            full_filename = os.path.join(to_make, os.path.basename(m_filename))

            with open(full_filename, 'wb') as fid:
                fid.write(utils.b64str_to_bytes(m_data))

    logger.debug("Finished storing function and modules")
