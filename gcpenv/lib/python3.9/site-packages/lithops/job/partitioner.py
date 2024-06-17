#
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
import logging
import requests
from concurrent.futures import ThreadPoolExecutor

from lithops import utils
from lithops.storage import Storage
from lithops.storage.utils import CloudObject, CloudObjectUrl, CloudObjectLocal
from lithops.utils import sizeof_fmt

logger = logging.getLogger(__name__)

CHUNK_THRESHOLD = 128 * 1024  # 128KB


def create_partitions(
    config,
    internal_storage,
    map_iterdata,
    obj_chunk_size,
    obj_chunk_number,
    obj_newline
):
    """
    Method that returns the function that will create
    the partitions of the objects in the Cloud
    """

    urls = []
    paths = []
    objects = []

    logger.debug("Parsing input data")

    # first filter; decide if the iterdata elements are urls,
    # paths or object storage objects
    for elem in map_iterdata:
        if elem['obj'].startswith('http'):
            # iterdata is a list of public urls
            urls.append(elem)

        elif elem['obj'].startswith('/'):
            # iterdata is a list of localhost paths or dirs
            paths.append(elem)

        else:
            # assume iterdata contains buckets or object keys
            objects.append(elem)

    if urls:
        # process objects from urls.
        return _split_objects_from_urls(
            urls, obj_chunk_size,
            obj_chunk_number, obj_newline
        )

    elif paths:
        # process objects from localhost paths.
        return _split_objects_from_paths(
            paths, obj_chunk_size,
            obj_chunk_number, obj_newline
        )

    elif objects:
        # process objects from an object store.
        return _split_objects_from_object_storage(
            objects, obj_chunk_size, obj_chunk_number,
            internal_storage, config, obj_newline
        )


def _split_objects_from_urls(
    map_func_args_list,
    chunk_size,
    chunk_number,
    obj_newline
):
    """
    Create partitions from a list of objects urls
    """
    if chunk_number:
        logger.debug(f'Chunk size set to {chunk_size}')
    elif chunk_size:
        logger.debug(f'Chunk number set to {chunk_number}')
    else:
        logger.debug('Chunk size and chunk number not set ')

    partitions = []
    parts_per_object = []

    def _split(entry):
        obj_size = None
        object_url = entry['obj']
        metadata = requests.head(object_url)

        if 'content-length' in metadata.headers:
            obj_size = int(metadata.headers['content-length'])

        if chunk_number and obj_size:
            chunk_rest = obj_size % chunk_number
            obj_chunk_size = (obj_size // chunk_number) + \
                round((chunk_rest / chunk_number) + 0.5)
        elif chunk_size and obj_size:
            obj_chunk_size = chunk_size
        elif obj_size:
            obj_chunk_size = obj_size
        else:
            obj_chunk_size = obj_size = 1

        if 'accept-ranges' not in metadata.headers:
            obj_chunk_size = obj_size

        obj_partitions = []
        size = obj_total_partitions = 0

        ci = obj_size
        cz = obj_chunk_size
        parts = ci // cz + (ci % cz > 0)
        logger.debug(f'Creating {parts} partitions from url {object_url} ({sizeof_fmt(obj_size)})')

        while size < obj_size - 1:
            if obj_size <= obj_chunk_size:
                # Only one chunk
                brange = None
                obj_chunk_size = obj_size
            elif obj_newline is None:
                # partitions of the same size
                brange = (size, size + obj_chunk_size - 1)
            elif size + obj_chunk_size < obj_size:
                # common chunk
                brange = (size - 1 if size > 0 else 0, size + obj_chunk_size + CHUNK_THRESHOLD)
            else:
                # last chunk
                brange = (size - 1, obj_size - 1)
                obj_chunk_size = obj_size - size

            obj_total_partitions += 1

            partition = entry.copy()
            partition['obj'] = CloudObjectUrl(object_url)
            partition['obj'].data_byte_range = brange
            partition['obj'].chunk_size = obj_chunk_size
            partition['obj'].part = obj_total_partitions
            partition['obj'].newline = obj_newline
            obj_partitions.append(partition)

            size += obj_chunk_size

        for partition in obj_partitions:
            partition['obj'].total_parts = obj_total_partitions

        partitions.extend(obj_partitions)
        parts_per_object.append(obj_total_partitions)

    with ThreadPoolExecutor(64) as ex:
        ex.map(_split, map_func_args_list)

    return partitions, parts_per_object


def _split_objects_from_paths(
    map_func_args_list,
    chunk_size,
    chunk_number,
    obj_newline
):
    """
    Create partitions from a list of objects paths
    """
    if chunk_number:
        logger.debug(f'Chunk size set to {chunk_size}')
    elif chunk_size:
        logger.debug(f'Chunk number set to {chunk_number}')
    else:
        logger.debug('Chunk size and chunk number not set ')

    partitions = []
    parts_per_object = []

    files = set()
    new_map_func_args_list = []

    for elem in map_func_args_list:
        if os.path.isdir(elem['obj']):
            path = elem['obj']
            found_files = os.listdir(path)
            for filename in found_files:
                full_path = os.path.join(path, filename)
                if full_path in files or \
                   not os.path.isfile(full_path):
                    continue
                files.add(full_path)
                new_elem = elem.copy()
                new_elem['obj'] = full_path
                new_map_func_args_list.append(new_elem)
        elif os.path.isfile(elem['obj']):
            if elem['obj'] in files:
                continue
            files.add(elem['obj'])
            new_map_func_args_list.append(elem)

    def _split(entry):
        path = entry['obj']
        file_stats = os.stat(entry['obj'])
        obj_size = int(file_stats.st_size)

        if chunk_number and obj_size:
            chunk_rest = obj_size % chunk_number
            obj_chunk_size = (obj_size // chunk_number) + \
                round((chunk_rest / chunk_number) + 0.5)
        elif chunk_size and obj_size:
            obj_chunk_size = chunk_size
        elif obj_size:
            obj_chunk_size = obj_size
        else:
            obj_chunk_size = obj_size = 1

        obj_partitions = []
        size = obj_total_partitions = 0

        ci = obj_size
        cz = obj_chunk_size
        parts = ci // cz + (ci % cz > 0)
        logger.debug(f'Creating {parts} partitions from url {path} ({sizeof_fmt(obj_size)})')

        while size < obj_size - 1:
            if obj_size <= obj_chunk_size:
                # Only one chunk
                brange = None
                obj_chunk_size = obj_size
            elif obj_newline is None:
                # partitions of the same size
                brange = (size, size + obj_chunk_size - 1)
            elif size + obj_chunk_size < obj_size:
                # common chunk
                brange = (size - 1 if size > 0 else 0, size + obj_chunk_size + CHUNK_THRESHOLD)
            else:
                # last chunk
                brange = (size - 1, obj_size - 1)
                obj_chunk_size = obj_size - size

            obj_total_partitions += 1

            partition = entry.copy()
            partition['obj'] = CloudObjectLocal(path)
            partition['obj'].data_byte_range = brange
            partition['obj'].chunk_size = obj_chunk_size
            partition['obj'].part = obj_total_partitions
            partition['obj'].newline = obj_newline
            obj_partitions.append(partition)

            size += obj_chunk_size

        for partition in obj_partitions:
            partition['obj'].total_parts = obj_total_partitions

        partitions.extend(obj_partitions)
        parts_per_object.append(obj_total_partitions)

    with ThreadPoolExecutor(64) as ex:
        ex.map(_split, new_map_func_args_list)

    return partitions, parts_per_object


def _split_objects_from_object_storage(
    map_func_args_list,
    chunk_size,
    chunk_number,
    internal_storage,
    config,
    obj_newline
):
    """
    Create partitions from a list of buckets or object keys
    """
    if chunk_number:
        logger.debug(f'Chunk size set to {chunk_size}')
    elif chunk_size:
        logger.debug(f'Chunk number set to {chunk_number}')
    else:
        logger.debug('Chunk size and chunk number not set')

    sbs = set()

    # check that only one schemma provided. Throw exception if more than one provided
    for elem in map_func_args_list:
        if type(elem['obj']) == CloudObject:
            elem['obj'] = f"{elem['obj'].backend}://{elem['obj'].bucket}/{elem['obj'].key}"
        sb, bucket, prefix, obj_name = utils.split_object_url(elem['obj'])
        if sb is None:
            sb = internal_storage.backend
            elem['obj'] = f"{sb}://{elem['obj']}"

        sbs.add(sb)

    if len(sbs) > 1:
        raise Exception('Process objects from multiple storage backends is not supported. '
                        f'Current storage backends: {sbs}')

    sb = sbs.pop()
    if sb == internal_storage.backend:
        storage = internal_storage.storage
    else:
        storage = Storage(config=config, backend=sb)
    partitions = []
    parts_per_object = []

    def _split(bucket, key, entry, obj_size):

        if key.endswith('/'):
            logger.debug(f'Discarding object "{key}" as it is a prefix folder (0.0B)')
            return

        #obj_size = keys_dict[bucket][key]

        if chunk_number:
            chunk_rest = obj_size % chunk_number
            obj_chunk_size = (obj_size // chunk_number) + \
                round((chunk_rest / chunk_number) + 0.5)
        elif chunk_size:
            obj_chunk_size = chunk_size
        else:
            obj_chunk_size = obj_size

        obj_partitions = []
        size = obj_total_partitions = 0

        ci = obj_size
        cz = obj_chunk_size
        parts = ci // cz + (ci % cz > 0)
        logger.debug(f'Creating {parts} partitions from object {key} ({sizeof_fmt(obj_size)})')

        while size < obj_size - 1:
            if obj_size <= obj_chunk_size:
                # Only one chunk
                brange = None
                obj_chunk_size = obj_size
            elif obj_newline is None:
                # partitions of the same size
                brange = (size, size + obj_chunk_size - 1)
            elif size + obj_chunk_size < obj_size:
                # common chunk
                brange = (size - 1 if size > 0 else 0, size + obj_chunk_size + CHUNK_THRESHOLD)
            else:
                # last chunk
                brange = (size - 1, obj_size - 1)
                obj_chunk_size = obj_size - size

            obj_total_partitions += 1

            partition = entry.copy()
            partition['obj'] = CloudObject(sb, bucket, key)
            partition['obj'].data_byte_range = brange
            partition['obj'].chunk_size = obj_chunk_size
            partition['obj'].part = obj_total_partitions
            partition['obj'].newline = obj_newline
            obj_partitions.append(partition)

            size += obj_chunk_size

        for partition in obj_partitions:
            partition['obj'].total_parts = obj_total_partitions

        partitions.extend(obj_partitions)
        parts_per_object.append(obj_total_partitions)

    total_objects = int(0)
    for elem in map_func_args_list:
        objects = []
        exclude = {'obj'}
        params = {k: elem[k] for k in set(list(elem.keys())) - set(exclude)}
        sb, bucket, prefix, obj_name = utils.split_object_url(elem['obj'])

        if obj_name:
            match_pattern = None
            if sb in ['aws_s3', 'ibm_cos'] and (prefix.find('*') > -1 or obj_name.find('*') > -1):

                match_pattern = os.path.join(prefix, obj_name)

                if prefix.find('*') > -1:
                    prefix = prefix[:prefix.index('*')]
                else:
                    prefix = '/'.join(prefix, obj_name[:obj_name.index('*')])

            prefix = prefix + '/' if prefix else prefix
            if match_pattern is not None:
                logger.debug(f"Listing objects with Globber {match_pattern} in {sb}://{'/'.join([bucket, prefix])}")
                objects = storage.list_objects(bucket, prefix, match_pattern)
            else:
                # this is wrong to list prefix only, as it may return more objects than requested
                logger.debug(f"Head on object  {sb}://{'/'.join([bucket, prefix, obj_name])}")
                head_md = storage.head_object(bucket, os.path.join(prefix, obj_name))
                head_md['Key'] = os.path.join(prefix, obj_name)
                head_md['Size'] = int(head_md['content-length'])
                objects.append(head_md)

        elif prefix:
            match_pattern = None
            if sb in ['aws_s3', 'ibm_cos'] and prefix.find('*') > -1:

                match_pattern = prefix
                if prefix.find('*') > -1:
                    prefix = prefix[:prefix.index('*')]

                logger.debug(f"Listing prefixes with Globber {match_pattern} in {sb}://{'/'.join([bucket, prefix])}")
            else:
                logger.debug(f"Listing prefixes in {sb}://{'/'.join([bucket, prefix])}")

            prefix = prefix + '/' if prefix else prefix
            objects = storage.list_objects(bucket, prefix, match_pattern)
        else:
            logger.debug(f"Listing objects in {sb}://{bucket}")
            objects = storage.list_objects(bucket)

        total_objects = total_objects + len(objects)
        for dobj in objects:
            key = dobj['Key']
            entry = {'obj' : f'{sb}://{bucket}/{key}'}
            entry.update(params)
            _split(bucket, key, entry, dobj['Size'] )


    logger.debug(f"Total objects found: {total_objects}")
    if total_objects == 0 :
        raise Exception(f'No objects found')



    return partitions, parts_per_object
