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
import math
import unittest
import logging

import lithops
from lithops.tests import main_util
from lithops.tests.util_func.map_reduce_util import simple_reduce_function, my_reduce_function
from lithops.tests.util_func.map_util import simple_map_function, my_map_function_obj, my_map_function_url
from lithops.tests.util_func.storage_util import list_dataset_keys, get_dataset_key_size

logger = logging.getLogger(__name__)

CONFIG = None
STORAGE_CONFIG = None
STORAGE = None
TEST_FILES_URLS = None
PREFIX = '__lithops.test'
DATASET_PREFIX = PREFIX + '/dataset'


class TestMapReduce(unittest.TestCase):
    words_in_cos_files = None

    @classmethod
    def setUpClass(cls):
        global CONFIG, STORAGE, STORAGE_CONFIG, TEST_FILES_URLS

        CONFIG, STORAGE, STORAGE_CONFIG = main_util.get_config().values()
        TEST_FILES_URLS = main_util.get_data_sets()
        cls.words_in_cos_files = main_util.get_words_in_files()

    @classmethod
    def setUp(cls):
        print('\n-------------------------------------------------------------\n')

    def test_map_reduce(self):
        logger.info('Testing map_reduce() using memory')
        iterdata = [(1, 1), (2, 2), (3, 3), (4, 4)]
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.map_reduce(simple_map_function, iterdata,
                         simple_reduce_function)
        result = fexec.get_result()
        self.assertEqual(result, 20)

    def test_map_reduce_obj_bucket(self):
        logger.info('Testing map_reduce() over a bucket')
        sb = STORAGE_CONFIG['backend']
        data_prefix = sb + '://' + STORAGE_CONFIG['bucket'] + '/' + DATASET_PREFIX + '/'
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.map_reduce(my_map_function_obj, data_prefix,
                         my_reduce_function)
        result = fexec.get_result()
        self.assertEqual(result, self.__class__.words_in_cos_files)

    def test_map_reduce_obj_bucket_reduce_by_key(self):
        logger.info('Testing map_reduce() over a bucket with one reducer per object')
        sb = STORAGE_CONFIG['backend']
        data_prefix = sb + '://' + STORAGE_CONFIG['bucket'] + '/' + DATASET_PREFIX + '/'
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.map_reduce(my_map_function_obj, data_prefix,
                         my_reduce_function,
                         obj_reduce_by_key=True)
        result = fexec.get_result()
        # the reducer returns a list containing sum of the words uploaded via each file.
        self.assertEqual(sum(result), self.__class__.words_in_cos_files)

    def test_map_reduce_obj_key(self):
        logger.info('Testing map_reduce() over object keys')
        sb = STORAGE_CONFIG['backend']
        bucket_name = STORAGE_CONFIG['bucket']
        iterdata = [sb + '://' + bucket_name + '/' + key for key in list_dataset_keys(STORAGE, STORAGE_CONFIG)]
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.map_reduce(my_map_function_obj, iterdata,
                         my_reduce_function)
        result = fexec.get_result()
        self.assertEqual(result, self.__class__.words_in_cos_files)

    def test_map_reduce_obj_key_reduce_by_key(self):
        logger.info('Testing map_reduce() over object keys with one reducer per object')
        sb = STORAGE_CONFIG['backend']
        bucket_name = STORAGE_CONFIG['bucket']
        iterdata = [sb + '://' + bucket_name + '/' + key for key in list_dataset_keys(STORAGE, STORAGE_CONFIG)]
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.map_reduce(my_map_function_obj, iterdata,
                         my_reduce_function,
                         obj_reduce_by_key=True)
        result = fexec.get_result()
        self.assertEqual(sum(result), self.__class__.words_in_cos_files)

    def test_map_reduce_url(self):
        logger.info('Testing map_reduce() over URLs')
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.map_reduce(my_map_function_url, TEST_FILES_URLS,
                         my_reduce_function, obj_chunk_number=2)
        result = fexec.get_result()
        self.assertEqual(result, self.__class__.words_in_cos_files)

    def test_chunks_bucket(self):
        """tests the ability to create a separate function invocation based on the following parameters:
         chunk_size - creates [file_size//chunk_size] invocations to process each chunk_size bytes, of a given object.
         chunk_number - creates 'chunk_number' invocations that process [file_size//chunk_number] bytes each. """

        logger.info('Testing chunks on a bucket')
        OBJ_CHUNK_SIZE = 1 * 800 ** 2  # create a new invocation
        OBJ_CHUNK_NUMBER = 2
        activations = 0

        sb = STORAGE_CONFIG['backend']
        data_prefix = sb + '://' + STORAGE_CONFIG['bucket'] + '/' + DATASET_PREFIX + '/'

        fexec = lithops.FunctionExecutor(config=CONFIG)
        futures = fexec.map_reduce(my_map_function_obj, data_prefix,
                                   my_reduce_function,
                                   obj_chunk_size=OBJ_CHUNK_SIZE)
        result = fexec.get_result(futures)
        self.assertEqual(result, self.__class__.words_in_cos_files)

        for size in get_dataset_key_size(STORAGE, STORAGE_CONFIG):
            activations += math.ceil(size / OBJ_CHUNK_SIZE)

        self.assertEqual(len(futures), activations + 1)  # +1 due to the reduce function

        fexec = lithops.FunctionExecutor(config=CONFIG)
        futures = fexec.map_reduce(my_map_function_obj, data_prefix,
                                   my_reduce_function, obj_chunk_number=OBJ_CHUNK_NUMBER)
        result = fexec.get_result(futures)
        self.assertEqual(result, self.__class__.words_in_cos_files)

        self.assertEqual(len(futures), len(TEST_FILES_URLS)*OBJ_CHUNK_NUMBER + 1)

    def test_chunks_bucket_one_reducer_per_object(self):
        """tests the ability to create a separate function invocation based on the following parameters, as well as
         create a separate invocation of a reduce function for each object:
         chunk_size - creates [file_size//chunk_size] invocations to process each chunk_size bytes, of a given object.
         chunk_number - creates 'chunk_number' invocations that process [file_size//chunk_number] bytes each. """

        logger.info('Testing chunks on a bucket with one reducer per object')
        OBJ_CHUNK_SIZE = 1 * 1024 ** 2
        OBJ_CHUNK_NUMBER = 2
        activations = 0

        sb = STORAGE_CONFIG['backend']
        data_prefix = sb + '://' + STORAGE_CONFIG['bucket'] + '/' + DATASET_PREFIX + '/'

        fexec = lithops.FunctionExecutor(config=CONFIG)
        futures = fexec.map_reduce(my_map_function_obj, data_prefix,
                                   my_reduce_function,
                                   obj_chunk_size=OBJ_CHUNK_SIZE,
                                   obj_reduce_by_key=True)
        result = fexec.get_result(futures)
        self.assertEqual(sum(result), self.__class__.words_in_cos_files)

        for size in get_dataset_key_size(STORAGE, STORAGE_CONFIG):
            activations += math.ceil(size / OBJ_CHUNK_SIZE)

        self.assertEqual(len(futures), activations + len(TEST_FILES_URLS))  # + len(TEST_FILES_URLS) due to map_reduce activation per object

        fexec = lithops.FunctionExecutor(config=CONFIG)
        futures = fexec.map_reduce(my_map_function_obj, data_prefix,
                                   my_reduce_function, obj_chunk_number=OBJ_CHUNK_NUMBER,
                                   obj_reduce_by_key=True)
        result = fexec.get_result(futures)
        self.assertEqual(sum(result), self.__class__.words_in_cos_files)
        self.assertEqual(len(futures), len(TEST_FILES_URLS) * OBJ_CHUNK_NUMBER + len(TEST_FILES_URLS))  # + len(TEST_FILES_URLS) due to map_reduce activation per object
