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


import unittest
import logging
import lithops
from lithops.tests import main_util
from lithops.tests.util_func.map_util import simple_map_function, hello_world, lithops_inside_lithops_map_function, \
    lithops_return_futures_map_function1, lithops_return_futures_map_function3, lithops_return_futures_map_function2, \
    concat

logger = logging.getLogger(__name__)

CONFIG = None
STORAGE_CONFIG = None
STORAGE = None


class TestMap(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        global CONFIG, STORAGE, STORAGE_CONFIG

        CONFIG, STORAGE, STORAGE_CONFIG = main_util.get_config().values()

    @classmethod
    def setUp(cls):
        print('\n-------------------------------------------------------------\n')

    def test_map(self):
        logger.info('Testing map()')
        iterdata = [(1, 1), (2, 2), (3, 3), (4, 4)]
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.map(simple_map_function, iterdata)
        result = fexec.get_result()
        self.assertEqual(result, [2, 4, 6, 8])

        fexec = lithops.FunctionExecutor(config=CONFIG, max_workers=1)
        fexec.map(simple_map_function, iterdata)
        result = fexec.get_result()
        self.assertEqual(result, [2, 4, 6, 8])

        fexec = lithops.FunctionExecutor(config=CONFIG)
        set_iterdata = set(range(2))
        fexec.map(hello_world, set_iterdata)
        result = fexec.get_result()
        self.assertEqual(result, ['Hello World!'] * 2)

        fexec = lithops.FunctionExecutor(config=CONFIG)
        generator_iterdata = range(2)
        fexec.map(hello_world, generator_iterdata)
        result = fexec.get_result()
        self.assertEqual(result, ['Hello World!'] * 2)

        fexec = lithops.FunctionExecutor(config=CONFIG)
        listDicts_iterdata = [{'x': 2, 'y': 8}, {'x': 2, 'y': 8}]
        fexec.map(simple_map_function, listDicts_iterdata)
        result = fexec.get_result()
        self.assertEqual(result, [10, 10])

        fexec = lithops.FunctionExecutor(config=CONFIG)
        set_iterdata = [["a", "b"], ["c", "d"]]
        fexec.map(concat, set_iterdata)
        result = fexec.get_result()
        self.assertEqual(result, ["a b", "c d"])

    def test_multiple_executions(self):
        logger.info('Testing multiple executions before requesting results')
        fexec = lithops.FunctionExecutor(config=CONFIG)
        iterdata = [(1, 1), (2, 2)]
        fexec.map(simple_map_function, iterdata)
        iterdata = [(3, 3), (4, 4)]
        fexec.map(simple_map_function, iterdata)
        result = fexec.get_result()
        self.assertEqual(result, [2, 4, 6, 8])

        iterdata = [(1, 1), (2, 2)]
        fexec.map(simple_map_function, iterdata)
        result = fexec.get_result()
        self.assertEqual(result, [2, 4])

        iterdata = [(1, 1), (2, 2)]
        futures1 = fexec.map(simple_map_function, iterdata)
        result1 = fexec.get_result(fs=futures1)
        iterdata = [(3, 3), (4, 4)]
        futures2 = fexec.map(simple_map_function, iterdata)
        result2 = fexec.get_result(fs=futures2)
        self.assertEqual(result1, [2, 4])
        self.assertEqual(result2, [6, 8])

    def test_internal_executions(self):
        logger.info('Testing internal executions')
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.map(lithops_inside_lithops_map_function, range(1, 5))
        result = fexec.get_result()
        self.assertEqual(result, [list(range(i)) for i in range(1, 5)])

        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.call_async(lithops_return_futures_map_function1, 3)
        fexec.get_result()

        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.call_async(lithops_return_futures_map_function2, 3)
        fexec.get_result()

        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.call_async(lithops_return_futures_map_function3, 3)
        fexec.wait()
        fexec.get_result()
