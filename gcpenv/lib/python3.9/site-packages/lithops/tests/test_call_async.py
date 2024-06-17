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
from lithops.tests.util_func.map_util import simple_map_function

logger = logging.getLogger(__name__)

CONFIG = None
STORAGE_CONFIG = None
STORAGE = None


class TestAsync(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        global CONFIG, STORAGE, STORAGE_CONFIG

        CONFIG, STORAGE, STORAGE_CONFIG = main_util.get_config().values()

    @classmethod
    def setUp(cls):
        print('\n-------------------------------------------------------------\n')

    def test_call_async(self):
        def hello_world(param):
            return "Hello World!"

        logger.info('Testing call_async()')
        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.call_async(hello_world, "")
        result = fexec.get_result()
        self.assertEqual(result, "Hello World!")

        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.call_async(lambda x: " ".join(x), ["a", "b"])
        result = fexec.get_result()
        self.assertEqual(result, "a b")

        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.call_async(simple_map_function, (4, 6))
        result = fexec.get_result()
        self.assertEqual(result, 10)

        fexec = lithops.FunctionExecutor(config=CONFIG)
        fexec.call_async(simple_map_function, {'x': 2, 'y': 8})
        result = fexec.get_result()
        self.assertEqual(result, 10)


