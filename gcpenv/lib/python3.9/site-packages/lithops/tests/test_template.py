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

import subprocess
import unittest  # Mandatory. Required to incorporate the test class into the test framework
import lithops  # Mandatory, unless test class is confined to storage testing
from lithops.tests import main_util  # required to initialize config variables and other constants below.


# To utilize the project's logging capabilities:
import logging
logger = logging.getLogger(__name__)

# Global constants that upon necessity, can be initialized at setUpClass:
CONFIG = None  # contains the entire config data, including compute backend as well as STORAGE_CONFIG and STORAGE
STORAGE_CONFIG = None  # to get access to the details of the chosen storage, e.g - bucket in COS.
STORAGE = None  # storage class to directly use specific storage backend functions
TEST_FILES_URLS = None  # to run tests using the urls of the test files as parameters
PREFIX = '__lithops.test'  # prefix of the files uploaded to storage
DATASET_PREFIX = PREFIX + '/dataset'  # prefix of the dataset files uploaded to storage


class TestFeatureName(unittest.TestCase):  # Mandatory,unittest test classes are in camel format and inherit as demonstrated.
    words_in_cos_files = None  # an example of a class variable

    # method called once, before the tests are run.
    @classmethod
    def setUpClass(cls):

        # config variables to gain access to config variables as needed:
        global CONFIG, STORAGE, STORAGE_CONFIG, TEST_FILES_URLS
        CONFIG, STORAGE, STORAGE_CONFIG = main_util.get_config().values()

        TEST_FILES_URLS = main_util.get_data_sets()
        cls.words_in_cos_files = main_util.get_words_in_files()  # get number of words in test files for testing.

    # called once, after the tests are run.

    # @classmethod
    # def tearDownClass(cls):
    #     print('--------- All tests in template have been completed ---------')

    # Method called automatically before every single test method.

    # @classmethod
    # def setUp(cls):
    #     print('\n-------------------------------------------------------------\n')

    # Method called automatically after every single test method.

    # @classmethod
    # def tearDown(cls):
    #     print('--------- A test in template has been completed ---------')

# ------------------------------------ Incorporate your test function here ---------------------------------------------

    @unittest.skipIf(subprocess.getoutput("lithops --version").split()[2] >= "2.3.4",
                     "This test function isn't a part of the test procedure.")  # conditionally skip a test
    def test_example_function(self):  # unittest's function naming convention requires functions to be named as demonstrated.
        """A simple test function using memory against a lithop's map function."""

        from lithops.tests.util_func import map_util
        logger.info('Testing test_tester_name()')

        fexec = lithops.FunctionExecutor(config=CONFIG)  # Passing the config parameter to allow your test function to work on users that provided a path to the config file via a flag
        fexec.map(map_util.simple_map_function, [(1, 1), (2, 2), (3, 3), (4, 4)])
        result = fexec.get_result()
        self.assertEqual(result, [2, 4, 6, 8])
