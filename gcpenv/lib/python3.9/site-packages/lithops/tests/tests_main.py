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
import argparse
import os
from importlib import import_module
import inspect
import pathlib
import sys
import unittest
import logging
import urllib.request
from os import walk

from lithops.storage import Storage
from lithops.config import default_config, extract_storage_config, load_yaml_config
from concurrent.futures import ThreadPoolExecutor
from lithops.tests import main_util
from lithops.tests.util_func.storage_util import clean_tests
from lithops.utils import setup_lithops_logger

TEST_MODULES = None  # test files, e.g. test_map
TEST_GROUPS = {}  # dict of test classes in the format: {test class names:test class objects}
CONFIG = None
STORAGE_CONFIG = None
STORAGE = None
PREFIX = '__lithops.test'
DATASET_PREFIX = PREFIX + '/dataset'

TEST_FILES_URLS = ["http://archive.ics.uci.edu/ml/machine-learning-databases/bag-of-words/vocab.enron.txt",
                   "http://archive.ics.uci.edu/ml/machine-learning-databases/bag-of-words/vocab.kos.txt",
                   "http://archive.ics.uci.edu/ml/machine-learning-databases/bag-of-words/vocab.nips.txt",
                   "http://archive.ics.uci.edu/ml/machine-learning-databases/bag-of-words/vocab.nytimes.txt",
                   "http://archive.ics.uci.edu/ml/machine-learning-databases/bag-of-words/vocab.pubmed.txt"]

logger = logging.getLogger(__name__)


def get_tests_of_class(class_obj):
    """returns a list of all test methods of a given test class """
    method_list = []
    for attribute in dir(class_obj):
        attribute_value = getattr(class_obj, attribute)
        if callable(attribute_value):
            if attribute.startswith('test'):
                method_list.append(attribute)
    return method_list


def print_test_functions():
    """responds to '-t help' from CLI by printing the test functions within the various test_modules"""
    print("\nAvailable test functions:")
    init_test_variables()

    for test_group in sorted(TEST_GROUPS.keys()):
        print(f'\n{test_group}:')
        for test in get_tests_of_class(TEST_GROUPS[test_group]):
            print(f'    ->{test}')


def print_test_groups():
    """responds to '-g help' from CLI by printing test groups within the various test_modules, e.g. storage/map etc. """
    print("\nAvailable test groups:\n")
    init_test_variables()
    for test_group in sorted(TEST_GROUPS.keys()):
        print(f'{test_group} \n-----------------')


def register_test_groups():
    """initializes the TEST_GROUPS variable - test classes within given test modules"""
    global TEST_GROUPS
    for module in TEST_MODULES:
        group_name = str(module).split('test_')[1].split('\'')[0]
        # A test group is created for every module that contains a class inheriting from unittest.TestCase.
        for member in inspect.getmembers(module, inspect.isclass):
            if issubclass(member[1], unittest.TestCase):
                TEST_GROUPS[group_name] = member[1]


def import_test_modules():
    """dynamically imports test modules from test files within the tests package"""
    global TEST_MODULES
    TEST_MODULES = [import_module(module) for module in ["lithops.tests." + file[:-3]
                                                         for file in
                                                         next(walk(pathlib.Path(__file__).parent.absolute()))[2]
                                                         if file.startswith("test_")]]


def init_test_variables():
    """initializes the global TEST variables in case they haven't been initialized"""
    if not TEST_MODULES:
        import_test_modules()
    if not TEST_GROUPS:
        register_test_groups()


def upload_data_sets():
    """uploads datasets to storage and return a list of the number of words within each test file"""

    def up(param):
        logger.info(f'Uploading dataset {param[1]}')
        i, url = param
        content = urllib.request.urlopen(url).read()
        STORAGE.put_object(bucket=STORAGE_CONFIG['bucket'],
                           key=f'{DATASET_PREFIX}/test{str(i)}',
                           body=content)
        return len(content.split())

    with ThreadPoolExecutor() as pool:
        results = list(pool.map(up, enumerate(TEST_FILES_URLS)))
    result_to_compare = sum(results)
    return result_to_compare


def config_suite(suite, tests, groups):
    """ Loads tests into unittest's test-suite according to user input.  """

    if groups:  # user specified the name(s) of a test group(s)
        groups_list = groups.split(',')
        for test_group in groups_list:
            if test_group in TEST_GROUPS:
                suite.addTest(unittest.makeSuite(TEST_GROUPS[test_group]))
            else:
                terminate('group', test_group)

    if tests:
        if tests == 'all':
            for test_class in TEST_GROUPS.values():  # values of TEST_GROUPS are test class objects.
                suite.addTest(unittest.makeSuite(test_class))

        else:  # user specified specific test/s
            tests_list = tests.split(',')
            for test in tests_list:
                test_found = False

                if test.find(
                        '.') != -1:  # user specified a test class along with the tester, i.e <TestClass.tester_name>
                    test_class = TEST_GROUPS.get(test.split('.')[0])
                    test_name = test.split('.')[1]
                    if test_name in get_tests_of_class(test_class):
                        suite.addTest(test_class(test_name))
                        test_found = True

                else:  # user simply specified a test function, i.e <tester_name>
                    for test_class in TEST_GROUPS.values():
                        if test in get_tests_of_class(test_class):
                            suite.addTest(test_class(test))
                            test_found = True

                if not test_found:
                    terminate('test', test)


def run_tests(tests, config=None, group=None, backend=None, storage=None, fail_fast=False,
              keep_datasets=False):
    global CONFIG, STORAGE_CONFIG, STORAGE

    config_ow = {'lithops': {}}
    if storage:
        config_ow['lithops']['storage'] = storage
    if backend:
        config_ow['lithops']['backend'] = backend

    CONFIG = default_config(config, config_ow)
    STORAGE_CONFIG = extract_storage_config(CONFIG)
    STORAGE = Storage(storage_config=STORAGE_CONFIG)
    init_test_variables()

    suite = unittest.TestSuite()
    config_suite(suite, tests, group)
    words_in_data_set = upload_data_sets()  # uploads datasets and returns word count
    main_util.init_config(CONFIG, STORAGE, STORAGE_CONFIG, words_in_data_set, TEST_FILES_URLS)

    runner = unittest.TextTestRunner(verbosity=2, failfast=fail_fast)
    tests_results = runner.run(suite)

    # removes previously uploaded datasets from storage.
    if not keep_datasets:
        clean_tests(STORAGE, STORAGE_CONFIG, PREFIX)

    if not tests_results.wasSuccessful():  # Fails github workflow action to reject merge to repository
        sys.tracebacklimit = 0  # avoid displaying redundant stack track-back info
        raise Exception("--------Test procedure failed. Merge rejected--------")


def terminate(msg_type, failed_input):
    if msg_type == 'group':  # group not found
        print(f'unknown test group: {failed_input}, use: "test -g help" to get a list of the available test groups')
    else:  # test not found
        print(f'unknown test: {failed_input}, use: "test -t help" to get a list of the available testers')
    sys.exit()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="test all Lithops's functionality",
                                     usage='python -m lithops.tests.tests_main [-c CONFIG] [-t TESTNAME] ...')
    parser.add_argument('-c', '--config', metavar='', default=None,
                        help="'path to yaml config file")
    parser.add_argument('-t', '--test', metavar='', default='all',
                        help='run a specific test, type "-t help" for tests list')
    parser.add_argument('-g', '--groups', metavar='', default='',
                        help='run all tests belonging to a specific group.'
                             ' type "-g help" for groups list')
    parser.add_argument('-b', '--backend', metavar='', default=None,
                        help='compute backend')
    parser.add_argument('-s', '--storage', metavar='', default=None,
                        help='storage backend')
    parser.add_argument('-d', '--debug', action='store_true', default=False,
                        help='activate debug logging')
    parser.add_argument('-f', '--fail_fast', action='store_true', default=False,
                        help='Stops test run upon first occurrence of a failed test')
    parser.add_argument('-k', '--keep_datasets', action='store_true', default=False,
                        help='keeps datasets in storage after the test run. '
                             'Mainly for some instances in github workflow.')
    args = parser.parse_args()

    if args.config:
        if os.path.exists(args.config):
            args.config = load_yaml_config(args.config)
        else:
            raise FileNotFoundError("Provided config file '{}' does not exist".format(args.config))

    log_level = logging.INFO if not args.debug else logging.DEBUG
    setup_lithops_logger(log_level)

    if args.groups and args.test == 'all':  # if user specified test a group(s) avoid running all tests.
        args.test = ''

    if args.groups == 'help':
        print_test_groups()
    elif args.test == 'help':
        print_test_functions()
    else:
        run_tests(args.test, args.config, args.groups, args.backend,
                  args.storage, args.fail_fast, args.keep_datasets)
