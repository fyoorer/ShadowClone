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

import logging

logger = logging.getLogger(__name__)

CONFIG = None
STORAGE_CONFIG = None
STORAGE = None
TEST_FILES_URLS = None
WORDS_IN_DATA_SET = None


def init_config(config, storage, storage_config, words_in_data_set, test_files_urls):
    global CONFIG, STORAGE, STORAGE_CONFIG, WORDS_IN_DATA_SET, TEST_FILES_URLS

    CONFIG, STORAGE, STORAGE_CONFIG, WORDS_IN_DATA_SET, TEST_FILES_URLS = \
        config, storage, storage_config, words_in_data_set, test_files_urls


def get_config():
    return {'config': CONFIG, 'storage': STORAGE, 'storage_config': STORAGE_CONFIG}


def get_data_sets():
    """returns urls to data-sets that contains many single word rows (for easy processing) """
    return TEST_FILES_URLS


def get_words_in_files():
    return WORDS_IN_DATA_SET
