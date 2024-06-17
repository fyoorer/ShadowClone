import os
import logging
from datetime import datetime, timezone
from ibm_botocore.credentials import DefaultTokenManager

from lithops.utils import is_lithops_worker
from lithops.config import load_yaml_config, dump_yaml_config
from lithops.constants import CACHE_DIR

logger = logging.getLogger(__name__)


class IBMTokenManager:

    def __init__(self, api_key, api_key_type='IAM', token=None, token_expiry_time=None):
        self.api_key = api_key
        self.api_key_type = api_key_type

        self._token_manager = DefaultTokenManager(api_key_id=self.api_key)
        self._token_filename = os.path.join(CACHE_DIR, 'ibm_{}'.format(api_key_type.lower()), 'token')

        if token:
            logger.debug("Using IBM {} API Key - Reusing Token from config".format(self.api_key_type))
            self._token_manager._token = token
            self._token_manager._expiry_time = datetime.strptime(token_expiry_time,
                                                                 '%Y-%m-%d %H:%M:%S.%f%z')
            logger.debug("Token expiry time: {} - Minutes left: {}"
                         .format(self._token_manager._expiry_time,
                                 self._get_token_minutes_diff()))

        elif os.path.exists(self._token_filename):
            logger.debug("Using IBM {} API Key - Reusing Token from local cache".format(self.api_key_type))
            token_data = load_yaml_config(self._token_filename)
            self._token_manager._token = token_data['token']
            self._token_manager._expiry_time = datetime.strptime(token_data['token_expiry_time'],
                                                                 '%Y-%m-%d %H:%M:%S.%f%z')
            logger.debug("Token expiry time: {} - Minutes left: {}".
                         format(self._token_manager._expiry_time,
                                self._get_token_minutes_diff()))

    def _is_token_expired(self):
        """
        Checks if a token already expired
        """
        return self._get_token_minutes_diff() < 1

    def _get_token_minutes_diff(self):
        """
        Gets the remaining minutes in which the current token is valid
        """
        expiry_time = self._token_manager._expiry_time
        return max(0, int((expiry_time - datetime.now(timezone.utc)).total_seconds() / 60.0))

    def _generate_new_token(self):
        self._token_manager._token = None
        self._token_manager.get_token()
        token_data = {}
        token_data['token'] = self._token_manager._token
        token_data['token_expiry_time'] = self._token_manager._expiry_time.strftime('%Y-%m-%d %H:%M:%S.%f%z')
        dump_yaml_config(self._token_filename, token_data)
        logger.debug("Token expiry time: {} - Minutes left: {}".
                     format(self._token_manager._expiry_time,
                            self._get_token_minutes_diff()))

    def get_token(self):
        """
        Gets a new token within a mutex block to prevent multiple threads
        requesting new tokens at the same time.
        """
        if (self._token_manager._is_expired() or self._is_token_expired()) \
           and not is_lithops_worker():
            logger.debug("Token expired. Requesting new token")
            self._generate_new_token()

        token = self._token_manager._token
        token_expiry_time = self._token_manager._expiry_time.strftime('%Y-%m-%d %H:%M:%S.%f%z')

        return token, token_expiry_time
