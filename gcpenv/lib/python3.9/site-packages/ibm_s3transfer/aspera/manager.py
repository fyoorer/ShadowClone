# Copyright 2018 IBM Corp. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
import time
import json
import requests
import logging
import uuid
import six

import threading
from collections import OrderedDict
from collections import deque

from ibm_s3transfer.manager import TransferCoordinatorController
from ibm_s3transfer.futures import TransferMeta
from ibm_s3transfer.utils import CallArgs
from ibm_botocore.client import BaseClient
from ibm_botocore.credentials import DelegatedTokenManager
from ibm_s3transfer.exceptions import CancelledError
from ibm_s3transfer.exceptions import FatalError

from ibm_s3transfer.aspera.exceptions import AsperaTransferQueueError

from ibm_s3transfer.aspera.futures import AsperaTransferCoordinator
from ibm_s3transfer.aspera.futures import AsperaTransferFuture
from ibm_s3transfer.aspera.futures import enumAsperaDirection
from ibm_s3transfer.aspera.subscribers import AsperaBaseSubscriber
from ibm_s3transfer.aspera.utils import check_io_access, FilePair

try:
    from functools import lru_cache
except ImportError:
    from backports.functools_lru_cache import lru_cache

logger = logging.getLogger("ibmcos.aspera")

RECEIVER_CLIENT_IDS = 'aspera_ats'


class AsperaConfig(object):
    ''' AsperaConfig - Configurations used to update the Aspera transfer spec
        which controls how a file is transferred '''
    def __init__(self,
                 target_rate_mbps=None,
                 target_rate_cap_mbps=None,
                 min_rate_cap_mbps=None,
                 min_rate_mbps=None,
                 rate_policy=None,
                 lock_min_rate=None,
                 lock_target_rate=None,
                 lock_rate_policy=None,
                 multi_session=None,
                 multi_session_threshold_mb=None,
                 destination_root=None):
        """Configuration for the Aspera Uploads and Downloads
        :param target_rate_mbps:
                Integer: The desired speed of the transfer. If there is competing network traffic,
                         fasp may share this bandwidth, depending on the rate_policy.
        :param target_rate_cap_mbps:
                Integer: The maximum target rate for transfers that are authorized
                         by this access key,in kilobits per second.
        :param min_rate_cap_mbps:
        :param min_rate_mbps:
                Integer: The minimum speed of the transfer. fasp
                         will only share bandwidth exceeding this value.
                Note: This value has no effect if rate_policy is "fixed".
        :param rate_policy:
                fixed: Transfer at the target rate, regardless of the
                       actual network capacity. Do not share bandwidth.
                high:  When sharing bandwidth, transfer at twice the rate of a transfer
                       using a "fair" policy.
                fair (default): Share bandwidth equally with other traffic.
                low: Use only unutilized bandwidth
        :param lock_min_rate:
                True/False: Prevents the user from changing the minimum rate during a transfer.
        :param lock_target_rate:
                True/False: Prevents the user from changing the target rate during a transfer.
        :param lock_rate_policy:
                True/False: Prevents the user from changing the rate policy during a transfer.
        :param multi_session:
               Integer: The number of sessions to use to transfer a file or folder
               'all': if specified then multiple remote ips are used(if configured) in the transfer
        :param multi_session_threshold_mb:
               Integer: The MegaByte threshold size at which a single file can be split
               and transferred by multiple sessions
               Note: If value is below 60mb , then it is ignored
        :param destination_root:
                The transfer destination file path. If destinations are specified in paths,
                this value is prepended to each destination
        """
        self._dict = {}
        self.store("multi_session_threshold_mb", multi_session_threshold_mb, int,
                   "multi_session_threshold",  1000000, [60])

        self.store("target_rate_mbps",         target_rate_mbps, int,
                   "target_rate_kbps",    1000)

        self.store("target_rate_cap_mbps",     target_rate_cap_mbps, int,
                   "target_rate_cap_kbps", 1000)

        self.store("min_rate_cap_mbps",        min_rate_cap_mbps, int,
                   "min_rate_cap_kbps",   1000)

        self.store("min_rate_mbps",            min_rate_mbps, int,
                   "min_rate_kbps",       1000)

        self.store("rate_policy",              rate_policy, str,
                   allowed_values=['fixed', 'high', 'fair', 'low'])

        self.store("lock_min_rate",            lock_min_rate, bool)

        self.store("lock_target_rate",         lock_target_rate, bool)

        self.store("lock_rate_policy",         lock_rate_policy, bool)

        self.store("multi_session",            multi_session, int,
                   allowed_values=['all'])

        self.store("destination_root",         destination_root, str)

    def store(self, name, value, atype, new_name=None, multiplier=None, allowed_values=None):
        ''' store a config value in a dictionary, these values are used to populate a trasnfer spec
            validation -- check type, check allowed values and rename if required '''
        if value is not None:
            _bad_type = (not isinstance(value, atype))
            if not _bad_type:
                # special case
                _bad_type = (isinstance(value, bool) and atype == int)

            if _bad_type:
                # could be a special value
                if allowed_values and value in allowed_values:
                    allowed_values = None
                else:
                    raise ValueError("%s should be value of type (%s)" % (name, atype.__name__))

            if allowed_values:
                if isinstance(value, str):
                    if value not in allowed_values:
                        raise ValueError("%s can be %s" % (name, allowed_values))
                elif isinstance(value, int):
                    if isinstance(allowed_values[0], int):
                        if value < allowed_values[0]:
                            raise ValueError("%s must be >= %d" % (name, allowed_values[0]))

            _val = value if not multiplier else (multiplier * value)
            _name = name if not new_name else new_name
            self._dict[_name] = _val

    @property
    def dict(self):
        ''' get the config values stored in a dictinary '''
        return self._dict

    @property
    def multi_session(self):
        ''' convert the multi_session param a number '''
        _val = 0
        if "multi_session" in self._dict:
            _val = self._dict["multi_session"]
            if str(_val).lower() == 'all':
                _val = -1

        return int(_val)

    @property
    def is_multi_session_all(self):
        ''' is the multi_session param set to all '''
        return self.multi_session == -1


class AsperaManagerConfig(object):
    ''' AsperaManagerConfig - Configurations for the Aspera transfer mangager '''
    def __init__(self,
                 max_submission_queue_size=100,
                 ascp_max_concurrent=10,
                 ascp_log_path=None,
                 max_fasp_cache_size=1000,
                 verify_ssl=True):
        """Configuration for the Aspera Manager
        :param max_submission_queue_size:
            The maximum amount of AsperaTransferManager method calls that can be queued at a time.
        :param ascp_max_concurrent:
            The maximum number of ascp sub processes that can be running at a time.
        :param ascp_log_path:
            The path where Apera transfer logs are output to.
        :param max_fasp_cache_size:
        """
        self.max_submission_queue_size = max_submission_queue_size
        self.ascp_max_concurrent = ascp_max_concurrent
        self.ascp_log_path = ascp_log_path
        self.max_fasp_cache_size = max_fasp_cache_size
        self.verify_ssl = verify_ssl


class AsperaTransferManager(object):
    ''' AsperaTransferManager - a class to manage upload/downloads using the Aspera sdk '''
    def __init__(self, client, config=None, transfer_config=None, delegated_token_manager=None):

        assert(isinstance(client, BaseClient))
        if config:
            assert (isinstance(config, AsperaManagerConfig))
        if transfer_config:
            assert (isinstance(transfer_config, AsperaConfig))

        self._client = client
        self._transfer_config = transfer_config

        self._config = config
        if not self._config:
            self._config = AsperaManagerConfig()

        if self._config.ascp_log_path:
            AsperaTransferManager.set_log_details(self._config.ascp_log_path)

        self._coordinator_controller = AsperaTransferCoordinatorController(self._config)

        # Aspera metadata caching function
        self._get_aspera_metadata = (
            lru_cache(maxsize=self._config.max_fasp_cache_size)(self._raw_aspera_metadata))

        if delegated_token_manager:
            self._delegated_token_manager = delegated_token_manager
        else:
            _client_credentials = self._client._request_signer._credentials
            self._delegated_token_manager = (
                DelegatedTokenManager(api_key_id=_client_credentials.api_key_id,
                                      service_instance_id=_client_credentials.service_instance_id,
                                      auth_endpoint=_client_credentials.auth_endpoint,
                                      receiver_client_ids=RECEIVER_CLIENT_IDS,
                                      verify=self._config.verify_ssl))

    def _raw_aspera_metadata(self, bucket):
        ''' get the Aspera connection details on Aspera enabled buckets '''
        response = self._client.get_bucket_aspera(Bucket=bucket)

        # Parse metadata from response
        aspera_access_key = response['AccessKey']['Id']
        aspera_secret_key = response['AccessKey']['Secret']
        ats_endpoint = response['ATSEndpoint']

        return aspera_access_key, aspera_secret_key, ats_endpoint

    def _fetch_transfer_spec(self, node_action, token, bucket_name, paths):
        ''' make hhtp call to Aspera to fetch back trasnfer spec '''
        aspera_access_key, aspera_secret_key, ats_endpoint = self._get_aspera_metadata(bucket_name)

        _headers = {'accept': "application/json",
                    'Content-Type': "application/json"}

        credentials = {'type': 'token',
                       'token': {'delegated_refresh_token': token}}

        _url = ats_endpoint
        _headers['X-Aspera-Storage-Credentials'] = json.dumps(credentials)
        _data = {'transfer_requests': [
                {'transfer_request': {'paths': paths, 'tags': {'aspera': {
                 'node': {'storage_credentials': credentials}}}}}]}

        _session = requests.Session()
        _response = _session.post(url=_url + "/files/" + node_action,
                                  auth=(aspera_access_key, aspera_secret_key),
                                  headers=_headers, json=_data, verify=self._config.verify_ssl)
        return _response

    def _create_transfer_spec(self, call_args):
        ''' pass the transfer details to aspera and receive back a
            populated transfer spec complete with access token '''
        _paths = []
        for _file_pair in call_args.file_pair_list:
            _path = OrderedDict()
            if call_args.direction == enumAsperaDirection.SEND:
                _action = "upload_setup"
                _path['source'] = _file_pair.fileobj
                _path['destination'] = _file_pair.key
            else:
                _action = "download_setup"
                _path['source'] = _file_pair.key
                _path['destination'] = _file_pair.fileobj
            _paths.append(_path)

        # Add credentials before the transfer spec is requested.
        delegated_token = self._delegated_token_manager.get_token()
        _response = self._fetch_transfer_spec(_action, delegated_token, call_args.bucket, _paths)

        tspec_dict = json.loads(_response.content)['transfer_specs'][0]['transfer_spec']

        tspec_dict["destination_root"] = "/"

        if (call_args.transfer_config):
            tspec_dict.update(call_args.transfer_config.dict)
            if call_args.transfer_config.is_multi_session_all:
                tspec_dict['multi_session'] = 0
                _remote_host = tspec_dict['remote_host'].split('.')
                # now we append '-all' to the remote host
                _remote_host[0] += "-all"
                tspec_dict['remote_host'] = ".".join(_remote_host)
                logger.info("New remote_host(%s)" % tspec_dict['remote_host'])

        call_args.transfer_spec = json.dumps(tspec_dict)

        return True

    def upload_directory(self, directory, bucket, key, transfer_config=None, subscribers=None):
        ''' upload a directory using Aspera '''
        check_io_access(directory, os.R_OK)
        return self._queue_task(bucket, [FilePair(key, directory)], transfer_config,
                                subscribers, enumAsperaDirection.SEND)

    def download_directory(self, bucket, key, directory, transfer_config=None, subscribers=None):
        ''' download a directory using Aspera '''
        check_io_access(directory, os.W_OK)
        return self._queue_task(bucket, [FilePair(key, directory)], transfer_config,
                                subscribers, enumAsperaDirection.RECEIVE)

    def upload(self, fileobj, bucket, key, transfer_config=None, subscribers=None):
        ''' upload a file using Aspera '''
        check_io_access(fileobj, os.R_OK, True)
        return self._queue_task(bucket, [FilePair(key, fileobj)], transfer_config,
                                subscribers, enumAsperaDirection.SEND)

    def download(self, bucket, key, fileobj, transfer_config=None, subscribers=None):
        ''' download a file using Aspera '''
        check_io_access(os.path.dirname(fileobj), os.W_OK)
        return self._queue_task(bucket, [FilePair(key, fileobj)], transfer_config,
                                subscribers, enumAsperaDirection.RECEIVE)

    @staticmethod
    def set_log_details(aspera_log_path=None,
                        sdk_log_level=logging.NOTSET):
        ''' set the aspera log path - used by th Ascp process
            set the internal aspera sdk activity - for debug purposes '''
        if aspera_log_path:
            check_io_access(aspera_log_path, os.W_OK)
            AsperaTransferCoordinator.set_log_location(aspera_log_path)

        if sdk_log_level != logging.NOTSET:
            if logger:
                if not len(logger.handlers):
                    handler = logging.StreamHandler()
                    _fmt = '%(asctime)s %(levelname)s %(message)s'
                    handler.setFormatter(logging.Formatter(_fmt))
                    logger.addHandler(handler)
                    logger.setLevel(sdk_log_level)

    def _validate_args(self, args):
        ''' validate the user arguments '''
        assert(args.bucket)

        if args.subscribers:
            for _subscriber in args.subscribers:
                assert(isinstance(_subscriber, AsperaBaseSubscriber))

        if (args.transfer_config):
            assert(isinstance(args.transfer_config, AsperaConfig))

            # number of sessions requested cant be greater than max ascps
            if args.transfer_config.multi_session > self._config.ascp_max_concurrent:
                raise ValueError("Max sessions is %d" % self._config.ascp_max_concurrent)

        for _pair in args.file_pair_list:
            if not _pair.key or not _pair.fileobj:
                raise ValueError("Invalid file pair")

    def _queue_task(self, bucket, file_pair_list, transfer_config, subscribers, direction):
        ''' queue the upload/download - when get processed when resources available
            Use class level transfer_config if not defined. '''
        config = transfer_config if transfer_config else self._transfer_config

        _call_args = CallArgs(bucket=bucket,
                              file_pair_list=file_pair_list,
                              transfer_config=config,
                              subscribers=subscribers,
                              direction=direction,
                              transfer_spec=None,
                              transfer_spec_func=self._create_transfer_spec,
                              transfer_id=str(uuid.uuid4()))

        self._validate_args(_call_args)
        return self._coordinator_controller._queue_task(_call_args)

    def __enter__(self):
        ''' enter the AsperaTransferManager scope '''
        return self

    def __exit__(self, exc_type, exc_value, *args):
        ''' exit the AsperaTransferManager scope
            cancel all running transfers and free resources  '''
        cancel = False
        cancel_msg = ''
        cancel_exc_type = FatalError
        # If a exception was raised in the context handler, signal to cancel
        # all of the in progress futures in the shutdown.
        if exc_type:
            cancel = True
            cancel_msg = six.text_type(exc_value)
            if not cancel_msg:
                cancel_msg = repr(exc_value)
            # If it was a KeyboardInterrupt, the cancellation was initiated by the user.
            if isinstance(exc_value, KeyboardInterrupt):
                cancel_exc_type = CancelledError
        self._shutdown(cancel, cancel_msg, cancel_exc_type)

    def shutdown(self, cancel=False, cancel_msg=''):
        """Shutdown the TransferManager
        waits till all transfers complete before it completely shuts down.

        :type cancel: boolean
        :param cancel: If True, calls TransferFuture.cancel() for
            all in-progress in transfers. This is useful if you want the
            shutdown to happen quicker.

        :type cancel_msg: str
        :param cancel_msg: The message to specify if canceling all in-progress
            transfers.
        """
        self._shutdown(cancel, cancel, cancel_msg)

    def _shutdown(self, cancel, cancel_msg, exc_type=CancelledError):
        ''' Internal shutdown used by 'shutdown' method  above '''
        if cancel:
            # Cancel all in-flight transfers if requested, before waiting
            # for them to complete.
            self._coordinator_controller.cancel(cancel_msg, exc_type)
        try:
            # Wait until there are no more in-progress transfers. This is
            # wrapped in a try statement because this can be interrupted
            # with a KeyboardInterrupt that needs to be caught.
            self._coordinator_controller.wait()
        except KeyboardInterrupt:
            # If not errors were raised in the try block, the cancel should
            # have no coordinators it needs to run cancel on. If there was
            # an error raised in the try statement we want to cancel all of
            # the inflight transfers before shutting down to speed that
            # process up.
            self._coordinator_controller.cancel('KeyboardInterrupt()')
            raise
        finally:
            self._coordinator_controller.cleanup()

    def wait(self):
        ''' wait for all transfers complete '''
        self._coordinator_controller.wait()


class AsperaTransferCoordinatorController(TransferCoordinatorController):
    def __init__(self, config):
        """ Abstraction to control all transfer coordinators
            This abstraction allows the manager to wait for inprogress transfers
            to complete and cancel all inprogress transfers."""
        super(AsperaTransferCoordinatorController, self).__init__()
        self._config = config
        self._waiting_transfer_coordinators = deque()
        self._processed_coordinators = []
        self._lockw = threading.Lock()
        self._processing_thread = None
        self._processing_event = threading.Event()
        self._processing_stopped_event = threading.Event()
        self._processing_stop = False
        self._cancel_called = False
        self._wait_called = False

    def cleanup(self):
        ''' Stop backgroud thread and cleanup resources '''
        self._processing_stop = True
        self._wakeup_processing_thread()
        self._processing_stopped_event.wait(3)

    def tracked_coordinator_count(self, count_ascps=False):
        ''' count the number of cooridnators currently being processed
        or count the number of ascps currently being used '''
        with self._lock:
            _count = 0
            if count_ascps:
                for _coordinator in self._tracked_transfer_coordinators:
                    _count += _coordinator.session_count
            else:
                _count = len(self._tracked_transfer_coordinators)
            return _count

    def _in_waiting_queue(self, _coordinator):
        ''' check to see if a coordinator object is in the waiting queue '''
        with self._lockw:
            return _coordinator in self._waiting_transfer_coordinators

    def waiting_coordinator_count(self):
        ''' count the number of transfers waiting to be processed '''
        with self._lockw:
            return len(self._waiting_transfer_coordinators)

    def _queue_task(self, args):
        ''' add transfer to waiting queue if possible
            then notify the background thread to process it '''
        if self._cancel_called:
            raise AsperaTransferQueueError("Cancel already called")
        elif self._wait_called:
            raise AsperaTransferQueueError("Cant queue items during wait")
        elif self.waiting_coordinator_count() >= self._config.max_submission_queue_size:
            raise AsperaTransferQueueError("Max queued items reached")
        else:
            _coordinator = AsperaTransferCoordinator(args)
            _components = {'meta': TransferMeta(args, transfer_id=args.transfer_id),
                           'coordinator': _coordinator}

            _transfer_future = AsperaTransferFuture(**_components)
            _coordinator.add_subscribers(args.subscribers, future=_transfer_future)
            _coordinator.add_done_callback(self.remove_aspera_coordinator,
                                           transfer_coordinator=_coordinator)
            self.append_waiting_queue(_coordinator)

            if not self._processing_thread:
                self._processing_thread = threading.Thread(target=self._process_waiting_queue)
                self._processing_thread.daemon = True
                self._processing_thread.start()

            self._wakeup_processing_thread()

        return _transfer_future

    def remove_aspera_coordinator(self, transfer_coordinator):
        ''' remove entry from the waiting waiting
            or remove item from processig queue and add to processed quque
            notify background thread as it may be able to process watiign requests
        '''
        # usually called on processing completion - but can be called for a cancel
        if self._in_waiting_queue(transfer_coordinator):
            logger.info("Remove from waiting queue count=%d" % self.waiting_coordinator_count())
            with self._lockw:
                self._waiting_transfer_coordinators.remove(transfer_coordinator)
        else:
            logger.info("Remove from processing queue count=%d" % self.tracked_coordinator_count())
            try:
                self.remove_transfer_coordinator(transfer_coordinator)
                self.append_processed_queue(transfer_coordinator)
            except Exception:
                pass

            self._wakeup_processing_thread()

    def append_waiting_queue(self, transfer_coordinator):
        ''' append item to waiting queue '''
        logger.debug("Add to waiting queue count=%d" % self.waiting_coordinator_count())
        with self._lockw:
            self._waiting_transfer_coordinators.append(transfer_coordinator)

    def _wakeup_processing_thread(self):
        ''' set the threading event to wakeup background thread '''
        self._processing_event.set()

    def append_processed_queue(self, transfer_coordinator):
        ''' append item to processed queue '''
        with self._lock:
            self._processed_coordinators.append(transfer_coordinator)

    def free_processed_queue(self):
        ''' call the Aspera sdk to freeup resources '''
        with self._lock:
            if len(self._processed_coordinators) > 0:
                for _coordinator in self._processed_coordinators:
                    _coordinator.free_resources()
                self._processed_coordinators = []

    def is_stop(self):
        ''' has either of the stop processing flags been set '''
        if len(self._processed_coordinators) > 0:
            self.free_processed_queue()
        return self._cancel_called or self._processing_stop

    def _process_waiting_queue(self):
        ''' thread to processes the waiting queue
            fetches transfer spec
            then calls start transfer
            ensures that max ascp is not exceeded '''
        logger.info("Queue processing thread started")
        while not self.is_stop():
            self._processing_event.wait(3)
            self._processing_event.clear()
            if self.is_stop():
                break

            while self.waiting_coordinator_count() > 0:
                if self.is_stop():
                    break
                _used_slots = self.tracked_coordinator_count(True)
                _free_slots = self._config.ascp_max_concurrent - _used_slots
                if _free_slots <= 0:
                    break

                with self._lockw:
                    # check are there enough free slots
                    _req_slots = self._waiting_transfer_coordinators[0].session_count
                    if _req_slots > _free_slots:
                        break
                    _coordinator = self._waiting_transfer_coordinators.popleft()
                    self.add_transfer_coordinator(_coordinator)

                if not _coordinator.set_transfer_spec():
                    self.remove_aspera_coordinator(_coordinator)
                else:
                    logger.info("ASCP process queue - Max(%d) InUse(%d) Free(%d) New(%d)" %
                                (self._config.ascp_max_concurrent,
                                 _used_slots,
                                 _free_slots,
                                 _req_slots))
                    _coordinator.start_transfer()

        logger.info("Queue processing thread stopped")
        self._processing_stopped_event.set()

    def clear_waiting_coordinators(self, cancel=False):
        ''' remove all entries from waiting queue or cancell all in waiting queue '''
        with self._lockw:
            if cancel:
                for _coordinator in self._waiting_transfer_coordinators:
                    _coordinator.notify_cancelled("Clear Waiting Queue", False)
            self._waiting_transfer_coordinators.clear()

    def cancel(self, *args, **kwargs):
        """ Cancel all queue items - then attempt to cancel all in progress items """
        self._cancel_called = True
        self.clear_waiting_coordinators(cancel=True)
        super(AsperaTransferCoordinatorController, self).cancel(*args, **kwargs)

    def wait(self):
        """ Wait until all in progress and queued items are processed """
        self._wait_called = True
        while self.tracked_coordinator_count() > 0 or \
                self.waiting_coordinator_count() > 0:
            time.sleep(1)
            super(AsperaTransferCoordinatorController, self).wait()
        self._wait_called = False
