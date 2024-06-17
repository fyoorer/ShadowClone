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
import functools
import logging
import os
import threading
import time
import warnings

from ibm_s3transfer.aspera.exceptions import *
from ibm_s3transfer.futures import TransferMeta
from ibm_s3transfer.exceptions import CancelledError, TransferNotDoneError
from ibm_s3transfer.compat import MAXINT

try:
    from cos_aspera import faspmanager2
    warnings.warn("Using Aspera through the COS SDK is deprecated. Refer to the project readme: https://github.com/IBM/ibm-cos-sdk-python")
    faspmanager2.configureAsperaLocation(os.path.dirname(faspmanager2.__file__))
except ImportError:
    raise ImportError("Aspera SDK not installed")

logger = logging.getLogger("ibmcos.aspera")
logger.warning("Using Aspera through the COS SDK is deprecated. Refer to the project readme: https://github.com/IBM/ibm-cos-sdk-python")


class enumAsperaMsgType():
    ''' enum class - valid message types received in the Aspera callback '''
    INIT = "INIT"
    SESSION = "SESSION"
    NOTIFICATION = "NOTIFICATION"
    STATS = "STATS"
    ARGSTOP = "ARGSTOP"
    STOP = "STOP"
    DONE = "DONE"
    ERROR = "ERROR"
    FILEERROR = "FILEERROR"


class enumAsperaControllerStatus():
    ''' enum class - coordinator class status '''
    CREATED = "new"
    RUNNING = "running"
    FAILED = "failed"
    SUCCESS = "success"
    PAUSED = "paused"
    CANCELLED = "cancelled"


class enumAsperaDirection():
    ''' enum class - direction of transfer '''
    SEND = "send"
    RECEIVE = "receive"


class enumAsperaModifyTransfer():
    ''' enum class - actions that can performed in progress transfer '''
    target_rate_kbps = 1
    min_rate_kbps = 2
    priority = 3
    CTRL_PAUSE = 4
    CTRL_RESUME = 5


class AsperaTransferFuture(object):
    def __init__(self, meta=None, coordinator=None):
        """The future associated to a submitted transfer request

        :type meta: TransferMeta
        :param meta: The metadata associated to the request. This object
            is visible to the requester.

        :type coordinator: TransferCoordinator
        :param coordinator: The coordinator associated to the request. This
            object is not visible to the requester.
        """
        self._meta = meta
        self._coordinator = coordinator

    @property
    def meta(self):
        """The metadata associated with the TransferFuture"""
        return self._meta

    def is_done(self):
        """Determines if a TransferFuture has completed

        :returns: True if completed. False, otherwise.
        """
        return self._coordinator.is_done()

    def result(self):
        """Waits until TransferFuture is done and returns the result
        If the TransferFuture succeeded, it will return the result.
        If the TransferFuture failed, it will raise the exception
        associated to the failure. """
        try:
            # Usually the result() method blocks until the transfer is done,
            # however if a KeyboardInterrupt is raised we want want to exit
            # out of this and propogate the exception.
            return self._coordinator.result()
        except KeyboardInterrupt as e:
            self.cancel()
            # raise AsperaTransferFailedError("Keyboard Interrupt")
            raise e

    def cancel(self):
        """Cancels the request associated with the TransferFuture"""
        return self._coordinator.cancel()

    def pause(self):
        """Pause the request associated with the TransferFuture"""
        return self._coordinator.pause()

    def resume(self):
        """Resume the request associated with the TransferFuture"""
        return self._coordinator.resume()

    def set_exception(self, exception):
        """Sets the exception on the future."""
        if not self.is_done():
            raise TransferNotDoneError(
                'set_exception can only be called once the transfer is '
                'complete.')
        self._coordinator.set_exception(exception, override=True)

    def is_error(self):
        """ Has the transfer failed."""
        return self._coordinator.is_failed()

    def is_success(self):
        """ Has the transfer completed ok."""
        return self._coordinator.is_success()

    def get_last_error(self):
        """ Fetch the last error set in object."""
        return self._coordinator.get_last_error()


class AsperaTransferListener(faspmanager2.ITransferListener):
    ''' the class that provides the connectivity between the Aspera sdk and ibmcos sdk '''
    def __init__(self):
        super(AsperaTransferListener, self).__init__()
        self._sessions = {}
        self._session_lock = threading.Lock()
        self._is_stopped = False
        self._is_stopping = False

    def debug_id(self, xferId, session_id):
        ''' get last part of xferId and session_id to create an abrreviated id '''
        return xferId.split('-')[4] + "-" + session_id.split('-')[4]

    def transferReporter(self, xferId, message):
        ''' the callback method used by the Aspera sdk during transfer
            to notify progress, error or successful completion
        '''
        if self.is_stopped():
            return True

        _asp_message = AsperaMessage(message)

        if not _asp_message.is_msg_type(
            [enumAsperaMsgType.INIT,
             enumAsperaMsgType.DONE,
             enumAsperaMsgType.ERROR,
             enumAsperaMsgType.FILEERROR,
             enumAsperaMsgType.STATS]):
                return

        _session_id = _asp_message.get_session_id()

        _msg = self.debug_id(xferId, _session_id) + " : " + _asp_message._msg_type
        logger.info(_msg)

        with self._session_lock:
            if _asp_message.is_msg_type([enumAsperaMsgType.INIT]):
                assert(_session_id not in self._sessions)
                _session = AsperaSession(_session_id)
                self._sessions[_session_id] = _session
                self.notify_init()
            else:
                _session = self._sessions[_session_id]

        if _asp_message.is_msg_type([enumAsperaMsgType.DONE]):
            if _session.set_bytes_transferred(_asp_message.get_bytes_transferred()):
                self.notify_progress()
            _session.set_success()
            self.notify_done()
        elif _asp_message.is_msg_type([enumAsperaMsgType.ERROR, enumAsperaMsgType.FILEERROR]):
            _session.set_error(_asp_message.get_error_descr())
            self.notify_done(error=True)
        elif _asp_message.is_msg_type([enumAsperaMsgType.STATS]):
            if _session.set_bytes_transferred(_asp_message.get_bytes_transferred()):
                self.notify_progress()

    def start_transfer(self):
        ''' pass the transfer spec to the Aspera sdk and start the transfer '''
        try:
            if not self.is_done():
                faspmanager2.startTransfer(self.get_transfer_id(),
                                           None,
                                           self.get_transfer_spec(),
                                           self)
        except Exception as ex:
            self.notify_exception(ex)

    def pause(self):
        ''' send a pause transfer request to the Aspera sdk '''
        return self._modify_transfer(enumAsperaModifyTransfer.CTRL_PAUSE)

    def resume(self):
        ''' send a resume request to the Aspera sdk
            the transfer must be in a paused state '''
        return self._modify_transfer(enumAsperaModifyTransfer.CTRL_RESUME)

    def _cancel(self):
        ''' call stop to cancel the in progress transfer '''
        return self.stop()

    def is_running(self, is_stopped):
        ''' check whether a transfer is currently running '''
        if is_stopped and self.is_stopped():
            return False

        return faspmanager2.isRunning(self.get_transfer_id())

    def is_stopped(self, is_stopping=True):
        ''' check whether a transfer is stopped or is being stopped '''
        if is_stopping:
            return self._is_stopped or self._is_stopping
        return self._is_stopped

    def _modify_transfer(self, option, value=0):
        ''' call Apsera sdk modify an in progress eg pause/resume
            allowed values defined in enumAsperaModifyTransfer class '''
        _ret = False
        try:
            if self.is_running(True):
                logger.info("ModifyTransfer called %d = %d" % (option, value))
                _ret = faspmanager2.modifyTransfer(self.get_transfer_id(), option, value)
                logger.info("ModifyTransfer returned %s" % _ret)
        except Exception as ex:
            self.notify_exception(ex)

        return _ret

    def stop(self, free_resource=False):
        ''' send a stop transfer request to the Aspera sdk, can  be done for:
            cancel - stop an in progress transfer
            free_resource - request to the Aspera sdk free resouces related to trasnfer_id
        '''
        if not self.is_stopped():
            self._is_stopping = True
            try:
                if free_resource or self.is_running(False):
                    if not free_resource:
                        logger.info("StopTransfer called - %s" % self.get_transfer_id())
                    self._is_stopped = faspmanager2.stopTransfer(self.get_transfer_id())
                    if not free_resource:
                        logger.info("StopTransfer returned %s - %s" % (
                                    self._is_stopped, self.get_transfer_id()))
            except Exception as ex:
                self.notify_exception(ex)

            self._is_stopping = False

        return self.is_stopped(False)

    def free_resources(self):
        ''' call stop to free up resources '''
        if not self.is_stopped():
            logger.info("Freeing resources: %s" % self.get_transfer_id())
            self.stop(True)

    @staticmethod
    def set_log_location(aspera_log_path):
        ''' set the local path where the Aspera/ASCP log files will be stored '''
        try:
            if aspera_log_path:
                faspmanager2.configureLogLocation(aspera_log_path)
        except Exception as ex:
            raise ex


class AsperaMessage(object):
    ''' wrapper class to manage an Aspera callback message data string '''
    def __init__(self, message):
        self._message = message
        self._msg_type = self.get_message_type()

    def is_msg_type(self, types):
        ''' is the current message_type in a list of message types '''
        return self._msg_type in types

    def extract_message_value(self, name):
        ''' search message to find and extract a named value '''
        name += ":"
        assert(self._message)
        _start = self._message.find(name)
        if _start >= 0:
            _start += len(name) + 1
            _end = self._message.find("\n", _start)
            _value = self._message[_start:_end]
            return _value.strip()

        return None

    def get_session_id(self):
        ''' extract SessionId from message '''
        return self.extract_message_value("SessionId")

    def get_error_descr(self):
        ''' extract Description from message '''
        return self.extract_message_value("Description")

    def get_message_type(self):
        ''' extract Type from message '''
        return self.extract_message_value("Type")

    def get_bytes_transferred(self):
        ''' extract TransferBytes from message '''
        return self.extract_message_value("TransferBytes")


class AsperaSession(object):
    ''' Aspera uses one or more sessions to transfer a file -
        this class holds state information between callbacks '''
    PROGRESS_MSGS_SEND_ALL = False

    def __init__(self, session_id):
        ''' Each session has a corresponding Aspera Ascp process which passes
            back messages via the callback.These messages contain state,
            error, progress details which is stored in this object '''
        self.session_id = session_id
        self._exception = None
        self._status = None
        self._status = enumAsperaControllerStatus.CREATED
        self._done_event = threading.Event()
        self._bytes_transferred = 0

    def set_done(self):
        ''' set the done event - indicates processing complete '''
        self._done_event.set()

    def _set_status(self, status, ex=None):
        ''' set session status - eg failed, success --
            valid values contained in enumAsperaControllerStatus class '''
        self._status = status
        logger.debug("Set status(%s) for %s" % (self._status, self.session_id))
        self.set_done()
        if ex:
            self._exception = ex

    def set_bytes_transferred(self, bytes_transferred):
        ''' set the number of bytes transferred - if it has changed return True '''
        _changed = False
        if bytes_transferred:
            _changed = (self._bytes_transferred != int(bytes_transferred))
            if _changed:
                self._bytes_transferred = int(bytes_transferred)
                logger.debug("(%s) BytesTransferred: %d" % (
                             self.session_id, self._bytes_transferred))
            if AsperaSession.PROGRESS_MSGS_SEND_ALL:
                return True
        return _changed

    def set_error(self, error):
        ''' format an error message into an exception that can be thrown in result() '''
        self.set_exception(AsperaTransferFailedError(error))

    @property
    def bytes_transferred(self):
        ''' get the number of bytes transferred for this session '''
        return self._bytes_transferred

    def set_exception(self, exception):
        ''' set the exception message and set the status to failed '''
        logger.error("%s : %s" % (exception.__class__.__name__, str(exception)))
        self._set_status(enumAsperaControllerStatus.FAILED, exception)

    def set_success(self):
        ''' set the transfer status to success '''
        self._set_status(enumAsperaControllerStatus.SUCCESS)

    def set_cancelled(self):
        ''' set the transfer status to cancelled '''
        self._set_status(enumAsperaControllerStatus.CANCELLED)

    def is_status(self, st1):
        ''' is the transfer status set to the param value '''
        return st1 == self._status

    def is_success(self):
        ''' is the transfer status set to success '''
        return self.is_status(enumAsperaControllerStatus.SUCCESS)

    def is_cancelled(self):
        ''' is the transfer status set to success '''
        return self.is_status(enumAsperaControllerStatus.CANCELLED)

    def is_failed(self):
        ''' is the transfer status set to failed '''
        return self.is_status(enumAsperaControllerStatus.FAILED)

    def is_done(self):
        ''' check to see if the status is one of three possible done/completed states '''
        return self.is_failed() or self.is_cancelled() or self.is_success()

    def wait(self):
        ''' wait for the done event to be set - no timeout'''
        self._done_event.wait(MAXINT)
        return self._status, self._exception


class AsperaTransferCoordinator(AsperaTransferListener):
    """A helper class for managing TransferFuture"""
    def __init__(self, args):
        super(AsperaTransferCoordinator, self).__init__()

        self._args = args
        self._exception = None
        self._done_event = threading.Event()
        self._lock = threading.Lock()
        self._done_callbacks = []
        self._queued_callbacks = []
        self._progress_callbacks = []
        self._callbacks_lock = threading.Lock()
        self._total_bytes_transferred = 0
        self._update_session_count()

    def cancel(self, msg='', exc_type=CancelledError):
        """Cancels the TransferFuture
           :param msg: The message to attach to the cancellation
           :param exc_type: The type of exception to set for the cancellation
        """
        _ret = False
        if not self.is_done():
            self.notify_cancelled(msg, True)
            _ret = True

        return _ret

    @property
    def session_count(self):
        ''' session/ascp count used to limit the number of ascps than can be run concurrently '''
        return self._session_count

    def _update_session_count(self, type=0, actutal_session_count=0):
        ''' update the session/ascp count
            0 : set the number of sessions being used to 1 or number specified in transfer config
            -1: decrement the session count by one
             1: set the session count to param value
        '''
        if type == 0:  # init
            _count = 0
            if self._args.transfer_config:
                _count = self._args.transfer_config.multi_session
            self._session_count = _count if _count > 0 else 1
        elif type == -1:  # decrement
            self._session_count -= 1
        elif type == 1:  # set from number of actual session objects
            self._session_count = actutal_session_count

    def result(self, raise_exception=True):
        """Waits until TransferFuture is done and returns the result

        If the TransferFuture succeeded, it will return the result. If the
        TransferFuture failed, it will raise the exception associated to the
        failure.
        """
        _status = None
        _exception = None
        self._done_event.wait(MAXINT)  # first wait for session global
        if self.is_failed():  # global exception set
            _exception = self._exception
            _status = enumAsperaControllerStatus.FAILED
        else:
            for _session in self._sessions.values():
                _status_tmp, _exception_tmp = _session.wait()
                if _exception_tmp and not _exception:
                    _exception = _exception_tmp
                    _status = _status_tmp

        # Once done waiting, raise an exception if present or return the final status
        if _exception and raise_exception:
            raise _exception

        return _status

    def notify_cancelled(self, reason, run_done_callbacks):
        ''' notify cancel with reason and a whether to run done callbacks '''
        self.notify_exception(CancelledError(reason), run_done_callbacks)

    def notify_init(self):
        ''' run the queed callback  for just the first session only '''
        _session_count = len(self._sessions)
        self._update_session_count(1, _session_count)
        if _session_count == 1:
            self._run_queued_callbacks()

    def notify_done(self, error=False, run_done_callbacks=True):
        ''' if error clear all sessions otherwise check to see if all other sessions are complete
            then run the done callbacks
        '''
        if error:
            for _session in self._sessions.values():
                _session.set_done()
            self._session_count = 0
        else:
            self._update_session_count(-1)
            for _session in self._sessions.values():
                if not _session.is_done():
                    return

        if run_done_callbacks:
            self._run_done_callbacks()
        self._done_event.set()

    def notify_progress(self):
        ''' only call the progress callback if total has changed
            or PROGRESS_MSGS_SEND_ALL is set '''
        _total = 0
        for _session in self._sessions.values():
            _total += _session.bytes_transferred

        if AsperaSession.PROGRESS_MSGS_SEND_ALL:
            self._run_progress_callbacks(_total)
        else:
            # dont call progress callback unless total has changed
            if self._total_bytes_transferred != _total:
                self._total_bytes_transferred = _total
                self._run_progress_callbacks(_total)

    def notify_exception(self, exception, run_done_callbacks=True):
        ''' set the exception message, stop transfer if running and set the done event '''
        logger.error("%s : %s" % (exception.__class__.__name__, str(exception)))
        self._exception = exception
        if self.is_running(True):
            # wait for a short 5 seconds for it to finish
            for _cnt in range(0, 5):
                if not self._cancel():
                    time.sleep(1)
                else:
                    break

        self.notify_done(error=True, run_done_callbacks=run_done_callbacks)

    def is_success(self):
        ''' check all sessions to see if they have completed successfully  '''
        for _session in self._sessions.values():
            if not _session.is_success():
                return False
        return True

    def is_done(self):
        ''' check to see if the done event has been set '''
        return self._done_event.is_set()

    def is_cancelled(self):
        ''' check to see if the exception/error type is a CancelledError '''
        if self._exception:
            return isinstance(self._exception, CancelledError)
        return False

    def is_send(self):
        ''' is trasnfer an Upload file or directory '''
        return self._args.direction == enumAsperaDirection.SEND

    def is_receive(self):
        ''' is trasnfer a Download file or directory '''
        return self._args.direction == enumAsperaDirection.RECEIVE

    def is_failed(self):
        ''' check to see if the exception/error has been set '''
        return self._exception is not None

    def set_transfer_spec(self):
        ''' run the function to set the transfer spec on error set associated exception '''
        _ret = False
        try:
            self._args.transfer_spec_func(self._args)
            _ret = True
        except Exception as ex:
            self.notify_exception(AsperaTransferSpecError(ex), False)
        return _ret

    def get_transfer_spec(self):
        ''' get the stored transfer spec '''
        return self._args.transfer_spec

    def get_transfer_id(self):
        ''' get the unique transfer id GUID - used in all api calls to Aspera sdk '''
        return self._args.transfer_id

    def get_last_error(self):
        ''' fetch the exception message - if one was set '''
        return str(self._exception) if self._exception else ""

    # *************************************************************************************************
    # Callback related code
    # *************************************************************************************************
    def _add_subscribers_for_type(self, callback_type, subscribers, callbacks, **kwargs):
        ''' add a done/queued/progress callback to the appropriate list '''
        for subscriber in subscribers:
            callback_name = 'on_' + callback_type
            if hasattr(subscriber, callback_name):
                _function = functools.partial(getattr(subscriber, callback_name), **kwargs)
                callbacks.append(_function)

    def add_done_callback(self, function, **kwargs):
        """Add a done callback to be invoked when transfer is complete """
        with self._callbacks_lock:
            _function = functools.partial(function, **kwargs)
            self._done_callbacks.append(_function)

    def add_subscribers(self, subscribers, **kwargs):
        """ Add a callbacks to be invoked during transfer """
        if subscribers:
            with self._callbacks_lock:
                self._add_subscribers_for_type(
                    'done', subscribers, self._done_callbacks, **kwargs)
                self._add_subscribers_for_type(
                    'queued', subscribers, self._queued_callbacks, **kwargs)
                self._add_subscribers_for_type(
                    'progress', subscribers, self._progress_callbacks, **kwargs)

    def _run_queued_callbacks(self):
        ''' run the init/quued calback when the trasnfer is initiated on apsera '''
        for callback in self._queued_callbacks:
            try:
                callback()
            except Exception as ex:
                logger.error("Exception: %s" % str(ex))

    def _run_progress_callbacks(self, bytes_transferred):
        ''' pass the number of bytes process to progress callbacks '''
        if bytes_transferred:
            for callback in self._progress_callbacks:
                try:
                    callback(bytes_transferred=bytes_transferred)
                except Exception as ex:
                    logger.error("Exception: %s" % str(ex))

    def _run_done_callbacks(self):
        ''' Run the callbacks and remove the callbacks from the internal
            List so they do not get run again if done is notified more than once.
        '''
        with self._callbacks_lock:
            for callback in self._done_callbacks:
                try:
                    callback()
                # We do not want a callback interrupting the process, especially
                # in the failure cleanups. So log and catch, the excpetion.
                except Exception as ex:
                    logger.error("Exception: %s" % str(ex))
                    logger.error("Exception raised in %s." % callback, exc_info=True)

            self._done_callbacks = []
