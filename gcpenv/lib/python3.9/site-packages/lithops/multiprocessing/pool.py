#
# Module providing the `Pool` class for managing a process pool
#
# multiprocessing/pool.py
#
# Copyright (c) 2006-2008, R Oudkerk
# Licensed to PSF under a Contributor Agreement.
#
# Modifications Copyright (c) 2020 Cloudlab URV
#

#
# Imports
#
import queue
import itertools
import logging

from lithops import FunctionExecutor

from . import util
from . import config as mp_config
from .process import cloud_process_wrapper, CloudProcess

logger = logging.getLogger(__name__)

#
# Constants representing the state of a pool
#

RUN = 0
CLOSE = 1
TERMINATE = 2

#
# Miscellaneous
#

job_counter = itertools.count()


#
# Class representing a process pool
#

class Pool(object):
    """
    Class which supports an async version of applying functions to arguments.
    """
    _wrap_exception = True

    Process = CloudProcess

    def __init__(self, processes=None, initializer=None, initargs=None, maxtasksperchild=None, context=None):
        if initargs is None:
            initargs = ()

        self._taskqueue = queue.Queue()
        self._cache = {}
        self._state = RUN
        self._maxtasksperchild = maxtasksperchild
        self._initializer = initializer
        self._initargs = initargs
        self._remote_logger = {}
        self._logger_stream = None

        if processes is not None and processes < 1:
            raise ValueError("Number of processes must be at least 1")

        lithops_conf = mp_config.get_parameter(mp_config.LITHOPS_CONFIG)

        if processes is not None:
            self._processes = processes
            self._executor = FunctionExecutor(max_workers=processes, **lithops_conf)
        else:
            self._executor = FunctionExecutor(**lithops_conf)
            self._processes = self._executor.invoker.max_workers

        if initializer is not None and not callable(initializer):
            raise TypeError('initializer must be a callable')

        self._remote_logger, self._logger_stream = util.setup_log_streaming(self._executor)

    def apply(self, func, args=(), kwds={}):
        """
        Equivalent of `func(*args, **kwds)`.
        """
        assert self._state == RUN
        if kwds and not args:
            args = {}
        return self.apply_async(func, args, kwds).get()

    def map(self, func, iterable, chunksize=None):
        """
        Apply `func` to each element in `iterable`, collecting the results
        in a list that is returned.
        """
        return self._map_async(func, iterable, chunksize).get()

    def starmap(self, func, iterable, chunksize=None):
        """
        Like `map()` method but the elements of the `iterable` are expected to
        be iterables as well and will be unpacked as arguments. Hence
        `func` and (a, b) becomes func(a, b).
        """
        return self._map_async(func, iterable, chunksize=chunksize, starmap=True).get()

    def starmap_async(self, func, iterable, chunksize=None, callback=None, error_callback=None):
        """
        Asynchronous version of `starmap()` method.
        """
        return self._map_async(func, iterable, chunksize=chunksize,
                               callback=callback, error_callback=error_callback, starmap=True)

    def imap(self, func, iterable, chunksize=1):
        """
        Equivalent of `map()` -- can be MUCH slower than `Pool.map()`.
        """
        res = self.map(func, iterable, chunksize=chunksize)
        return IMapIterator(res)

    def imap_unordered(self, func, iterable, chunksize=1):
        """
        Like `imap()` method but ordering of results is arbitrary.
        """
        res = self.map(func, iterable, chunksize=chunksize)
        return IMapIterator(res)

    def apply_async(self, func, args=(), kwds={}, callback=None, error_callback=None):
        """
        Asynchronous version of `apply()` method.
        """
        if self._state != RUN:
            raise ValueError("Pool not running")

        self._remote_logger, stream = util.setup_log_streaming(self._executor)
        extra_env = mp_config.get_parameter(mp_config.ENV_VARS)

        process_name = '-'.join([self._executor.executor_id, func.__name__])
        futures = self._executor.call_async(cloud_process_wrapper,
                                            data={'func': func,
                                                  'data': {
                                                      'args': args,
                                                      'kwargs': kwds
                                                  },
                                                  'initializer': self._initializer,
                                                  'initargs': self._initargs,
                                                  'name': process_name,
                                                  'log_stream': stream,
                                                  'op': 'apply'},
                                            extra_env=extra_env)

        result = ApplyResult(self._executor, [futures], callback, error_callback)

        return result

    def map_async(self, func, iterable, chunksize=None, callback=None, error_callback=None):
        """
        Asynchronous version of `map()` method.
        """
        return self._map_async(func, iterable, chunksize, callback, error_callback)

    def _map_async(self, func, iterable, chunksize=None, callback=None, error_callback=None, starmap=False):
        """
        Helper function to implement map, starmap and their async counterparts.
        """
        if self._state != RUN:
            raise ValueError("Pool not running")
        if not hasattr(iterable, '__len__'):
            iterable = list(iterable)

        extra_env = mp_config.get_parameter(mp_config.ENV_VARS)
        extra_args = (
            func,
            self._initializer,
            self._initargs,
            '-'.join([self._executor.executor_id, func.__name__]),
            self._logger_stream,
            'starmap' if starmap else 'map'
        )

        fmt_args = [(arg,) for arg in iterable]

        futures = self._executor.map(cloud_process_wrapper,
                                     fmt_args,
                                     extra_args=extra_args,
                                     extra_env=extra_env)

        result = MapResult(self._executor, futures, callback, error_callback)

        return result

    def __reduce__(self):
        raise NotImplementedError('pool objects cannot be passed between processes or pickled')

    def close(self):
        logger.debug('closing pool')
        if self._state == RUN:
            self._state = CLOSE

    def terminate(self):
        logger.debug('terminating pool')
        self._state = TERMINATE
        if self._remote_logger:
            self._remote_logger.stop()
            self._remote_logger = None

    def join(self):
        logger.debug('joining pool')
        assert self._state in (CLOSE, TERMINATE)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.terminate()


#
# Class whose instances are returned by `Pool.apply_async()`
#

class ApplyResult(object):

    def __init__(self, executor, futures, callback, error_callback):
        self._job = next(job_counter)
        self._futures = futures
        self._executor = executor
        self._callback = callback
        self._error_callback = error_callback
        self._value = None
        self._exception = None

    def ready(self):
        return all(fut.done for fut in self._futures)

    def successful(self):
        if not self.ready():
            raise ValueError('{} not ready'.format(repr(self)))
        return not any(fut.error for fut in self._futures)

    def wait(self, timeout=None):
        try:
            self._executor.wait(self._futures, download_results=False, timeout=timeout)
        except Exception as e:
            self._exception = e

    def get(self, timeout=None):
        if self._exception:
            raise self._exception

        self._value = self._executor.get_result(self._futures, timeout=timeout)

        if self._callback is not None:
            self._callback(self._value)

        util.export_execution_details(self._futures, self._executor)

        return self._value

    def _set(self, i, success_result):
        self._success, self._value = success_result
        if self._callback and self._success:
            self._callback(self._value)
            self._callback = None
        if self._error_callback and not self._success:
            self._error_callback(self._value)
            self._callback = None
        # self._event.set()
        # del self._cache[self._job]


AsyncResult = ApplyResult  # create alias


#
# Class whose instances are returned by `Pool.map_async()`
#

class MapResult(ApplyResult):

    def __init__(self, executor, futures, callback, error_callback):
        ApplyResult.__init__(self, executor, futures, callback, error_callback)

        self._value = [None] * len(futures)


#
# Class whose instances are returned by `Pool.imap()` and `Pool.imap_unordered()`
#

class IMapIterator:
    def __init__(self, result):
        self._iter_result = iter(result)

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._iter_result)

    def next(self):
        return self.__next__()
