#
# Copyright (c) 2006-2008, R Oudkerk
# Licensed to PSF under a Contributor Agreement.
#
# Modifications Copyright (c) 2020 Cloudlab URV
#

import logging
import lithops

from . import process
from . import pool

logger = logging.getLogger(__name__)


#
# Exceptions
#

class ProcessError(Exception):
    pass


class BufferTooShort(ProcessError):
    pass


class TimeoutError(ProcessError):
    pass


class AuthenticationError(ProcessError):
    pass


#
# Base type for contexts
#

class CloudContext:
    ProcessError = ProcessError
    BufferTooShort = BufferTooShort
    TimeoutError = TimeoutError
    AuthenticationError = AuthenticationError

    current_process = staticmethod(process.current_process)
    active_children = staticmethod(process.active_children)

    Process = process.CloudProcess
    Pool = pool.Pool

    def Manager(self):
        """
        Returns a manager associated with a running server process
        The managers methods such as `Lock()`, `Condition()` and `Queue()`
        can be used to create shared objects.
        """
        from .managers import SyncManager
        return SyncManager()

    def Pipe(self, duplex=True):
        """Returns two connection object connected by a pipe"""
        from .connection import Pipe
        return Pipe(duplex)

    def Lock(self):
        """Returns a non-recursive lock object"""
        from .synchronize import Lock
        return Lock()

    def RLock(self):
        """Returns a recursive lock object"""
        from .synchronize import RLock
        return RLock()

    def Condition(self, lock=None):
        """Returns a condition object"""
        from .synchronize import Condition
        return Condition(lock)

    def Semaphore(self, value=1):
        """Returns a semaphore object"""
        from .synchronize import Semaphore
        return Semaphore(value)

    def BoundedSemaphore(self, value=1):
        """Returns a bounded semaphore object"""
        from .synchronize import BoundedSemaphore
        return BoundedSemaphore(value)

    def Event(self):
        """Returns an event object"""
        from .synchronize import Event
        return Event()

    def Barrier(self, parties, action=None, timeout=None):
        """Returns a barrier object"""
        from .synchronize import Barrier
        return Barrier(parties, action, timeout)

    def Queue(self, maxsize=0):
        """Returns a queue object"""
        from .queues import Queue
        return Queue(maxsize)

    def JoinableQueue(self, maxsize=0):
        """Returns a queue object"""
        from .queues import JoinableQueue
        return JoinableQueue()

    def SimpleQueue(self):
        """Returns a queue object"""
        from .queues import SimpleQueue
        return SimpleQueue()

    def RawValue(self, typecode_or_type, *args):
        """Returns a shared ctype"""
        from .sharedctypes import RawValue
        return RawValue(typecode_or_type, *args)

    def RawArray(self, typecode_or_type, size_or_initializer):
        """Returns a shared array"""
        from .sharedctypes import RawArray
        return RawArray(typecode_or_type, size_or_initializer)

    def Value(self, typecode_or_type, *args, lock=True):
        """Returns a synchronized shared object"""
        from .sharedctypes import Value
        return Value(typecode_or_type, *args, lock=lock,
                     ctx=self.get_context())

    def Array(self, typecode_or_type, size_or_initializer, *, lock=True):
        """Returns a synchronized shared array"""
        from .sharedctypes import Array
        return Array(typecode_or_type, size_or_initializer, lock=lock,
                     ctx=self.get_context())

    def cpu_count(self):
        lithops_config = lithops.config.default_config()
        backend = lithops_config['lithops']['backend']
        return lithops_config[backend]['max_workers']

    def get_context(self, method='cloud'):
        if method not in ['spawn', 'fork', 'forkserver', 'cloud']:
            raise ValueError('cannot find context for {}'.format(method))
        return _default_context  # For Lithops we only have CloudContext named as all contexts

    def get_all_start_methods(self):
        return ['fork', 'spawn', 'forkserver', 'cloud']

    def get_start_method(self, allow_none=False):
        return 'cloud'

    def set_start_method(self, method, force=False):
        pass

    @property
    def reducer(self):
        """Controls how objects will be reduced to a form that can be
        shared with other processes."""
        return globals().get('reduction')

    @reducer.setter
    def reducer(self, reduction):
        globals()['reduction'] = reduction

    def _check_available(self):
        pass


_default_context = CloudContext()

cpu_count = _default_context.cpu_count
get_context = _default_context.get_context
get_all_start_methods = _default_context.get_all_start_methods
set_start_method = _default_context.set_start_method
get_start_method = _default_context.get_start_method
