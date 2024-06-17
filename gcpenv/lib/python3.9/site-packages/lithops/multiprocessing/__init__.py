#
# Copyright (c) 2006-2008, R Oudkerk
# Licensed to PSF under a Contributor Agreement.
#
# Modifications Copyright (c) 2020 Cloudlab URV
#

from .context import (CloudContext, cpu_count, get_context,
                      get_all_start_methods, set_start_method, get_start_method)
from .context import CloudContext as DefaultContext
from .connection import Pipe
from .managers import SyncManager as Manager
from .pool import Pool
from .process import CloudProcess as Process
from .queues import Queue, SimpleQueue, JoinableQueue
from .sharedctypes import RawValue, RawArray, Value, Array
from .synchronize import (Semaphore, BoundedSemaphore,
                          Lock, RLock,
                          Condition, Event, Barrier)
from .process import current_process, active_children, parent_process


from . import config

context = CloudContext()
