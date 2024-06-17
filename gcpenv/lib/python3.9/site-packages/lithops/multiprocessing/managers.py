#
# Module providing the `SyncManager` class for dealing
# with shared objects
#
# multiprocessing/managers.py
#
# Copyright (c) 2006-2008, R Oudkerk
# Licensed to PSF under a Contributor Agreement.
#
# Modifications Copyright (c) 2020 Cloudlab URV
#

#
# Imports
#

import redis
import inspect
import cloudpickle
import logging

from . import pool
from . import synchronize
from . import queues
from . import util
from . import config as mp_config

logger = logging.getLogger(__name__)

_builtin_types = {
    'list',
    'dict',
    'Namespace',
    'Lock',
    'RLock',
    'Semaphore',
    'BoundedSemaphore',
    'Condition',
    'Event',
    'Barrier',
    'Queue',
    'Value',
    'Array',
    'JoinableQueue',
    'SimpleQueue',
    'Pool'
}


#
# Helper functions
#

def deslice(slic: slice):
    start = slic.start
    end = slic.stop
    step = slic.step

    if start is None:
        start = 0
    if end is None:
        end = -1
    elif start == end or end == 0:
        return None, None, None
    else:
        end -= 1

    return start, end, step


#
# Definition of BaseManager
#

class BaseManager:
    """
    Base class for managers
    """
    _registry = {}

    def __init__(self, address=None, authkey=None, serializer='pickle', ctx=None):
        self._client = util.get_redis_client()
        self._managing = False
        self._mrefs = []

    def get_server(self):
        pass

    def connect(self):
        pass

    def start(self, initializer=None, initargs=()):
        self._managing = True

    def _create(self, typeid, *args, **kwds):
        """
        Create a new shared object; return the token and exposed tuple
        """
        pass

    def join(self, timeout=None):
        pass

    def _number_of_objects(self):
        """
        Return the number of shared objects
        """
        return len(self._mrefs)

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()

    def shutdown(self):
        if self._managing:
            for ref in self._mrefs:
                ref.collect()
            self._mrefs = []
            self._managing = False

    @classmethod
    def register(cls, typeid, proxytype=None, callable=None, exposed=None,
                 method_to_typeid=None, create_method=True, can_manage=True):
        """
        Register a typeid with the manager type
        """

        def temp(self, *args, **kwargs):
            logger.debug('requesting creation of a shared %r object', typeid)

            if typeid in _builtin_types:
                proxy = proxytype(*args, **kwargs)
            else:
                proxy = GenericProxy(typeid, proxytype, *args, **kwargs)

            if self._managing and can_manage and hasattr(proxy, '_ref'):
                proxy._ref.managed = True
                self._mrefs.append(proxy._ref)
            return proxy

        temp.__name__ = typeid
        setattr(cls, typeid, temp)


#
# Definition of BaseProxy
#

class BaseProxy:
    """
    A base for proxies of shared objects
    """

    def __init__(self, typeid, serializer=None):
        self._typeid = typeid
        # object id
        self._oid = '{}-{}'.format(typeid, util.get_uuid())

        self._pickler = cloudpickle
        self._client = util.get_redis_client()
        self._ref = util.RemoteReference(self._oid, client=self._client)

    def __repr__(self):
        return '<{} object, typeid={}, key={}>'.format(type(self).__name__, self._typeid, self._oid)

    def __str__(self):
        """
        Return representation of the referent (or a fall-back if that fails)
        """
        return repr(self)


#
# Types/callables which we will register with SyncManager
#

class GenericProxy(BaseProxy):
    def __init__(self, typeid, klass, *args, **kwargs):
        super().__init__(typeid)
        self._klass = klass
        self._init_args = (args, kwargs)

        obj = self._after_fork()
        self._init_obj(obj)

    def _after_fork(self):
        args, kwargs = self._init_args
        obj = self._klass(*args, **kwargs)

        for attr_name in (attr for attr in dir(obj) if inspect.ismethod(getattr(obj, attr))):
            wrap = MethodWrapper(self, attr_name, obj)
            setattr(self, attr_name, wrap)

        return obj

    def _init_obj(self, obj):

        if not hasattr(obj, '__shared__'):
            shared = list(vars(obj).keys())
        else:
            shared = obj.__shared__

        pipeline = self._client.pipeline()
        for attr_name in shared:
            attr = getattr(obj, attr_name)
            attr_bin = self._pickler.dumps(attr)
            pipeline.hset(self._oid, attr_name, attr_bin)
        pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        pipeline.execute()

    def __getstate__(self):
        return {
            '_typeid': self._typeid,
            '_oid': self._oid,
            '_pickler': self._pickler,
            '_client': self._client,
            '_ref': self._ref,
            '_klass': self._klass,
            '_init_args': self._init_args,
        }

    def __setstate__(self, state):
        self._typeid = state['_typeid']
        self._oid = state['_oid']
        self._pickler = state['_pickler']
        self._client = state['_client']
        self._ref = state['_ref']
        self._klass = state['_klass']
        self._init_args = state['_init_args']
        self._after_fork()


class MethodWrapper:
    def __init__(self, proxy, attr_name, shared_object):
        self._attr_name = attr_name
        self._shared_object = shared_object
        self._proxy = proxy

    def __call__(self, *args, **kwargs):
        attrs = self._proxy._client.hgetall(self._proxy._oid)

        hashes = {}

        for attr_name, attr_bin in attrs.items():
            attr_name = attr_name.decode('utf-8')
            attr = self._proxy._pickler.loads(attr_bin)
            hashes[attr_name] = hash(attr_bin)
            setattr(self._shared_object, attr_name, attr)

        attr = getattr(self._shared_object, self._attr_name)
        if callable(attr):
            result = attr.__call__(*args, **kwargs)
        else:
            result = attr

        if not hasattr(self._shared_object, '__shared__'):
            shared = list(vars(self._shared_object).keys())
        else:
            shared = self._shared_object.__shared__

        pipeline = self._proxy._client.pipeline()
        for attr_name in shared:
            attr = getattr(self._shared_object, attr_name)
            attr_bin = self._proxy._pickler.dumps(attr)
            if hash(attr_bin) != hashes[attr_name]:
                pipeline.hset(self._proxy._oid, attr_name, attr_bin)
        pipeline.expire(self._proxy._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        pipeline.execute()

        return result


class ListProxy(BaseProxy):
    # NOTE: list slices should return an instance of a ListProxy
    #       or a native python list?
    #
    #          A = ListProxy([1, 2, 3])
    #          B = A[:2]
    #          C = A + [4, 5]
    #          D = A * 3
    #
    #        Following the multiprocessing implementation, lists (B,
    #        C, D) are plain python lists while A is the only ListProxy.
    #        This could cause problems like these:
    #
    #          A = A[2:]
    #
    #        with A being a python list after executing that line.
    #
    #        Current implementation is the same as multiprocessing

    # KEYS[1] - key to extend
    # KEYS[2] - key to extend with
    # ARGV[1] - number of repetitions
    # A = A + B * C
    LUA_EXTEND_LIST_SCRIPT = """
        local values = redis.call('LRANGE', KEYS[2], 0, -1)
        if #values == 0 then
            return
        else
            for i=1,tonumber(ARGV[1]) do
                redis.call('RPUSH', KEYS[1], unpack(values))
            end
        end
    """

    def __init__(self, iterable=None):
        super().__init__('list')
        self._lua_extend_list = self._client.register_script(ListProxy.LUA_EXTEND_LIST_SCRIPT)
        util.make_stateless_script(self._lua_extend_list)

        if iterable is not None:
            self.extend(iterable)

    def __setitem__(self, i, obj):
        if isinstance(i, int) or hasattr(i, '__index__'):
            idx = i.__index__()
            serialized = self._pickler.dumps(obj)
            try:
                pipeline = self._client.pipeline()
                pipeline.lset(self._oid, idx, serialized)
                pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
                pipeline.execute()
            except redis.exceptions.ResponseError:
                # raised when index >= len(self)
                raise IndexError('list assignment index out of range')

        elif isinstance(i, slice):  # TODO: step
            start, end, step = deslice(i)
            if start is None:
                return

            if end < 0:
                end = len(self) + end

            pipeline = self._client.pipeline(transaction=False)
            try:
                iterable = iter(obj)
                for j in range(start, end):
                    obj = next(iterable)
                    serialized = self._pickler.dumps(obj)
                    pipeline.lset(self._oid, j, serialized)
            except StopIteration:
                pass
            except redis.exceptions.ResponseError:
                # raised when index >= len(self)
                pipeline.execute()
                self.extend(iterable)
                return
            except TypeError:
                raise TypeError('can only assign an iterable')
            pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
            pipeline.execute()
        else:
            raise TypeError('list indices must be integers '
                            'or slices, not {}'.format(type(i)))

    def __getitem__(self, i):
        if isinstance(i, int) or hasattr(i, '__index__'):
            idx = i.__index__()
            pipeline = self._client.pipeline()
            pipeline.lindex(self._oid, idx)
            pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
            serialized, _ = pipeline.execute()
            if serialized is not None:
                return self._pickler.loads(serialized)
            raise IndexError('list index out of range')

        elif isinstance(i, slice):  # TODO: step
            start, end, step = deslice(i)
            if start is None:
                return []
            pipeline = self._client.pipeline()
            pipeline.lrange(self._oid, start, end)
            pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
            serialized, _ = pipeline.execute()
            unserialized = [self._pickler.loads(obj) for obj in serialized]
            return unserialized
            # return type(self)(unserialized)
        else:
            raise TypeError('list indices must be integers '
                            'or slices, not {}'.format(type(i)))

    def extend(self, iterable):
        if isinstance(iterable, type(self)):
            self._extend_same_type(iterable, 1)
        else:
            if iterable != []:
                values = map(self._pickler.dumps, iterable)
                pipeline = self._client.pipeline()
                pipeline.rpush(self._oid, *values)
                pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
                pipeline.execute()

    def _extend_same_type(self, listproxy, repeat=1):
        self._lua_extend_list(keys=[self._oid, listproxy._oid],
                              args=[repeat],
                              client=self._client)

    def append(self, obj):
        serialized = self._pickler.dumps(obj)
        pipeline = self._client.pipeline()
        pipeline.rpush(self._oid, serialized)
        pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        pipeline.execute()

    def pop(self, index=None):
        if index is None:
            pipeline = self._client.pipeline()
            pipeline.rpop(self._oid)
            pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
            serialized, _ = pipeline.execute()

            if serialized is not None:
                return self._pickler.loads(serialized)
        else:
            item = self[index]
            sentinel = util.get_uuid()
            self[index] = sentinel
            self.remove(sentinel)
            return item

    def __deepcopy__(self, memo):
        selfcopy = type(self)()

        # We should test the DUMP/RESTORE strategy
        # although it has serialization costs
        selfcopy._extend_same_type(self)

        memo[id(self)] = selfcopy
        return selfcopy

    def __add__(self, x):
        # FIXME: list only allows concatenation to other list objects
        #        (altough it can now be extended by iterables)
        # newlist = deepcopy(self)
        # return newlist.__iadd__(x)
        return self[:] + x

    def __iadd__(self, x):
        # FIXME: list only allows concatenation to other list objects
        #        (altough it can now be extended by iterables)
        self.extend(x)
        return self

    def __mul__(self, n):
        if not isinstance(n, int):
            raise TypeError("TypeError: can't multiply sequence"
                            " by non-int of type {}".format(type(n)))
        if n < 1:
            # return type(self)()
            return []
        else:
            # newlist = type(self)()
            # newlist._extend_same_type(self, repeat=n)
            # return newlist
            return self[:] * n

    def __rmul__(self, n):
        return self.__mul__(n)

    def __imul__(self, n):
        if not isinstance(n, int):
            raise TypeError("TypeError: can't multiply sequence"
                            " by non-int of type {}".format(type(n)))
        if n > 1:
            self._extend_same_type(self, repeat=n - 1)
        return self

    def __len__(self):
        return self._client.llen(self._oid)

    def remove(self, obj):
        serialized = self._pickler.dumps(obj)
        pipeline = self._client.pipeline()
        pipeline.lrem(self._oid, 1, serialized)
        pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        pipeline.execute()
        return self

    def __delitem__(self, i):
        sentinel = util.get_uuid()
        self[i] = sentinel
        self.remove(sentinel)

    def tolist(self):
        serialized = self._client.lrange(self._oid, 0, -1)
        unserialized = [self._pickler.loads(obj) for obj in serialized]
        return unserialized

    # The following methods can't be (properly) implemented on Redis
    # To still provide the functionality, the list is fetched
    # entirely, operated in-memory and then put back to Redis

    def reverse(self):
        rev = reversed(self[:])
        self._client.delete(self._oid)
        self.extend(rev)
        return self

    def sort(self, key=None, reverse=False):
        sortd = sorted(self[:], key=key, reverse=reverse)
        self._client.delete(self._oid)
        self.extend(sortd)
        return self

    def index(self, obj, start=0, end=-1):
        return self[:].index(obj, start, end)

    def count(self, obj):
        return self[:].count(obj)

    def insert(self, index, obj):
        new_list = self[:]
        new_list.insert(index, obj)
        self._client.delete(self._oid)
        self.extend(new_list)


class DictProxy(BaseProxy):

    def __init__(self, *args, **kwargs):
        super().__init__('dict')
        self.update(*args, **kwargs)

    def __setitem__(self, k, v):
        serialized = self._pickler.dumps(v)
        pipeline = self._client.pipeline()
        pipeline.hset(self._oid, k, serialized)
        pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        pipeline.execute()

    def __getitem__(self, k):
        pipeline = self._client.pipeline()
        pipeline.hget(self._oid, k)
        pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        serialized, _ = pipeline.execute()
        if serialized is None:
            raise KeyError(k)

        return self._pickler.loads(serialized)

    def __delitem__(self, k):
        pipeline = self._client.pipeline()
        pipeline.hdel(self._oid, k)
        pipeline.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        res, _ = pipeline.execute()

        if res == 0:
            raise KeyError(k)

    def __contains__(self, k):
        return self._client.hexists(self._oid, k)

    def __len__(self):
        return self._client.hlen(self._oid)

    def __iter__(self):
        return iter(self.keys())

    def get(self, k, default=None):
        try:
            v = self.__getitem__(k)
        except KeyError:
            return default
        else:
            return v

    def pop(self, k, default=None):
        try:
            v = self.__getitem__(k)
        except KeyError:
            return default
        else:
            self.__delitem__(k)
            return v

    def popitem(self):
        try:
            key = self.keys()[0]
            item = (key, self.__getitem__(key))
            self.__delitem__(key)
            return item
        except IndexError:
            raise KeyError('popitem(): dictionary is empty')

    def setdefault(self, k, default=None):
        serialized = self._pickler.dumps(default)
        res = self._client.hsetnx(self._oid, k, serialized)
        if res == 1:
            return default
        else:
            return self.__getitem__(k)

    def update(self, *args, **kwargs):
        items = []
        if args != ():
            if len(args) > 1:
                raise TypeError('update expected at most'
                                ' 1 arguments, got {}'.format(len(args)))
            try:
                for k in args[0].keys():
                    items.extend((k, self._pickler.dumps(args[0][k])))
            except Exception:
                try:
                    items = []  # just in case
                    for k, v in args[0]:
                        items.extend((k, self._pickler.dumps(v)))
                except Exception:
                    raise TypeError(type(args[0]))

        for k in kwargs.keys():
            items.extend((k, self._pickler.dumps(kwargs[k])))

        if len(items) > 0:
            self._client.execute_command('HMSET', self._oid, *items)
            self._client.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))

    def keys(self):
        return [k.decode() for k in self._client.hkeys(self._oid)]

    def values(self):
        return [self._pickler.loads(v) for v in self._client.hvals(self._oid)]

    def items(self):
        raw_dict = self._client.hgetall(self._oid)
        items = []
        for k, v in raw_dict.items():
            items.append((k.decode(), self._pickler.loads(v)))
        return items

    def clear(self):
        self._client.delete(self._oid)

    def copy(self):
        # TODO: use lua script
        return type(self)(self.items())

    def todict(self):
        raw_dict = self._client.hgetall(self._oid)
        py_dict = {}
        for k, v in raw_dict.items():
            py_dict[k.decode()] = self._pickler.loads(v)
        return py_dict


class NamespaceProxy(BaseProxy):
    def __init__(self, **kwargs):
        super().__init__('Namespace')
        DictProxy.update(self, **kwargs)

    def __getattr__(self, k):
        if k[0] == '_':
            return object.__getattribute__(self, k)
        try:
            return DictProxy.__getitem__(self, k)
        except KeyError:
            raise AttributeError(k)

    def __setattr__(self, k, v):
        if k[0] == '_':
            return object.__setattr__(self, k, v)
        DictProxy.__setitem__(self, k, v)

    def __delattr__(self, k):
        if k[0] == '_':
            return object.__delattr__(self, k)
        try:
            return DictProxy.__delitem__(self, k)
        except KeyError:
            raise AttributeError(k)

    def _todict(self):
        return DictProxy.todict(self)


class ValueProxy(BaseProxy):
    def __init__(self, typecode='Any', value=None, lock=True):
        super().__init__('Value({})'.format(typecode))
        if value is not None:
            self.set(value)

    def get(self):
        serialized = self._client.get(self._oid)
        return self._pickler.loads(serialized)

    def set(self, value):
        serialized = self._pickler.dumps(value)
        self._client.set(self._oid, serialized, ex=mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))

    value = property(get, set)


class ArrayProxy(ListProxy):
    def __init__(self, typecode, sequence, lock=True):
        super().__init__(sequence)


#
# Definition of SyncManager
#

class SyncManager(BaseManager):
    """
    Subclass of `BaseManager` which supports a number of shared object types.

    The types registered are those intended for the synchronization
    of threads, plus `dict`, `list` and `Namespace`.

    The `multiprocessing.Manager()` function creates started instances of
    this class.
    """


SyncManager.register('list', ListProxy)
SyncManager.register('dict', DictProxy)
SyncManager.register('Namespace', NamespaceProxy)
SyncManager.register('Lock', synchronize.Lock)
SyncManager.register('RLock', synchronize.RLock)
SyncManager.register('Semaphore', synchronize.Semaphore)
SyncManager.register('BoundedSemaphore', synchronize.BoundedSemaphore)
SyncManager.register('Condition', synchronize.Condition)
SyncManager.register('Event', synchronize.Event)
SyncManager.register('Barrier', synchronize.Barrier)
SyncManager.register('Queue', queues.Queue)
SyncManager.register('SimpleQueue', queues.SimpleQueue)
SyncManager.register('JoinableQueue', queues.JoinableQueue)
SyncManager.register('Value', ValueProxy)
SyncManager.register('Array', ArrayProxy)
SyncManager.register('Pool', pool.Pool, can_manage=False)
