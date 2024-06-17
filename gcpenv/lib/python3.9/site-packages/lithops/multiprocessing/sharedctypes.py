#
# Module which supports allocation of ctypes objects from shared memory
#
# multiprocessing/sharedctypes.py
#
# Copyright (c) 2006-2008, R Oudkerk
# Licensed to PSF under a Contributor Agreement.
#
# Modifications Copyright (c) 2020 Cloudlab URV
#

import ctypes
import cloudpickle
import logging

from . import util
from . import get_context
from . import config as mp_config

logger = logging.getLogger(__name__)

typecode_to_type = {
    'c': ctypes.c_char, 'u': ctypes.c_wchar,
    'b': ctypes.c_byte, 'B': ctypes.c_ubyte,
    'h': ctypes.c_short, 'H': ctypes.c_ushort,
    'i': ctypes.c_int, 'I': ctypes.c_uint,
    'l': ctypes.c_long, 'L': ctypes.c_ulong,
    'q': ctypes.c_longlong, 'Q': ctypes.c_ulonglong,
    'f': ctypes.c_float, 'd': ctypes.c_double
}


class SharedCTypeProxy:
    def __init__(self, ctype, *args, **kwargs):
        self._typeid = ctype.__name__
        self._oid = '{}-{}'.format(self._typeid, util.get_uuid())
        self._client = util.get_redis_client()
        self._ref = util.RemoteReference(self._oid, client=self._client)
        logger.debug('Requested creation on shared C type %s', self._oid)


class SynchronizedSharedCTypeProxy(SharedCTypeProxy):
    def __init__(self, ctype, lock=None, ctx=None, *args, **kwargs):
        super().__init__(ctype=ctype)
        if lock:
            self._lock = lock
        else:
            ctx = ctx or get_context()
            self._lock = ctx.RLock()
        self.acquire = self._lock.acquire
        self.release = self._lock.release

    def __enter__(self):
        return self._lock.__enter__()

    def __exit__(self, *args):
        return self._lock.__exit__(*args)

    def get_obj(self):
        raise NotImplementedError()

    def get_lock(self):
        return self._lock


class RawValueProxy(SharedCTypeProxy):
    def __init__(self, ctype, *args, **kwargs):
        super().__init__(ctype=ctype)

    def __setattr__(self, key, value):
        if key == 'value':
            obj = cloudpickle.dumps(value)
            logger.debug('Set raw value %s of size %i B', self._oid, len(obj))
            self._client.set(self._oid, obj, ex=mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        else:
            super().__setattr__(key, value)

    def __getattr__(self, item):
        if item == 'value':
            obj = self._client.get(self._oid)
            if not obj:
                logger.debug('Get value %s returned None', self._oid)
                value = 0
            else:
                logger.debug('Get value %s of size %i B', self._oid, len(obj))
                value = cloudpickle.loads(obj)
            return value
        else:
            super().__getattribute__(item)


class SynchronizedValueProxy(RawValueProxy, SynchronizedSharedCTypeProxy):
    def __init__(self, ctype, lock=None, ctx=None, *args, **kwargs):
        super().__init__(ctype=ctype, lock=lock, ctx=ctx)

    def get_obj(self):
        return self.value


class RawArrayProxy(SharedCTypeProxy):
    def __init__(self, ctype, *args, **kwargs):
        super().__init__(ctype)
        self._it = 0

    def _append(self, value):
        obj = cloudpickle.dumps(value)
        self._client.rpush(self._oid, obj)

    def _extend(self, arr):
        objs = [cloudpickle.dumps(obj) for obj in arr]
        self._client.rpush(self._oid, *objs)

    def __len__(self):
        return self._client.llen(self._oid)

    def __iter__(self):
        self._it = 0
        return self

    def __next__(self):
        if self._it >= self.__len__():
            raise StopIteration()
        elem = self.__getitem__(self._it)
        self._it += 1
        return elem

    def __getitem__(self, i):
        if isinstance(i, slice):
            start, stop, step = i.indices(self.__len__())
            stop -= 1
            logger.debug('Requested get list slice from %i to %i', start, stop)
            objl = self._client.lrange(self._oid, start, stop)
            self._client.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
            return [cloudpickle.loads(obj) for obj in objl]
        else:
            obj = self._client.lindex(self._oid, i)
            logger.debug('Requested get list index %i of size %i B', i, len(obj))
            return cloudpickle.loads(obj)

    def __setitem__(self, i, value):
        if isinstance(i, slice):
            start, stop, step = i.indices(self.__len__())
            logger.debug('Requested set slice from %i to %i', start, stop)
            pipeline = self._client.pipeline()
            for i, val in enumerate(value):
                obj = cloudpickle.dumps(val)
                pipeline.lset(self._oid, i + start, obj)
            pipeline.execute()
        else:
            obj = cloudpickle.dumps(value)
            logger.debug('Requested set list index %i of size %i B', i, len(obj))
            self._client.lset(self._oid, i, obj)
            self._client.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))


class SynchronizedArrayProxy(RawArrayProxy, SynchronizedSharedCTypeProxy):
    def __init__(self, ctype, lock=None, ctx=None, *args, **kwargs):
        super().__init__(ctype=ctype, lock=lock, ctx=ctx)

    def get_obj(self):
        return self[:]


class SynchronizedStringProxy(SynchronizedArrayProxy):
    def __init__(self, ctype, lock=None, ctx=None, *args, **kwargs):
        super().__init__(ctype, lock=lock, ctx=ctx)

    def __setattr__(self, key, value):
        if key == 'value':
            for i, elem in enumerate(value):
                obj = cloudpickle.dumps(elem)
                logger.debug('Requested set string index %i of size %i B', i, len(obj))
                self._client.lset(self._oid, i, obj)
                self._client.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
        else:
            super().__setattr__(key, value)

    def __getattr__(self, item):
        if item == 'value':
            return self[:]
        else:
            super().__getattribute__(item)

    def __getitem__(self, i):
        if isinstance(i, slice):
            start, stop, step = i.indices(self.__len__())
            logger.debug('Requested get string slice from %i to %i', start, stop)
            objl = self._client.lrange(self._oid, start, stop)
            self._client.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
            return bytes([cloudpickle.loads(obj) for obj in objl])
        else:
            obj = self._client.lindex(self._oid, i)
            self._client.expire(self._oid, mp_config.get_parameter(mp_config.REDIS_EXPIRY_TIME))
            return bytes([cloudpickle.loads(obj)])


#
#
#


def RawValue(typecode_or_type, initial_value=None):
    """
    Returns a ctypes object allocated from shared memory
    """
    logger.debug('Requested creation of resource RawValue')
    type_ = typecode_to_type.get(typecode_or_type, typecode_or_type)
    obj = RawValueProxy(type_)
    if initial_value:
        obj.value = initial_value
    return obj


def RawArray(typecode_or_type, size_or_initializer):
    """
    Returns a ctypes array allocated from shared memory
    """
    logger.debug('Requested creation of resource RawArray')
    type_ = typecode_to_type.get(typecode_or_type, typecode_or_type)
    if type_ is ctypes.c_char:
        raise NotImplementedError()
    else:
        obj = RawArrayProxy(type_)

    if isinstance(size_or_initializer, list):
        for elem in size_or_initializer:
            obj._append(elem)
    elif isinstance(size_or_initializer, int):
        for _ in range(size_or_initializer):
            obj._append(0)
    else:
        raise ValueError('Invalid size or initializer {}'.format(size_or_initializer))

    return obj


def Value(typecode_or_type, initial_value=None, lock=True, ctx=None):
    """
    Return a synchronization wrapper for a Value
    """
    logger.debug('Requested creation of resource Value')
    type_ = typecode_to_type.get(typecode_or_type, typecode_or_type)
    obj = SynchronizedValueProxy(type_)
    if initial_value is not None:
        obj.value = initial_value
    return obj


def Array(typecode_or_type, size_or_initializer, *, lock=True, ctx=None):
    """
    Return a synchronization wrapper for a RawArray
    """
    logger.debug('Requested creation of resource Array')
    type_ = typecode_to_type.get(typecode_or_type, typecode_or_type)
    if type_ is ctypes.c_char:
        obj = SynchronizedStringProxy(type_)
    else:
        obj = SynchronizedArrayProxy(type_)

    if isinstance(size_or_initializer, list) or isinstance(size_or_initializer, bytes):
        obj._extend(size_or_initializer)
    elif isinstance(size_or_initializer, int):
        for _ in range(size_or_initializer):
            obj._append(0)
    else:
        raise ValueError('Invalid size or initializer {}'.format(size_or_initializer))

    return obj
