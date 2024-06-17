from joblib.parallel import register_parallel_backend


def register_lithops():
    """ Register Lithops Backend to be called with parallel_backend("lithops"). """
    try:
        from lithops.util.joblib.lithops_backend import LithopsBackend
        register_parallel_backend("lithops", LithopsBackend)
    except ImportError:
        msg = ("To use the Lithops backend you must install lithops.")
        raise ImportError(msg)


__all__ = ["register_lithops"]
