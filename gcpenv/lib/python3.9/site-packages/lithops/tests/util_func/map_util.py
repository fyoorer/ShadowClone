import lithops
import logging

logger = logging.getLogger(__name__)


def simple_map_function(x, y):
    return x + y


def concat(lst):
    return " ".join(lst)


def hello_world(param):
    return "Hello World!"


def lithops_inside_lithops_map_function(x):
    def _func(x):
        return x

    fexec = lithops.FunctionExecutor()
    fexec.map(_func, range(x))
    return fexec.get_result()


def lithops_return_futures_map_function1(x):
    def _func(x):
        return x + 1

    fexec = lithops.FunctionExecutor()
    return fexec.map(_func, range(x))


def lithops_return_futures_map_function2(x):
    def _func(x):
        return x + 1

    fexec = lithops.FunctionExecutor()
    return fexec.call_async(_func, x + 5)


def lithops_return_futures_map_function3(x):
    def _func(x):
        return x + 1

    fexec = lithops.FunctionExecutor()
    fut1 = fexec.map(_func, range(x))
    fut2 = fexec.map(_func, range(x))
    return fut1 + fut2


def my_map_function_obj(obj, id):
    """returns a dictionary of {word:number of appearances} key:value items."""
    print('Function id: {}'.format(id))
    print('Bucket: {}'.format(obj.bucket))
    print('Key: {}'.format(obj.key))
    print('Partition num: {}'.format(obj.part))

    print('Chunk size: {}'.format(obj.chunk_size))
    print('Byte range: {}'.format(obj.data_byte_range))

    counter = {}
    data = obj.data_stream.read()

    print('Data lenght: {}'.format(len(data)))

    for line in data.splitlines():
        for word in line.decode('utf-8').split():
            if word not in counter:
                counter[word] = 1
            else:
                counter[word] += 1
    logger.info('Testing map_reduce() over a bucket')
    return counter


def my_map_function_url(id, obj):
    print('I am processing the object from {}'.format(obj.url))
    print('Function id: {}'.format(id))
    print('Partition num: {}'.format(obj.part))
    print('Chunk size: {}'.format(obj.chunk_size))
    print('Byte range: {}'.format(obj.data_byte_range))

    counter = {}
    data = obj.data_stream.read()

    print('Data lenght: {}'.format(len(data)))

    for line in data.splitlines():
        for word in line.decode('utf-8').split():
            if word not in counter:
                counter[word] = 1
            else:
                counter[word] += 1
    return counter
