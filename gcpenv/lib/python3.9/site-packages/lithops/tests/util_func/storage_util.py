import pickle
from lithops.tests.util_func.map_reduce_util import my_reduce_function
from lithops.tests.util_func.map_util import my_map_function_obj

PREFIX = '__lithops.test'
DATASET_PREFIX = PREFIX + '/dataset'


def clean_tests(storage, storage_config, prefix=PREFIX):
    """removes datasets from storage"""
    def _list_test_keys(storage, storage_config, prefix):
        return storage.list_keys(bucket=storage_config['bucket'], prefix=prefix + '/')

    for key in _list_test_keys(storage, storage_config, prefix):
        storage.delete_object(bucket=storage_config['bucket'],
                              key=key)


def list_dataset_keys(storage, storage_config, dataset_prefix=DATASET_PREFIX):
    return storage.list_keys(bucket=storage_config['bucket'],
                             prefix=dataset_prefix + '/')


def my_cloudobject_put(obj, storage):
    """uploads to storage pickled dict of type: {word:number of appearances} """
    counter = my_map_function_obj(obj, 0)
    cloudobject = storage.put_cloudobject(pickle.dumps(counter))
    return cloudobject


def my_cloudobject_get(cloudobjects, storage):
    """unpickles list of data from storage and return their sum by using a reduce function """
    data = [pickle.loads(storage.get_cloudobject(co)) for co in cloudobjects]
    return my_reduce_function(data)


def my_map_function_storage(key_i, bucket_name, storage):
    print(f'I am processing the object /{bucket_name}/{key_i}')
    counter = {}
    data = storage.get_object(bucket_name, key_i)
    for line in data.splitlines():
        for word in line.decode('utf-8').split():
            if word not in counter:
                counter[word] = 1
            else:
                counter[word] += 1
    return counter


def get_dataset_key_size(storage, storage_config, key_prefix=DATASET_PREFIX):
    """return a list of file sizes in bytes, belonging to files whose names are
    prefixed by 'key_prefix' """

    sizes = []
    bucket_name = storage_config['bucket']
    keys = list_dataset_keys(storage, storage_config, key_prefix)
    for key in keys:
        sizes.append(float(storage.head_object(bucket_name, key)['content-length']))
    return sizes


def extract_keys(bucket_objects):
    keys = []
    for obj in bucket_objects:
        keys.append(obj['Key'])
    return keys
