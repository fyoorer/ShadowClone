#
# (C) Copyright IBM Corp. 2018
# (C) Copyright Cloudlab URV 2020
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import logging
import importlib

logger = logging.getLogger(__name__)


class ServerlessHandler:
    """
    A ServerlessHandler object is used by invokers and other components to access
    underlying serverless backend without exposing the implementation details.
    """

    def __init__(self, servereless_config, internal_storage):
        self.config = servereless_config
        self.backend_name = self.config['backend']
        self.backend = None

        try:
            module_location = f'lithops.serverless.backends.{self.backend_name}'
            sb_module = importlib.import_module(module_location)
            ServerlessBackend = getattr(sb_module, 'ServerlessBackend')
            self.backend = ServerlessBackend(self.config[self.backend_name], internal_storage)

        except Exception as e:
            logger.error("There was an error trying to create the {} "
                         "serverless backend".format(self.backend_name))
            raise e

    def init(self):
        """
        Init tasks for serverless batch backends
        """
        pass

    def invoke(self, job_payload):
        """
        Invoke -- return information about this invocation
        """
        runtime_name = job_payload['runtime_name']
        runtime_memory = job_payload['runtime_memory']

        return self.backend.invoke(runtime_name, runtime_memory, job_payload)

    def build_runtime(self, runtime_name, file, extra_args=[]):
        """
        Wrapper method to build a new runtime for the compute backend.
        return: the name of the runtime
        """
        self.backend.build_runtime(runtime_name, file, extra_args)

    def deploy_runtime(self, runtime_name, memory, timeout):
        """
        Wrapper method to deploy a runtime in the compute backend.
        return: the name of the runtime
        """
        return self.backend.deploy_runtime(runtime_name, memory, timeout=timeout)

    def delete_runtime(self, runtime_name, memory, version):
        """
        Wrapper method to delete a runtime in the compute backend
        """
        self.backend.delete_runtime(runtime_name, memory, version)

    def clean(self, **kwargs):
        """
        Wrapper method to clean the compute backend
        """
        self.backend.clean()

    def clear(self, job_keys=None):
        """
        Wrapper method to clear the compute backend
        """
        if hasattr(self.backend, 'clear'):
            self.backend.clear(job_keys)

    def list_runtimes(self, runtime_name='all'):
        """
        Wrapper method to list deployed runtime in the compute backend
        """
        return self.backend.list_runtimes(runtime_name)

    def get_runtime_key(self, runtime_name, memory, version):
        """
        Wrapper method that returns a formated string that represents the runtime key.
        Each backend has its own runtime key format. Used to store runtime metadata
        into the storage
        """
        return self.backend.get_runtime_key(runtime_name, memory, version)

    def get_runtime_info(self):
        """
        Wrapper method that returns a dictionary with all the runtime information
        set in config
        """
        return self.backend.get_runtime_info()

    def get_backend_type(self):
        """
        Wrapper method that returns the type of the backend (Batch or FaaS)
        """
        return self.backend.type
