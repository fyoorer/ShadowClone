#
# Copyright IBM Coorp. 2021
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

import os
import logging
import time

from lithops.version import __version__
from lithops.constants import COMPUTE_CLI_MSG
from lithops.util.ssh_client import SSHClient
from lithops.standalone.standalone import LithopsValidationError

logger = logging.getLogger(__name__)


INSTANCE_START_TIMEOUT = 30


class VMBackend:

    def __init__(self, vm_config, mode):
        logger.debug("Creating Virtual Machine client")
        self.name = 'vm'
        self.config = vm_config
        self.mode = mode
        self.master = None

        msg = COMPUTE_CLI_MSG.format('Virtual Machine')
        logger.info("{}".format(msg))

    def init(self):
        """
        Initialize the VM backend
        """
        if self.mode == 'consume':
            logger.debug('Initializing VM backend (Consume mode)')
            self.master = VMInstance(self.config)
        else:
            raise Exception(f'{self.mode} mode is not allowed in the VM backend')

    def clean(self, **kwargs):
        pass

    def clear(self, **kwargs):
        pass

    def dismantle(self, **kwargs):
        pass

    def get_runtime_key(self, runtime_name, version=__version__):
        runtime = runtime_name.replace('/', '-').replace(':', '-')
        runtime_key = os.path.join(self.name, version, self.config['ip_address'], runtime)
        return runtime_key


class VMInstance:

    def __init__(self, config):
        self.config = config
        self.public_ip = self.private_ip = self.config['ip_address']
        self.ssh_client = None

        logger.debug(f'{self} created')

    def __str__(self):
        return f'VM instance {self.public_ip}'

    def get_ssh_client(self):
        """
        Creates an ssh client against the VM only if the Instance is the master
        """
        self.ssh_credentials = {
            'username': self.config.get('ssh_user', 'root'),
            'password': self.config.get('ssh_password', None),
            'key_filename': self.config.get('ssh_key_filename', '~/.ssh/id_rsa')
        }

        if self.public_ip and not self.ssh_client:
            self.ssh_client = SSHClient(self.public_ip, self.ssh_credentials)
        return self.ssh_client

    def del_ssh_client(self):
        """
        Deletes the ssh client
        """
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None

    def is_ready(self):
        """
        Checks if the VM is ready to receive ssh connections
        """
        try:
            self.get_ssh_client().run_remote_command('id')
        except LithopsValidationError as e:
            raise e
        except Exception as e:
            logger.debug(f'ssh to {self.public_ip} failed: {e}')
            self.del_ssh_client()
            return False
        return True

    def wait_ready(self, timeout=INSTANCE_START_TIMEOUT):
        """
        Waits until the VM is ready to receive ssh connections
        """
        logger.debug(f'Waiting {self} to become ready')

        start = time.time()
        while (time.time() - start < timeout):
            if self.is_ready():
                start_time = round(time.time() - start, 2)
                logger.debug(f'{self} ready in {start_time} seconds')
                return True
            time.sleep(5)

        raise TimeoutError(f'Readiness probe expired on {self}')

    def get_instance_id(self):
        """
        Requests the Instance ID
        """
        return "0af1"

    def get_public_ip(self):
        """
        Requests the primary public IP address
        """
        return self.public_ip

    def get_private_ip(self):
        """
        Requests the primary private IP address
        """
        return self.private_ip

    def create(self, **kwargs):
        pass

    def start(self):
        pass

    def stop(self):
        pass

    def delete(self):
        pass
