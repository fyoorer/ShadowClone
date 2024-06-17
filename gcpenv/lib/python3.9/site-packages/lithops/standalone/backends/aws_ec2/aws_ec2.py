#
# Copyright Cloudlab URV 2021
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
import time
import logging
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

import boto3
import botocore

from lithops.version import __version__
from lithops.util.ssh_client import SSHClient
from lithops.constants import COMPUTE_CLI_MSG, CACHE_DIR
from lithops.config import load_yaml_config, dump_yaml_config
from lithops.standalone.utils import CLOUD_CONFIG_WORKER, CLOUD_CONFIG_WORKER_PK, ExecMode
from lithops.standalone.standalone import LithopsValidationError


logger = logging.getLogger(__name__)

INSTANCE_START_TIMEOUT = 180
DEFAULT_UBUNTU_IMAGE = 'ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-202204*'


def b64s(string):
    """
    Base-64 encode a string and return a string
    """
    return base64.b64encode(string.encode('utf-8')).decode('ascii')


class AWSEC2Backend:

    def __init__(self, ec2_config, mode):
        logger.debug("Creating AWS EC2 client")
        self.name = 'aws_ec2'
        self.config = ec2_config
        self.mode = mode
        self.region = self.config['region_name']
        self.cache_dir = os.path.join(CACHE_DIR, self.name)

        self.ec2_data = None
        self.vpc_key = self.config['vpc_id'][-4:]

        client_config = botocore.client.Config(
            user_agent_extra=self.config['user_agent']
        )

        self.ec2_client = boto3.client(
            'ec2', aws_access_key_id=ec2_config['access_key_id'],
            aws_secret_access_key=ec2_config['secret_access_key'],
            aws_session_token=ec2_config.get('session_token'),
            config=client_config,
            region_name=self.region
        )

        self.master = None
        self.workers = []

        msg = COMPUTE_CLI_MSG.format('AWS EC2')
        logger.info(f"{msg} - Region: {self.region}")

    def init(self):
        """
        Initialize the backend by defining the Master VM
        """
        ec2_data_filename = os.path.join(self.cache_dir, 'data')
        self.ec2_data = load_yaml_config(ec2_data_filename)

        cahced_mode = self.ec2_data.get('mode')
        cahced_instance_id = self.ec2_data.get('instance_id')

        logger.debug(f'Initializing AWS EC2 backend ({self.mode} mode)')

        if self.mode == ExecMode.CONSUME.value:
            ins_id = self.config['instance_id']

            if self.mode != cahced_mode or ins_id != cahced_instance_id:
                instances = self.ec2_client.describe_instances(InstanceIds=[ins_id])
                instance_data = instances['Reservations'][0]['Instances'][0]
                name = 'lithops-consume'
                for tag in instance_data['Tags']:
                    if tag['Key'] == 'Name':
                        name = tag['Value']
                private_ip = instance_data['PrivateIpAddress']
                self.ec2_data = {'mode': self.mode,
                                 'instance_id': ins_id,
                                 'instance_name': name,
                                 'private_ip': private_ip}
                dump_yaml_config(ec2_data_filename, self.ec2_data)

            self.master = EC2Instance(self.ec2_data['instance_name'], self.config,
                                      self.ec2_client, public=True)
            self.master.instance_id = ins_id
            self.master.private_ip = self.ec2_data['private_ip']
            self.master.delete_on_dismantle = False
            self.master.ssh_credentials.pop('password')

        elif self.mode in [ExecMode.CREATE.value, ExecMode.REUSE.value]:
            if self.mode != cahced_mode:
                # invalidate cached data
                self.ec2_data = {}

            if 'target_ami' not in self.config:
                response = self.ec2_client.describe_images(Filters=[
                    {
                        'Name': 'name',
                        'Values': [DEFAULT_UBUNTU_IMAGE]
                    }], Owners=['099720109477'])

                self.config['target_ami'] = response['Images'][0]['ImageId']

            master_name = f'lithops-master-{self.vpc_key}'
            self.master = EC2Instance(master_name, self.config, self.ec2_client, public=True)
            self.master.instance_type = self.config['master_instance_type']
            self.master.delete_on_dismantle = False
            self.master.ssh_credentials.pop('password')

            instance_data = self.master.get_instance_data()
            if instance_data:
                if 'InstanceId' in instance_data:
                    self.master.instance_id = instance_data['InstanceId']
                if 'PrivateIpAddress' in instance_data:
                    self.master.private_ip = instance_data['PrivateIpAddress']
                if instance_data['State']['Name'] == 'running' and \
                   'PublicIpAddress' in instance_data:
                    self.master.public_ip = instance_data['PublicIpAddress']

            self.ec2_data['instance_id'] = '0af1'

            if self.config['request_spot_instances']:
                wit = self.config["worker_instance_type"]
                logger.debug(f'Requesting current spot price for worker VMs of type {wit}')
                response = self.ec2_client.describe_spot_price_history(
                    EndTime=datetime.today(), InstanceTypes=[wit],
                    ProductDescriptions=['Linux/UNIX (Amazon VPC)'],
                    StartTime=datetime.today()
                )
                spot_prices = []
                for az in response['SpotPriceHistory']:
                    spot_prices.append(float(az['SpotPrice']))
                self.config["spot_price"] = max(spot_prices)
                logger.debug(f'Current spot instance price for {wit} is ${self.config["spot_price"]}')

    def _delete_worker_vm_instances(self):
        """
        Deletes all worker VM instances
        """
        logger.info('Deleting all Lithops worker VMs in EC2')

        ins_to_delete = []
        response = self.ec2_client.describe_instances()
        for res in response['Reservations']:
            for ins in res['Instances']:
                if ins['State']['Name'] != 'terminated' and 'Tags' in ins:
                    for tag in ins['Tags']:
                        if tag['Key'] == 'Name' and tag['Value'].startswith('lithops-worker'):
                            ins_to_delete.append(ins['InstanceId'])
                            logger.info(f"Going to delete VM instance {tag['Value']}")

        if ins_to_delete:
            self.ec2_client.terminate_instances(InstanceIds=ins_to_delete)

    def clean(self, all=False):
        """
        Clean all the backend resources
        The gateway public IP and the floating IP are never deleted
        """
        logger.debug('Cleaning AWS EC2 resources')
        self._delete_worker_vm_instances()
        if all:
            self.master.delete()

    def clear(self, job_keys=None):
        """
        Delete all the workers
        """
        # clear() is automatically called after get_result(),
        self.dismantle(include_master=False)

    def dismantle(self, include_master=True):
        """
        Stop all worker VM instances
        """
        if len(self.workers) > 0:
            with ThreadPoolExecutor(len(self.workers)) as ex:
                ex.map(lambda worker: worker.stop(), self.workers)
            self.workers = []

        if include_master and self.mode == ExecMode.CONSUME.value:
            # in consume mode master VM is a worker
            self.master.stop()

    def get_instance(self, name, **kwargs):
        """
        Returns a VM class instance.
        Does not creates nor starts a VM instance
        """
        instance = EC2Instance(name, self.config, self.ec2_client)

        for key in kwargs:
            if hasattr(instance, key):
                setattr(instance, key, kwargs[key])

        return instance

    def create_worker(self, name):
        """
        Creates a new worker VM instance
        """
        worker = EC2Instance(name, self.config, self.ec2_client, public=False)

        user = worker.ssh_credentials['username']

        pub_key = f'{self.cache_dir}/{self.master.name}-id_rsa.pub'
        if os.path.isfile(pub_key):
            with open(pub_key, 'r') as pk:
                pk_data = pk.read().strip()
            user_data = CLOUD_CONFIG_WORKER_PK.format(user, pk_data)
            worker.ssh_credentials['key_filename'] = '~/.ssh/id_rsa'
            worker.ssh_credentials.pop('password')
        else:
            worker.ssh_credentials.pop('key_filename')
            token = worker.ssh_credentials['password']
            user_data = CLOUD_CONFIG_WORKER.format(user, token)

        worker.create(user_data=user_data)
        self.workers.append(worker)

    def get_runtime_key(self, runtime_name, version=__version__):
        """
        Creates the runtime key
        """
        name = runtime_name.replace('/', '-').replace(':', '-')
        runtime_key = os.path.join(self.name, version, self.ec2_data['instance_id'], name)
        return runtime_key


class EC2Instance:

    def __init__(self, name, ec2_config, ec2_client=None, public=False):
        """
        Initialize a EC2Instance instance
        VMs can have master role, this means they will have a public IP address
        """
        self.name = name.lower()
        self.config = ec2_config

        self.delete_on_dismantle = self.config['delete_on_dismantle']
        self.instance_type = self.config['worker_instance_type']
        self.region = self.config['region_name']
        self.spot_instance = self.config['request_spot_instances']

        self.ec2_client = ec2_client or self._create_ec2_client()
        self.public = public

        self.ssh_client = None
        self.instance_id = None
        self.instance_data = None
        self.private_ip = None
        self.public_ip = '0.0.0.0'
        self.fast_io = self.config.get('fast_io', False)
        self.home_dir = '/home/ubuntu'

        self.ssh_credentials = {
            'username': self.config['ssh_username'],
            'password': self.config['ssh_password'],
            'key_filename': self.config.get('ssh_key_filename', '~/.ssh/id_rsa')
        }

    def __str__(self):
        ip = self.public_ip if self.public else self.private_ip

        if ip is None or ip == '0.0.0.0':
            return f'VM instance {self.name}'
        else:
            return f'VM instance {self.name} ({ip})'

    def _create_ec2_client(self):
        """
        Creates an EC2 boto3 instance
        """
        client_config = botocore.client.Config(
            user_agent_extra=self.config['user_agent']
        )

        ec2_client = boto3.client(
            'ec2', aws_access_key_id=self.config['access_key_id'],
            aws_secret_access_key=self.config['secret_access_key'],
            aws_session_token=self.config.get('session_token'),
            config=client_config,
            region_name=self.region
        )

        return ec2_client

    def get_ssh_client(self):
        """
        Creates an ssh client against the VM only if the Instance is the master
        """
        if self.public:
            if not self.ssh_client or self.ssh_client.ip_address != self.public_ip:
                self.ssh_client = SSHClient(self.public_ip, self.ssh_credentials)
        else:
            if not self.ssh_client or self.ssh_client.ip_address != self.private_ip:
                self.ssh_client = SSHClient(self.private_ip, self.ssh_credentials)

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
        Checks if the VM instance is ready to receive ssh connections
        """
        login_type = 'password' if 'password' in self.ssh_credentials and \
            not self.public else 'publickey'
        try:
            self.get_ssh_client().run_remote_command('id')
        except LithopsValidationError as err:
            raise err
        except Exception as err:
            logger.debug(f'SSH to {self.public_ip if self.public else self.private_ip} failed ({login_type}): {err}')
            self.del_ssh_client()
            return False
        return True

    def wait_ready(self, timeout=INSTANCE_START_TIMEOUT):
        """
        Waits until the VM instance is ready to receive ssh connections
        """
        logger.debug(f'Waiting {self} to become ready')

        start = time.time()

        if self.public:
            self.get_public_ip()
        else:
            self.get_private_ip()

        while (time.time() - start < timeout):
            if self.is_ready():
                start_time = round(time.time() - start, 2)
                logger.debug(f'{self} ready in {start_time} seconds')
                return True
            time.sleep(5)

        raise TimeoutError(f'Readiness probe expired on {self}')

    def _create_instance(self, user_data=None):
        """
        Creates a new VM instance
        """
        if self.fast_io:
            BlockDeviceMappings = [
                {
                    'DeviceName': '/dev/xvda',
                    'Ebs': {
                        'VolumeSize': 100,
                        'DeleteOnTermination': True,
                        'VolumeType': 'gp2',
                        # 'Iops' : 10000,
                    },
                },
            ]
        else:
            BlockDeviceMappings = None

        LaunchSpecification = {
            "ImageId": self.config['target_ami'],
            "InstanceType": self.instance_type,
            "SecurityGroupIds": [self.config['security_group_id']],
            "EbsOptimized": False,
            "IamInstanceProfile": {'Name': self.config['iam_role']},
            "Monitoring": {'Enabled': False}
        }

        if BlockDeviceMappings is not None:
            LaunchSpecification['BlockDeviceMappings'] = BlockDeviceMappings
        if 'key_name' in self.config:
            LaunchSpecification['KeyName'] = self.config['key_name']

        if self.spot_instance and not self.public:

            logger.debug("Creating new VM instance {} (Spot)".format(self.name))

            if user_data:
                # Allow master VM to access workers trough ssh key or password
                LaunchSpecification['UserData'] = b64s(user_data)

            spot_request = self.ec2_client.request_spot_instances(
                SpotPrice=str(self.config['spot_price']),
                InstanceCount=1,
                LaunchSpecification=LaunchSpecification)['SpotInstanceRequests'][0]

            request_id = spot_request['SpotInstanceRequestId']
            failures = ['price-too-low', 'capacity-not-available']

            while spot_request['State'] == 'open':
                time.sleep(5)
                spot_request = self.ec2_client.describe_spot_instance_requests(
                    SpotInstanceRequestIds=[request_id])['SpotInstanceRequests'][0]

                if spot_request['State'] == 'failed' or spot_request['Status']['Code'] in failures:
                    msg = "The spot request failed for the following reason: " + spot_request['Status']['Message']
                    logger.debug(msg)
                    self.ec2_client.cancel_spot_instance_requests(SpotInstanceRequestIds=[request_id])
                    raise Exception(msg)
                else:
                    logger.debug("Waitting to get the spot instance: " + spot_request['Status']['Message'])

            self.ec2_client.create_tags(
                Resources=[spot_request['InstanceId']],
                Tags=[{'Key': 'Name', 'Value': self.name}]
            )

            filters = [{'Name': 'instance-id', 'Values': [spot_request['InstanceId']]}]
            resp = self.ec2_client.describe_instances(Filters=filters)['Reservations'][0]

        else:
            logger.debug("Creating new VM instance {}".format(self.name))

            LaunchSpecification['MinCount'] = 1
            LaunchSpecification['MaxCount'] = 1
            LaunchSpecification["TagSpecifications"] = [{"ResourceType": "instance", "Tags": [{'Key': 'Name', 'Value': self.name}]}]
            LaunchSpecification["InstanceInitiatedShutdownBehavior"] = 'terminate' if self.delete_on_dismantle else 'stop'

            if user_data:
                LaunchSpecification['UserData'] = user_data

            # if not self.public:
            #  LaunchSpecification['NetworkInterfaces'] = [{'AssociatePublicIpAddress': False, 'DeviceIndex': 0}]

            resp = self.ec2_client.run_instances(**LaunchSpecification)

        logger.debug("VM instance {} created successfully ".format(self.name))

        return resp['Instances'][0]

    def get_instance_data(self):
        """
        Returns the instance information
        """
        if self.instance_id:
            instances = self.ec2_client.describe_instances(InstanceIds=[self.instance_id])
            instances = instances['Reservations'][0]['Instances']
            if len(instances) > 0:
                self.instance_data = instances[0]
                return self.instance_data
        else:
            filters = [{'Name': 'tag:Name', 'Values': [self.name]}]
            resp = self.ec2_client.describe_instances(Filters=filters)
            if len(resp['Reservations']) > 0:
                for res in resp['Reservations']:
                    instance_data = res['Instances'][0]
                    if instance_data['State']['Name'] != 'terminated':
                        self.instance_data = instance_data
                        return self.instance_data

        return None

    def get_instance_id(self):
        """
        Returns the instance ID
        """
        if self.instance_id:
            return self.instance_id

        instance_data = self.get_instance_data()
        if instance_data:
            self.instance_id = instance_data['InstanceId']
            return self.instance_id
        logger.debug('VM instance {} does not exists'.format(self.name))
        return None

    def get_private_ip(self):
        """
        Requests the private IP address
        """
        while not self.private_ip:
            instance_data = self.get_instance_data()
            if instance_data and 'PrivateIpAddress' in instance_data:
                self.private_ip = instance_data['PrivateIpAddress']
            else:
                time.sleep(1)
        return self.private_ip

    def get_public_ip(self):
        """
        Requests the public IP address
        """
        while self.public and (not self.public_ip or self.public_ip == '0.0.0.0'):
            instance_data = self.get_instance_data()
            if instance_data and 'PublicIpAddress' in instance_data:
                self.public_ip = instance_data['PublicIpAddress']
            else:
                time.sleep(1)
        return self.public_ip

    def create(self, check_if_exists=False, user_data=None):
        """
        Creates a new VM instance
        """
        vsi_exists = True if self.instance_id else False

        if check_if_exists and not vsi_exists:
            logger.debug('Checking if VM instance {} already exists'.format(self.name))
            instance_data = self.get_instance_data()
            if instance_data:
                logger.debug('VM instance {} already exists'.format(self.name))
                vsi_exists = True
                self.instance_id = instance_data['InstanceId']
                self.private_ip = instance_data['PrivateIpAddress']

        if not vsi_exists:
            instance_data = self._create_instance(user_data=user_data)
            self.instance_id = instance_data['InstanceId']
            self.private_ip = instance_data['PrivateIpAddress']
        else:
            self.start()

        return self.instance_id

    def start(self):
        """
        Starts the VM instance
        """
        logger.info("Starting VM instance {}".format(self.name))

        try:
            self.ec2_client.start_instances(InstanceIds=[self.instance_id])
            self.public_ip = self.get_public_ip()
        except botocore.exceptions.ClientError as err:
            if err.response['Error']['Code'] == 'IncorrectInstanceState':
                time.sleep(20)
                return self.start()
            raise err

        logger.debug("VM instance {} started successfully".format(self.name))

    def _delete_instance(self):
        """
        Deletes the VM instance and the associated volume
        """
        logger.debug("Deleting VM instance {}".format(self.name))

        self.ec2_client.terminate_instances(InstanceIds=[self.instance_id])

        self.instance_id = None
        self.private_ip = None
        self.public_ip = None
        self.del_ssh_client()

    def _stop_instance(self):
        """
        Stops the VM instance
        """
        logger.debug("Stopping VM instance {}".format(self.name))
        self.ec2_client.stop_instances(InstanceIds=[self.instance_id])

    def stop(self):
        """
        Stops the VM instance
        """
        if self.delete_on_dismantle:
            self._delete_instance()
        else:
            self._stop_instance()

    def delete(self):
        """
        Deletes the VM instance
        """
        self._delete_instance()

    def validate_capabilities(self):
        """
        Validate hardware/os requirments specified in backend config
        """
        pass
