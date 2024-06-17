import os
import pika
import json
import time
import logging
from tblib import pickling_support
from distutils.util import strtobool
from contextlib import contextmanager

import lithops.worker
from lithops.utils import sizeof_fmt
from lithops.storage.utils import create_status_key, \
    create_init_key


pickling_support.install()

logger = logging.getLogger(__name__)


def create_call_status(job, internal_storage):
    """ Creates a call status class based on the monitoring backend"""
    monitoring_backend = job.config['lithops']['monitoring']
    Status = getattr(lithops.worker.status, '{}CallStatus'
                     .format(monitoring_backend.capitalize()))
    return Status(job, internal_storage)


class CallStatus:

    def __init__(self, job, internal_storage):
        self.job = job
        self.config = job.config
        self.internal_storage = internal_storage

        self.status = {
            'exception': False,
            'activation_id': os.environ.get('__LITHOPS_ACTIVATION_ID'),
            'python_version': os.environ.get("PYTHON_VERSION"),
            'worker_start_tstamp': job.start_tstamp,
            'host_submit_tstamp': job.host_submit_tstamp,
            'call_id': job.call_id,
            'job_id': job.job_id,
            'executor_id': job.executor_id,
            'chunksize': job.chunksize
        }

        if strtobool(os.environ.get('WARM_CONTAINER', 'False')):
            self.status['worker_cold_start'] = False
        else:
            self.status['worker_cold_start'] = True
            os.environ['WARM_CONTAINER'] = 'True'

    def add(self, key, value):
        """ Adds data to the call status"""
        self.status[key] = value

    def send_init_event(self):
        """ Sends the init event"""
        self.status['type'] = '__init__'
        self._send()

    def send_finish_event(self):
        """ Sends the finish event"""
        self.status['type'] = '__end__'
        self._send()


class StorageCallStatus(CallStatus):

    def _send(self):
        """
        Send the status event to the Object Storage
        """
        executor_id = self.status['executor_id']
        job_id = self.status['job_id']
        call_id = self.status['call_id']
        act_id = self.status['activation_id']

        if self.status['type'] == '__init__':
            init_key = create_init_key(executor_id, job_id, call_id, act_id)
            self.internal_storage.put_data(init_key, '')

        elif self.status['type'] == '__end__':
            status_key = create_status_key(executor_id, job_id, call_id)
            dmpd_response_status = json.dumps(self.status)
            drs = sizeof_fmt(len(dmpd_response_status))
            logger.info("Storing execution stats - Size: {}".format(drs))
            self.internal_storage.put_data(status_key, dmpd_response_status)


class RabbitmqCallStatus(StorageCallStatus):

    def __init__(self, job, internal_storage):
        super().__init__(job, internal_storage)

        rabbit_amqp_url = self.config['rabbitmq'].get('amqp_url')
        self.pikaparams = pika.URLParameters(rabbit_amqp_url)

    @contextmanager
    def _create_channel(self):
        """
        Creates a rabbitmq channel
        """
        self.connection = pika.BlockingConnection(self.pikaparams)
        self.channel = self.connection.channel()
        try:
            yield self.channel
        finally:
            self.channel.close()
            self.connection.close()

    def _send(self):
        """
        Send the status event to RabbitMQ
        """
        dmpd_response_status = json.dumps(self.status)
        drs = sizeof_fmt(len(dmpd_response_status))

        status_sent = False
        output_query_count = 0

        queues = []
        executor_keys = self.job.executor_id.split('-')
        for k in range(int(len(executor_keys) / 2)):
            qname = 'lithops-{}'.format('-'.join(executor_keys[0:k * 3 + 2]))
            queues.append(qname)

        while not status_sent and output_query_count < 5:
            output_query_count = output_query_count + 1
            try:
                with self._create_channel() as ch:
                    for queue in queues:
                        ch.basic_publish(exchange='', routing_key=queue, body=dmpd_response_status)
                logger.info("Execution status sent to RabbitMQ - Size: {}".format(drs))
                status_sent = True
            except Exception:
                time.sleep(0.2)

        if self.status['type'] == '__end__':
            super()._send()
