import requests
import logging
import os

logger = logging.getLogger(__name__)


class PrometheusExporter():

    def __init__(self, enabled, config):
        """ Prometheus exporter for sending metrics to an API Gateway"""
        self.enabled = enabled
        self.apigateway = config.get('apigateway') if config else None

        self.job = 'lithops'
        self.instance = os.environ['__LITHOPS_SESSION_ID'].split('-')[0]

    def send_metric(self, name, value, type, labels):
        """Send a metric to prometheus"""

        if self.enabled and self.apigateway:
            dim = 'job/{}/instance/{}'.format(self.job, self.instance)
            for key, val in labels:
                dim += '/%s/%s' % (key, val)
            url = '/'.join([self.apigateway, 'metrics', dim])
            logger.debug('Sending metric "{} {} ({})" to {}'.format(name, value, type, url))

            try:
                requests.post(url, data='# TYPE %s %s\n%s %s\n' % (name, type, name, value))
            except Exception as e:
                logger.error(e)
