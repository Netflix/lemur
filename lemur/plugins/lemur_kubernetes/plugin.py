"""
.. module: lemur.plugins.lemur_kubernetes.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.


    The plugin inserts certificates and the private key as Kubernetes secret that
     can later be used to secure service endpoints running in Kubernetes pods

.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
"""
import base64
import itertools
import os

import requests
from flask import current_app

from lemur.common.defaults import common_name
from lemur.common.utils import parse_certificate
from lemur.plugins.bases import DestinationPlugin

DEFAULT_API_VERSION = 'v1'


def ensure_resource(k8s_api, k8s_base_uri, namespace, kind, name, data):

    # _resolve_uri(k8s_base_uri, namespace, kind, name, api_ver=DEFAULT_API_VERSION)
    url = _resolve_uri(k8s_base_uri, namespace, kind)
    current_app.logger.debug("K8S POST request URL: %s", url)

    create_resp = k8s_api.post(url, json=data)
    current_app.logger.debug("K8S POST response: %s", create_resp)

    if 200 <= create_resp.status_code <= 299:
        return None

    else:
        json = create_resp.json()
        if 'reason' in json:
            if json['reason'] != 'AlreadyExists':
                return create_resp.content
        else:
            return create_resp.content

    url = _resolve_uri(k8s_base_uri, namespace, kind, name)
    current_app.logger.debug("K8S PUT request URL: %s", url)

    update_resp = k8s_api.put(url, json=data)
    current_app.logger.debug("K8S PUT response: %s", update_resp)

    if not 200 <= update_resp.status_code <= 299:
        return update_resp.content

    return None


def _resolve_ns(k8s_base_uri, namespace, api_ver=DEFAULT_API_VERSION,):
    api_group = 'api'
    if '/' in api_ver:
        api_group = 'apis'
    return '{base}/{api_group}/{api_ver}/namespaces'.format(base=k8s_base_uri, api_group=api_group, api_ver=api_ver) + ('/' + namespace if namespace else '')


def _resolve_uri(k8s_base_uri, namespace, kind, name=None, api_ver=DEFAULT_API_VERSION):
    if not namespace:
        namespace = 'default'

    return "/".join(itertools.chain.from_iterable([
        (_resolve_ns(k8s_base_uri, namespace, api_ver=api_ver),),
        ((kind + 's').lower(),),
        (name,) if name else (),
    ]))


# Performs Base64 encoding of string to string using the base64.b64encode() function
# which encodes bytes to bytes.
def base64encode(string):
    return base64.b64encode(string.encode()).decode()


class KubernetesDestinationPlugin(DestinationPlugin):
    title = 'Kubernetes'
    slug = 'kubernetes-destination'
    description = 'Allow the uploading of certificates to Kubernetes as secret'

    author = 'Mikhail Khodorovskiy'
    author_url = 'https://github.com/mik373/lemur'

    options = [
        {
            'name': 'kubernetesURL',
            'type': 'str',
            'required': True,
            'validation': 'https?://[a-zA-Z0-9.-]+(?::[0-9]+)?',
            'helpMessage': 'Must be a valid Kubernetes server URL!',
        },
        {
            'name': 'kubernetesAuthToken',
            'type': 'str',
            'required': True,
            'validation': '[0-9a-zA-Z-_.]+',
            'helpMessage': 'Must be a valid Kubernetes server Token!',
        },
        {
            'name': 'kubernetesServerCertificate',
            'type': 'textarea',
            'required': True,
            'validation': '-----BEGIN CERTIFICATE-----[a-zA-Z0-9/+\\s\\r\\n]+-----END CERTIFICATE-----',
            'helpMessage': 'Must be a valid Kubernetes server Certificate!',
        },
        {
            'name': 'kubernetesNamespace',
            'type': 'str',
            'required': True,
            'validation': '[a-z0-9]([-a-z0-9]*[a-z0-9])?',
            'helpMessage': 'Must be a valid Kubernetes Namespace!',
        },

    ]

    def __init__(self, *args, **kwargs):
        super(KubernetesDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        try:
            k8_bearer = self.get_option('kubernetesAuthToken', options)
            k8_cert = self.get_option('kubernetesServerCertificate', options)
            k8_namespace = self.get_option('kubernetesNamespace', options)
            k8_base_uri = self.get_option('kubernetesURL', options)

            k8s_api = K8sSession(k8_bearer, k8_cert)

            cn = common_name(parse_certificate(body))

            # in the future once runtime properties can be passed-in - use passed-in secret name
            secret_name = 'certs-' + cn

            err = ensure_resource(k8s_api, k8s_base_uri=k8_base_uri, namespace=k8_namespace, kind="secret", name=secret_name, data={
                'apiVersion': 'v1',
                'kind': 'Secret',
                'metadata': {
                    'name': secret_name,
                },
                'data': {
                    'combined.pem': base64encode('%s\n%s' % (body, private_key)),
                    'ca.crt': base64encode(cert_chain),
                    'service.key': base64encode(private_key),
                    'service.crt': base64encode(body),
                }
            })
        except Exception as e:
            current_app.logger.exception("Exception in upload")
            raise e

        if err is not None:
            current_app.logger.debug("Error deploying resource: %s", err)
            raise Exception("Error uploading secret: " + err)


class K8sSession(requests.Session):

    def __init__(self, bearer, cert):
        super(K8sSession, self).__init__()

        self.headers.update({
            'Authorization': 'Bearer %s' % bearer
        })

        k8_ca = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'k8.cert')

        with open(k8_ca, "w") as text_file:
            text_file.write(cert)

        self.verify = k8_ca

    def request(self, method, url, params=None, data=None, headers=None, cookies=None, files=None, auth=None, timeout=30, allow_redirects=True, proxies=None,
                hooks=None, stream=None, verify=None, cert=None, json=None):
        """
        This method overrides the default timeout to be 10s.
        """
        return super(K8sSession, self).request(method, url, params, data, headers, cookies, files, auth, timeout, allow_redirects, proxies, hooks, stream,
                                               verify, cert, json)
