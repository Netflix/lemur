"""
.. module: lemur.plugins.lemur_kubernetes.aws
    :platform: Unix
    :copyright: (c) 2015 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.

.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>

    The plugin inserts certificates and the private key as Kubernetes secret that
     can later be used to secure service endpoints running in Kubernetes pods

"""
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from lemur.certificates.models import get_cn
from lemur.plugins.bases import DestinationPlugin

import itertools
import base64
import requests
import urllib

DEFAULT_API_VERSION = 'v1'


def ensure_resource(k8s_api, k8s_base_uri, namespace, kind, name, data):

    # _resolve_uri(k8s_base_uri, namespace, kind, name, api_ver=DEFAULT_API_VERSION)
    url = _resolve_uri(k8s_base_uri, namespace, kind)

    create_resp = k8s_api.post(url, json=data)

    if 200 <= create_resp.status_code <= 299:
        return None
    elif create_resp.json()['reason'] != 'AlreadyExists':
        return create_resp.content
    update_resp = k8s_api.put(_resolve_uri(k8s_base_uri, namespace, kind, name), json=data)
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
            'validation': '@(https?|http)://(-\.)?([^\s/?\.#-]+\.?)+(/[^\s]*)?$@iS',
            'helpMessage': 'Must be a valid Kubernetes server URL!',
        },
        {
            'name': 'kubernetesAuthToken',
            'type': 'str',
            'required': True,
            'validation': '/^$|\s+/',
            'helpMessage': 'Must be a valid Kubernetes server Token!',
        },
        {
            'name': 'kubernetesServerCertificate',
            'type': 'str',
            'required': True,
            'validation': '/^$|\s+/',
            'helpMessage': 'Must be a valid Kubernetes server Certificate!',
        },
        {
            'name': 'kubernetesNamespace',
            'type': 'str',
            'required': True,
            'validation': '/^$|\s+/',
            'helpMessage': 'Must be a valid Kubernetes Namespace!',
        },

    ]

    def __init__(self, *args, **kwargs):
        super(KubernetesDestinationPlugin, self).__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        k8_bearer = self.get_option('kubernetesAuthToken', options)
        k8_cert = self.get_option('kubernetesServerCertificate', options)
        k8_namespace = self.get_option('kubernetesNamespace', options)
        k8_base_uri = self.get_option('kubernetesURL', options)

        k8s_api = K8sSession(k8_bearer, k8_cert)

        cert = x509.load_pem_x509_certificate(str(body), default_backend())
        name = get_cn(cert)

        # in the future once runtime properties can be passed-in - use passed-in secret name
        secret_name = 'certs-' + urllib.quote_plus(name)

        err = ensure_resource(k8s_api, k8s_base_uri=k8_base_uri, namespace=k8_namespace, kind="secret", name=secret_name, data={
            'apiVersion': 'v1',
            'kind': 'Secret',
            'metadata': {
                'name': secret_name,
            },
            'data': {
                'combined.pem': base64.b64encode(body + private_key),
                'ca.crt': base64.b64encode(cert_chain),
                'service.key': base64.b64encode(private_key),
                'service.crt': base64.b64encode(body),
            }
        })

        if err is not None:
            raise Exception("Error uploading secret: " + err)


class K8sSession(requests.Session):

    def __init__(self, bearer, cert):
        super(K8sSession, self).__init__()

        self.headers.update({
            'Authorization': 'Bearer %s' % bearer
        })

        k8_ca = '/tmp/k8.cert'

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
