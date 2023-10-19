"""
.. module: lemur.plugins.lemur_kubernetes.plugin
    :platform: Unix
    :copyright: (c) 2018 by Netflix Inc., see AUTHORS for more
    :license: Apache, see LICENSE for more details.


    The plugin inserts certificates and the private key as Kubernetes secret that
     can later be used to secure service endpoints running in Kubernetes pods

.. moduleauthor:: Mikhail Khodorovskiy <mikhail.khodorovskiy@jivesoftware.com>
"""
import itertools
import os

import requests
from flask import current_app

from lemur.common.defaults import common_name
from lemur.common.utils import parse_certificate, base64encode, check_validation
from lemur.plugins.bases import DestinationPlugin

DEFAULT_API_VERSION = "v1"


def ensure_resource(k8s_api, k8s_base_uri, namespace, kind, name, data):
    # _resolve_uri(k8s_base_uri, namespace, kind, name, api_ver=DEFAULT_API_VERSION)
    url = _resolve_uri(k8s_base_uri, namespace, kind)
    current_app.logger.debug("K8S POST request URL: %s", url)

    create_resp = k8s_api.post(url, json=data)
    current_app.logger.debug("K8S POST response: %s", create_resp)

    if 200 <= create_resp.status_code <= 299:
        return None
    elif create_resp.json().get("reason", "") != "AlreadyExists":
        return create_resp.content

    url = _resolve_uri(k8s_base_uri, namespace, kind, name)
    current_app.logger.debug("K8S PUT request URL: %s", url)

    update_resp = k8s_api.put(url, json=data)
    current_app.logger.debug("K8S PUT response: %s", update_resp)

    if not 200 <= update_resp.status_code <= 299:
        return update_resp.content

    return


def _resolve_ns(k8s_base_uri, namespace, api_ver=DEFAULT_API_VERSION):
    api_group = "api"
    if "/" in api_ver:
        api_group = "apis"
    return "{base}/{api_group}/{api_ver}/namespaces".format(
        base=k8s_base_uri, api_group=api_group, api_ver=api_ver
    ) + ("/" + namespace if namespace else "")


def _resolve_uri(k8s_base_uri, namespace, kind, name=None, api_ver=DEFAULT_API_VERSION):
    if not namespace:
        namespace = "default"

    return "/".join(
        itertools.chain.from_iterable(
            [
                (_resolve_ns(k8s_base_uri, namespace, api_ver=api_ver),),
                ((kind + "s").lower(),),
                (name,) if name else (),
            ]
        )
    )


def build_secret(secret_format, secret_name, body, private_key, cert_chain):
    secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {"name": secret_name},
    }
    if secret_format == "Full":
        secret["data"] = {
            "combined.pem": base64encode("{}\n{}".format(body, private_key)),
            "ca.crt": base64encode(cert_chain),
            "service.key": base64encode(private_key),
            "service.crt": base64encode(body),
        }
    if secret_format == "TLS":
        secret["type"] = "kubernetes.io/tls"
        secret["data"] = {
            "tls.crt": base64encode("{}\n{}".format(body, cert_chain)),
            "tls.key": base64encode(private_key),
        }
    if secret_format == "Certificate":
        secret["data"] = {"tls.crt": base64encode(cert_chain)}
    return secret


class KubernetesDestinationPlugin(DestinationPlugin):
    title = "Kubernetes"
    slug = "kubernetes-destination"
    description = "Allow the uploading of certificates to Kubernetes as secret"

    author = "Mikhail Khodorovskiy"
    author_url = "https://github.com/mik373/lemur"

    options = [
        {
            "name": "secretNameFormat",
            "type": "str",
            "required": False,
            # Validation is difficult. This regex is used by kubectl to validate secret names:
            #  [a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*
            # Allowing the insertion of "{common_name}" (or any other such placeholder}
            # at any point in the string proved very challenging and had a tendency to
            # cause my browser to hang. The specified expression will allow any valid string
            # but will also accept many invalid strings.
            "validation": check_validation("(?:[a-z0-9.-]|\\{common_name\\})+"),
            "helpMessage": 'Must be a valid secret name, possibly including "{common_name}"',
            "default": "{common_name}",
        },
        {
            "name": "kubernetesURL",
            "type": "str",
            "required": False,
            "validation": check_validation("https?://[a-zA-Z0-9.-]+(?::[0-9]+)?"),
            "helpMessage": "Must be a valid Kubernetes server URL!",
            "default": "https://kubernetes.default",
        },
        {
            "name": "kubernetesAuthToken",
            "type": "str",
            "required": False,
            "validation": check_validation("[0-9a-zA-Z-_.]+"),
            "helpMessage": "Must be a valid Kubernetes server Token!",
        },
        {
            "name": "kubernetesAuthTokenFile",
            "type": "str",
            "required": False,
            "validation": check_validation("(/[^/]+)+"),
            "helpMessage": "Must be a valid file path!",
            "default": "/var/run/secrets/kubernetes.io/serviceaccount/token",
        },
        {
            "name": "kubernetesServerCertificate",
            "type": "textarea",
            "required": False,
            "validation": check_validation("-----BEGIN CERTIFICATE-----[a-zA-Z0-9/+\\s\\r\\n]+-----END CERTIFICATE-----"),
            "helpMessage": "Must be a valid Kubernetes server Certificate!",
        },
        {
            "name": "kubernetesServerCertificateFile",
            "type": "str",
            "required": False,
            "validation": check_validation("(/[^/]+)+"),
            "helpMessage": "Must be a valid file path!",
            "default": "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        },
        {
            "name": "kubernetesNamespace",
            "type": "str",
            "required": False,
            "validation": check_validation("[a-z0-9]([-a-z0-9]*[a-z0-9])?"),
            "helpMessage": "Must be a valid Kubernetes Namespace!",
        },
        {
            "name": "kubernetesNamespaceFile",
            "type": "str",
            "required": False,
            "validation": check_validation("(/[^/]+)+"),
            "helpMessage": "Must be a valid file path!",
            "default": "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
        },
        {
            "name": "secretFormat",
            "type": "select",
            "required": True,
            "available": ["Full", "TLS", "Certificate"],
            "helpMessage": "The type of Secret to create.",
            "default": "Full",
        },
    ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def upload(self, name, body, private_key, cert_chain, options, **kwargs):

        try:
            k8_base_uri = self.get_option("kubernetesURL", options)
            secret_format = self.get_option("secretFormat", options)
            k8s_api = K8sSession(self.k8s_bearer(options), self.k8s_cert(options))
            cn = common_name(parse_certificate(body))
            secret_name_format = self.get_option("secretNameFormat", options)
            secret_name = secret_name_format.format(common_name=cn)
            secret = build_secret(
                secret_format, secret_name, body, private_key, cert_chain
            )
            err = ensure_resource(
                k8s_api,
                k8s_base_uri=k8_base_uri,
                namespace=self.k8s_namespace(options),
                kind="secret",
                name=secret_name,
                data=secret,
            )

        except Exception as e:
            current_app.logger.exception(
                f"Exception in upload: {e}", exc_info=True
            )
            raise

        if err is not None:
            current_app.logger.error("Error deploying resource: %s", err)
            raise Exception("Error uploading secret: " + err)

    def k8s_bearer(self, options):
        bearer = self.get_option("kubernetesAuthToken", options)
        if not bearer:
            bearer_file = self.get_option("kubernetesAuthTokenFile", options)
            with open(bearer_file) as file:
                bearer = file.readline()
            if bearer:
                current_app.logger.debug("Using token read from %s", bearer_file)
            else:
                raise Exception(
                    "Unable to locate token in options or from %s", bearer_file
                )
        else:
            current_app.logger.debug("Using token from options")
        return bearer

    def k8s_cert(self, options):
        cert_file = self.get_option("kubernetesServerCertificateFile", options)
        cert = self.get_option("kubernetesServerCertificate", options)
        if cert:
            cert_file = os.path.join(
                os.path.abspath(os.path.dirname(__file__)), "k8.cert"
            )
            with open(cert_file, "w") as text_file:
                text_file.write(cert)
            current_app.logger.debug("Using certificate from options")
        else:
            current_app.logger.debug("Using certificate from %s", cert_file)
        return cert_file

    def k8s_namespace(self, options):
        namespace = self.get_option("kubernetesNamespace", options)
        if not namespace:
            namespace_file = self.get_option("kubernetesNamespaceFile", options)
            with open(namespace_file) as file:
                namespace = file.readline()
            if namespace:
                current_app.logger.debug(
                    "Using namespace %s from %s", namespace, namespace_file
                )
            else:
                raise Exception(
                    "Unable to locate namespace in options or from %s", namespace_file
                )
        else:
            current_app.logger.debug("Using namespace %s from options", namespace)
        return namespace


class K8sSession(requests.Session):
    def __init__(self, bearer, cert_file):
        super().__init__()

        self.headers.update({"Authorization": "Bearer %s" % bearer})

        self.verify = cert_file

    def request(
        self,
        method,
        url,
        params=None,
        data=None,
        headers=None,
        cookies=None,
        files=None,
        auth=None,
        timeout=30,
        allow_redirects=True,
        proxies=None,
        hooks=None,
        stream=None,
        verify=None,
        cert=None,
        json=None,
    ):
        """
        This method overrides the default timeout to be 10s.
        """
        return super().request(
            method,
            url,
            params,
            data,
            headers,
            cookies,
            files,
            auth,
            timeout,
            allow_redirects,
            proxies,
            hooks,
            stream,
            verify,
            cert,
            json,
        )
