from collections import defaultdict
from flask import current_app

from google.cloud.compute_v1.services import ssl_policies, global_forwarding_rules, \
    target_https_proxies, target_ssl_proxies
from google.cloud.compute_v1 import TargetHttpsProxiesSetSslCertificatesRequest, \
    TargetSslProxiesSetSslCertificatesRequest

from lemur.plugins.lemur_gcp import certificates, utils


def fetch_target_proxies(project_id, credentials):
    """
    Fetches HTTPs target proxies for L7 traffic and SSL target proxies for L4 traffic.

    :param project_id:
    :param credentials:
    :return:
    """
    endpoints = []
    forwarding_rules_map = fetch_global_forwarding_rules_map(project_id, credentials)
    http_proxies_client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
    ssl_policies_client = ssl_policies.SslPoliciesClient(credentials=credentials)
    for proxy in http_proxies_client.list(project=project_id):
        endpoint = get_endpoint_from_proxy(project_id, proxy, ssl_policies_client, forwarding_rules_map)
        if endpoint:
            endpoints.append(endpoint)
    ssl_proxies_client = target_ssl_proxies.TargetSslProxiesClient(credentials=credentials)
    for proxy in ssl_proxies_client.list(project=project_id):
        endpoint = get_endpoint_from_proxy(project_id, proxy, ssl_policies_client, forwarding_rules_map)
        if endpoint:
            endpoints.append(endpoint)
    return endpoints


def get_endpoint_from_proxy(project_id, proxy, ssl_policies_client, forwarding_rules_map):
    """
    Converts a proxy (either HTTPs or SSL) into a Lemur endpoint.
    :param project_id:
    :param proxy:
    :param ssl_policies_client:
    :param forwarding_rules_map:
    :return:
    """
    kind = proxy.kind.split("#")[-1].lower()
    if kind not in ("targethttpsproxy", "targetsslproxy"):
        return None
    if len(proxy.ssl_certificates) == 0:
        return None
    fw_rules = forwarding_rules_map.get(proxy.self_link, None)
    if not fw_rules:
        return None
    fw_rule_ingresses = []
    for rule in fw_rules:
        ip = rule.I_p_address
        port = rule.port_range.split("-")[0]
        fw_rule_ingresses.append((ip, port))
    fw_rule_ingresses.sort()
    primary_ip, primary_port = fw_rule_ingresses[0][0], fw_rule_ingresses[0][1]
    endpoint = dict(
        name=proxy.name,
        type=kind,
        dnsname=primary_ip,
        port=primary_port,
        policy=dict(
            name="",
            ciphers=[],
        ),
        sni_certificates=[],
    )
    for idx, self_link in enumerate(proxy.ssl_certificates):
        crt = dict(
            name=utils.get_name_from_self_link(self_link),
            path="",
            registry_type="gcp",
        )
        # The first certificate is the primary.
        # See https://cloud.google.com/sdk/gcloud/reference/compute/target-https-proxies/update
        if idx == 0:
            endpoint["primary_certificate"] = crt
        else:
            endpoint["sni_certificates"].append(crt)
    if len(fw_rule_ingresses) > 1:
        endpoint["aliases"] = [info[0] for info in fw_rule_ingresses[1:]]
    if proxy.ssl_policy:
        policy = ssl_policies_client.get(
            project=project_id,
            ssl_policy=utils.get_name_from_self_link(proxy.ssl_policy))
        endpoint["policy"] = format_ssl_policy(policy)
    return endpoint


def update_target_proxy_default_cert(project_id, credentials, endpoint, certificate):
    """
    Sets the default certificate for targethttpsproxy or targetsslproxy
    :param project_id:
    :param credentials:
    :param endpoint:
    :param certificate:
    :return:
    """
    kind = endpoint.type
    if kind not in ("targethttpsproxy", "targetsslproxy") or endpoint.registry_type != "gcp":
        raise NotImplementedError()
    current_app.logger.info(f"Rotating default cert for endpoint {endpoint.name}")
    # Parses the API name from the certificate body. This is because the certificate's name
    # is different from the name of the certificate that finally gets uploaded to GCP.
    cert_name = certificates.get_name(certificate.body)
    cert_self_link = certificates.get_self_link(project_id, cert_name)
    if kind == "targethttpsproxy":
        client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_https_proxy=endpoint.name)
        set_target_https_proxy_certs(
            project_id, client, endpoint, [cert_self_link] + proxy.ssl_certificates[1:], proxy.ssl_certificates)
    elif kind == "targetsslproxy":
        client = target_ssl_proxies.TargetSslProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_ssl_proxy=endpoint.name)
        set_target_ssl_proxy_certs(
            project_id, client, endpoint, [cert_self_link] + proxy.ssl_certificates[1:], proxy.ssl_certificates)


def set_target_https_proxy_certs(project_id, client, endpoint, certificate_self_links, existing_self_links):
    current_app.logger.info(f"Setting certificates from {existing_self_links} to {certificate_self_links} for "
                            f"endpoint {endpoint.name}")
    req = TargetHttpsProxiesSetSslCertificatesRequest()
    req.ssl_certificates = certificate_self_links
    operation = client.set_ssl_certificates(
        project=project_id,
        target_https_proxy=endpoint.name,
        target_https_proxies_set_ssl_certificates_request_resource=req,
    )
    operation.result()


def set_target_ssl_proxy_certs(project_id, client, endpoint, certificate_self_links, existing_self_links):
    current_app.logger.info(f"Setting certificates from {existing_self_links} to {certificate_self_links} for "
                            f"endpoint {endpoint.name}")
    req = TargetSslProxiesSetSslCertificatesRequest()
    req.ssl_certificates = certificate_self_links
    operation = client.set_ssl_certificates(
        project=project_id,
        target_ssl_proxy=endpoint.name,
        target_ssl_proxies_set_ssl_certificates_request_resource=req,
    )
    operation.result()


def update_target_proxy_sni_certs(project_id, credentials, endpoint, old_cert, new_cert):
    kind = endpoint.type
    if kind not in ("targethttpsproxy", "targetsslproxy") or endpoint.registry_type != "gcp":
        raise NotImplementedError()
    current_app.logger.info(f"Rotating SNI cert for endpoint {endpoint.name}")
    new_cert_name = certificates.get_name(new_cert.body)
    new_cert_self_link = certificates.get_self_link(project_id, new_cert_name)
    if kind == "targethttpsproxy":
        client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_https_proxy=endpoint.name)
        cert_to_delete = certificates.find_cert(project_id, credentials, old_cert.body, proxy.ssl_certificates)
        if not cert_to_delete:
            current_app.logger.warning(f"Old cert {old_cert} found by Lemur but not in endpoint - proceeding with "
                                       "rotation anyway as detaching a non-existent cert is a no-op.")
        certs = certificates.calc_diff(proxy.ssl_certificates, new_cert_self_link, cert_to_delete)
        set_target_https_proxy_certs(project_id, client, endpoint, certs, proxy.ssl_certificates)
    elif kind == "targetsslproxy":
        client = target_ssl_proxies.TargetSslProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_ssl_proxy=endpoint.name)
        cert_to_delete = certificates.find_cert(project_id, credentials, old_cert.body, proxy.ssl_certificates)
        if not cert_to_delete:
            current_app.logger.warning(f"Old cert {old_cert} found by Lemur but not in endpoint - proceeding with "
                                       "rotation anyway as detaching a non-existent cert is a no-op.")
        certs = certificates.calc_diff(proxy.ssl_certificates, new_cert_self_link, cert_to_delete)
        set_target_ssl_proxy_certs(project_id, client, endpoint, certs, proxy.ssl_certificates)


def fetch_global_forwarding_rules_map(project_id, credentials):
    """
    Gets the global forwarding rules for the project, keyed by target name.
    :param project_id:
    :param credentials:
    :return:
    """
    forwarding_rules_client = global_forwarding_rules.GlobalForwardingRulesClient(credentials=credentials)
    forwarding_rules_map = defaultdict(list)
    # Multiple forwarding rules can reference the same target proxy
    # Construct a mapping of targets -> list of forwarding rules that use the target
    for rule in forwarding_rules_client.list(project=project_id):
        forwarding_rules_map[rule.target].append(rule)
    return forwarding_rules_map


def format_ssl_policy(policy):
    """
    Format cipher policy information for an HTTPs target proxy into a common format.
    :param policy:
    :return:
    """
    if not policy:
        return dict(name="", ciphers=[])
    return dict(name=policy.name, ciphers=[cipher for cipher in policy.enabled_features])
