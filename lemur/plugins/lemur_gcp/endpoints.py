from collections import defaultdict
from flask import current_app

from google.cloud.compute_v1.services import (
    ssl_policies,
    global_forwarding_rules,
    forwarding_rules,
    target_https_proxies,
    target_ssl_proxies,
    region_target_https_proxies,
)
from google.cloud.compute_v1 import (
    TargetHttpsProxiesSetSslCertificatesRequest,
    TargetSslProxiesSetSslCertificatesRequest,
    RegionTargetHttpsProxiesSetSslCertificatesRequest,
)

from lemur.plugins.lemur_gcp import certificates, utils


def fetch_target_proxies(project_id, credentials, region):
    """
    Fetches HTTPs target proxies for L7 traffic and SSL target proxies for L4 traffic.

    :param project_id:
    :param credentials:
    :param region:
    :return:
    """
    endpoints = []
    forwarding_rules_map = fetch_forwarding_rules_map(project_id, credentials, region)
    ssl_policies_client = ssl_policies.SslPoliciesClient(credentials=credentials)
    if region:
        # Regional resources include external HTTP(s) and internal HTTP(s) loadbalancers.
        http_proxies_client = (
            region_target_https_proxies.RegionTargetHttpsProxiesClient(
                credentials=credentials
            )
        )
        for proxy in http_proxies_client.list(project=project_id, region=region):
            endpoint = get_endpoint_from_proxy(
                project_id, proxy, ssl_policies_client, forwarding_rules_map
            )
            if endpoint:
                endpoints.append(endpoint)
    else:
        # Global resources include external HTTP(s) and external SSL loadbalancers.
        http_proxies_client = target_https_proxies.TargetHttpsProxiesClient(
            credentials=credentials
        )
        for proxy in http_proxies_client.list(project=project_id):
            endpoint = get_endpoint_from_proxy(
                project_id, proxy, ssl_policies_client, forwarding_rules_map
            )
            if endpoint:
                endpoints.append(endpoint)
        ssl_proxies_client = target_ssl_proxies.TargetSslProxiesClient(
            credentials=credentials
        )
        for proxy in ssl_proxies_client.list(project=project_id):
            endpoint = get_endpoint_from_proxy(
                project_id, proxy, ssl_policies_client, forwarding_rules_map
            )
            if endpoint:
                endpoints.append(endpoint)
    return endpoints


def get_endpoint_from_proxy(
    project_id, proxy, ssl_policies_client, forwarding_rules_map
):
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
            ssl_policy=utils.get_name_from_self_link(proxy.ssl_policy),
        )
        endpoint["policy"] = format_ssl_policy(policy)
    return endpoint


def update_target_proxy_default_cert(
    project_id, credentials, endpoint, certificate, region
):
    """
    Sets the default certificate for targethttpsproxy or targetsslproxy
    :param project_id:
    :param credentials:
    :param endpoint:
    :param certificate:
    :param region:
    :return:
    """
    kind = endpoint.type
    if (
        kind not in ("targethttpsproxy", "targetsslproxy")
        or endpoint.registry_type != "gcp"
    ):
        raise NotImplementedError()
    # Parses the API name from the certificate body. This is because the certificate's name
    # is different from the name of the certificate that finally gets uploaded to GCP.
    cert_name = certificates.get_name(certificate.body)
    cert_self_link = certificates.get_self_link(project_id, cert_name, region)
    if region and kind == "targethttpsproxy":
        current_app.logger.info(
            f"Rotating default cert for regional endpoint {endpoint.name} in {region}"
        )
        client = region_target_https_proxies.RegionTargetHttpsProxiesClient(
            credentials=credentials
        )
        proxy = client.get(
            project=project_id, target_https_proxy=endpoint.name, region=region
        )
        set_region_target_https_proxy_certs(
            project_id,
            client,
            endpoint,
            [cert_self_link] + proxy.ssl_certificates[1:],
            proxy.ssl_certificates,
            region,
        )
    elif not region and kind == "targethttpsproxy":
        current_app.logger.info(
            f"Rotating default cert for global endpoint {endpoint.name}"
        )
        client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_https_proxy=endpoint.name)
        set_target_https_proxy_certs(
            project_id,
            client,
            endpoint,
            [cert_self_link] + proxy.ssl_certificates[1:],
            proxy.ssl_certificates,
        )
    elif not region and kind == "targetsslproxy":
        client = target_ssl_proxies.TargetSslProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_ssl_proxy=endpoint.name)
        set_target_ssl_proxy_certs(
            project_id,
            client,
            endpoint,
            [cert_self_link] + proxy.ssl_certificates[1:],
            proxy.ssl_certificates,
        )
    else:
        raise NotImplementedError()


def set_region_target_https_proxy_certs(
    project_id,
    client: region_target_https_proxies.RegionTargetHttpsProxiesClient,
    endpoint,
    new_self_links,
    old_self_links,
    region,
):
    current_app.logger.info(
        f"Setting certificates from {old_self_links} to {new_self_links} for "
        f"endpoint {endpoint.name}"
    )
    req = RegionTargetHttpsProxiesSetSslCertificatesRequest()
    req.ssl_certificates = new_self_links
    operation = client.set_ssl_certificates(
        project=project_id,
        target_https_proxy=endpoint.name,
        region_target_https_proxies_set_ssl_certificates_request_resource=req,
        region=region,
    )
    operation.result()


def set_target_https_proxy_certs(
    project_id,
    client: target_https_proxies.TargetHttpsProxiesClient,
    endpoint,
    certificate_self_links,
    existing_self_links,
):
    current_app.logger.info(
        f"Setting certificates from {existing_self_links} to {certificate_self_links} for "
        f"endpoint {endpoint.name}"
    )
    req = TargetHttpsProxiesSetSslCertificatesRequest()
    req.ssl_certificates = certificate_self_links
    operation = client.set_ssl_certificates(
        project=project_id,
        target_https_proxy=endpoint.name,
        target_https_proxies_set_ssl_certificates_request_resource=req,
    )
    operation.result()


def set_target_ssl_proxy_certs(
    project_id,
    client: target_ssl_proxies.TargetSslProxiesClient,
    endpoint,
    certificate_self_links,
    existing_self_links,
):
    current_app.logger.info(
        f"Setting certificates from {existing_self_links} to {certificate_self_links} for "
        f"endpoint {endpoint.name}"
    )
    req = TargetSslProxiesSetSslCertificatesRequest()
    req.ssl_certificates = certificate_self_links
    operation = client.set_ssl_certificates(
        project=project_id,
        target_ssl_proxy=endpoint.name,
        target_ssl_proxies_set_ssl_certificates_request_resource=req,
    )
    operation.result()


def update_target_proxy_sni_certs(
    project_id, credentials, endpoint, old_cert, new_cert, region
):
    kind = endpoint.type
    if (
        kind not in ("targethttpsproxy", "targetsslproxy")
        or endpoint.registry_type != "gcp"
    ):
        raise NotImplementedError()
    new_cert_name = certificates.get_name(new_cert.body)
    new_cert_self_link = certificates.get_self_link(project_id, new_cert_name, region)
    if region and kind == "targethttpsproxy":
        current_app.logger.info(
            f"Rotating SNI cert for regional endpoint {endpoint.name} in {region}"
        )
        client = region_target_https_proxies.RegionTargetHttpsProxiesClient(
            credentials=credentials
        )
        proxy = client.get(
            project=project_id, target_https_proxy=endpoint.name, region=region
        )
        certs = calculate_new_certs_for_sni_rotation(
            project_id, credentials, old_cert, proxy, new_cert_self_link, region
        )
        set_region_target_https_proxy_certs(
            project_id, client, endpoint, certs, proxy.ssl_certificates, region
        )
    elif not region and kind == "targethttpsproxy":
        current_app.logger.info(f"Rotating SNI cert for endpoint {endpoint.name}")
        client = target_https_proxies.TargetHttpsProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_https_proxy=endpoint.name)
        certs = calculate_new_certs_for_sni_rotation(
            project_id, credentials, old_cert, proxy, new_cert_self_link, region
        )
        set_target_https_proxy_certs(
            project_id, client, endpoint, certs, proxy.ssl_certificates
        )
    elif not region and kind == "targetsslproxy":
        current_app.logger.info(f"Rotating SNI cert for endpoint {endpoint.name}")
        client = target_ssl_proxies.TargetSslProxiesClient(credentials=credentials)
        proxy = client.get(project=project_id, target_ssl_proxy=endpoint.name)
        certs = calculate_new_certs_for_sni_rotation(
            project_id, credentials, old_cert, proxy, new_cert_self_link, region
        )
        set_target_ssl_proxy_certs(
            project_id, client, endpoint, certs, proxy.ssl_certificates
        )
    else:
        raise NotImplementedError()


def calculate_new_certs_for_sni_rotation(
    project_id, credentials, old_cert, proxy, new_cert_self_link, region
):
    cert_to_delete = certificates.find_cert(
        project_id, credentials, old_cert.body, proxy.ssl_certificates, region
    )
    if not cert_to_delete:
        current_app.logger.warning(
            f"Old cert {old_cert} found by Lemur but not in endpoint - proceeding with "
            "rotation anyway as detaching a non-existent cert is a no-op."
        )
    elif cert_to_delete == proxy.ssl_certificates[0]:
        current_app.logger.warning(
            f"Old cert {old_cert} found by Lemur in endpoint as the default cert."
            "Will not proceed with rotation."
        )
        raise Exception("attempting to rotate primary cert during SNI cert rotation")
    certs = certificates.calc_diff(
        proxy.ssl_certificates, new_cert_self_link, cert_to_delete
    )
    assert proxy.ssl_certificates[0] == certs[0]
    return certs


def fetch_forwarding_rules_map(project_id, credentials, region=None):
    """
    Gets the forwarding rules for the project, keyed by target name.
    :param project_id:
    :param credentials:
    :param region:
    :return:
    """
    forwarding_rules_map = defaultdict(list)
    if region:
        forwarding_rules_client = forwarding_rules.ForwardingRulesClient(
            credentials=credentials
        )
        pager = forwarding_rules_client.list(project=project_id, region=region)
    else:
        forwarding_rules_client = global_forwarding_rules.GlobalForwardingRulesClient(
            credentials=credentials
        )
        pager = forwarding_rules_client.list(project=project_id)
    # Multiple forwarding rules can reference the same target proxy
    # Construct a mapping of targets -> list of forwarding rules that use the target
    for rule in pager:
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
    return dict(
        name=policy.name, ciphers=[cipher for cipher in policy.enabled_features]
    )
