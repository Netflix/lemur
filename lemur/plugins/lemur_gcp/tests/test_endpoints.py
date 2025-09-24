from unittest import mock
from collections import defaultdict
from google.cloud.compute_v1 import types

target1_self_link = "https://www.googleapis.com/compute/v1/projects/staging/global/targetHttpsProxies/target1"

fw_rule_1 = types.ForwardingRule()
fw_rule_1.I_p_address = "1.2.3.4"
fw_rule_1.target = target1_self_link
fw_rule_1.port_range = "443-443"

fw_rule_2 = types.ForwardingRule()
fw_rule_2.I_p_address = "1.2.3.5"
fw_rule_2.target = target1_self_link
fw_rule_2.port_range = "443-443"

forwarding_rules = defaultdict(list)
forwarding_rules[target1_self_link] = [fw_rule_1, fw_rule_2]


def test_get_endpoint_from_proxy():
    from lemur.plugins.lemur_gcp.endpoints import get_endpoint_from_proxy

    proxy = types.TargetHttpsProxy()
    proxy.name = "test-https-proxy"
    proxy.kind = "compute#targetHttpsProxy"
    proxy.ssl_certificates = [
        "https://www.googleapis.com/compute/v1/projects/staging/global/sslCertificates/cert1"
    ]
    proxy.self_link = target1_self_link
    proxy.ssl_policy = "https://www.googleapis.com/compute/v1/projects/staging/global/sslPolicies/policy1"

    policy = types.SslPolicy()
    policy.name = "policy1"
    policy.enabled_features = ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"]
    ssl_policies_client = mock.Mock()
    ssl_policies_client.get.return_value = policy

    endpoint = get_endpoint_from_proxy(
        "123", proxy, ssl_policies_client, forwarding_rules
    )
    assert endpoint is not None
    ssl_policies_client.get.assert_called_once_with(project="123", ssl_policy="policy1")
    assert endpoint["name"] == "test-https-proxy"
    assert endpoint["type"] == "targethttpsproxy"
    assert endpoint["dnsname"] == "1.2.3.4"
    assert endpoint["port"] == "443"
    assert endpoint["aliases"] == ["1.2.3.5"]
    assert endpoint["policy"] == {
        "name": "policy1",
        "ciphers": ["TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"],
    }
    assert endpoint["primary_certificate"] == {
        "name": "cert1",
        "registry_type": "gcp",
        "path": "",
    }
