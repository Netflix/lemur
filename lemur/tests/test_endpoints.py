import pytest

from lemur.endpoints.views import *  # noqa
from lemur.tests.factories import EndpointFactory, CertificateFactory


from .vectors import (
    VALID_ADMIN_API_TOKEN,
    VALID_ADMIN_HEADER_TOKEN,
    VALID_USER_HEADER_TOKEN,
)


def test_rotate_primary_certificate(client, source_plugin):
    from lemur.deployment.service import rotate_certificate

    new_certificate = CertificateFactory()
    endpoint = EndpointFactory()

    rotate_certificate(endpoint, None, new_certificate)
    assert endpoint.certificate == new_certificate


def test_rotate_sni_certificate(client, source_plugin):
    from lemur.deployment.service import rotate_certificate

    old_sni_certificate = CertificateFactory()
    new_sni_certificate = CertificateFactory()
    new_sni_certificate.replaces = [old_sni_certificate]

    endpoint = EndpointFactory()
    primary_certificate = endpoint.primary_certificate
    endpoint.add_sni_certificate(old_sni_certificate)

    rotate_certificate(endpoint, old_sni_certificate, new_sni_certificate)
    assert endpoint.primary_certificate == primary_certificate
    assert endpoint.sni_certificates == [new_sni_certificate]


def test_get_by_name_and_source(client, source_plugin):
    from lemur.endpoints.service import get_by_name_and_source

    endpoint = EndpointFactory()
    assert endpoint == get_by_name_and_source(endpoint.name, endpoint.source.label)


def test_get_all_pending_rotation(client, source_plugin):
    from lemur.endpoints.service import get_all_pending_rotation

    endpoint = EndpointFactory()
    endpoint.certificate = CertificateFactory()
    new_certificate = CertificateFactory()
    endpoint.certificate.replaced = [new_certificate]

    assert [endpoint] == get_all_pending_rotation()


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 404),
        (VALID_ADMIN_HEADER_TOKEN, 404),
        (VALID_ADMIN_API_TOKEN, 404),
        ("", 401),
    ],
)
def test_endpoint_get(client, token, status):
    assert (
        client.get(api.url_for(Endpoints, endpoint_id=999), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_endpoint_post_(client, token, status):
    assert (
        client.post(
            api.url_for(Endpoints, endpoint_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_endpoint_put(client, token, status):
    assert (
        client.put(
            api.url_for(Endpoints, endpoint_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_endpoint_delete(client, token, status):
    assert (
        client.delete(api.url_for(Endpoints, endpoint_id=1), headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_endpoint_patch(client, token, status):
    assert (
        client.patch(
            api.url_for(Endpoints, endpoint_id=1), data={}, headers=token
        ).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_endpoint_list_post_(client, token, status):
    assert (
        client.post(api.url_for(EndpointsList), data={}, headers=token).status_code
        == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 200),
        (VALID_ADMIN_HEADER_TOKEN, 200),
        (VALID_ADMIN_API_TOKEN, 200),
        ("", 401),
    ],
)
def test_endpoint_list_get(client, token, status):
    assert client.get(api.url_for(EndpointsList), headers=token).status_code == status


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_endpoint_list_delete(client, token, status):
    assert (
        client.delete(api.url_for(EndpointsList), headers=token).status_code == status
    )


@pytest.mark.parametrize(
    "token,status",
    [
        (VALID_USER_HEADER_TOKEN, 405),
        (VALID_ADMIN_HEADER_TOKEN, 405),
        (VALID_ADMIN_API_TOKEN, 405),
        ("", 405),
    ],
)
def test_endpoint_list_patch(client, token, status):
    assert (
        client.patch(api.url_for(EndpointsList), data={}, headers=token).status_code
        == status
    )


def test_rotate_cli_bulk(session, source_plugin):
    """
    Ensure that the CLI command 'lemur certificate rotate' correctly rotates
    all endpoints which have a certificate attached to it that has been re-issued.
    """
    from lemur.certificates.cli import rotate

    old_cert1, new_cert1 = CertificateFactory(), CertificateFactory()
    old_cert2, new_cert2 = CertificateFactory(), CertificateFactory()
    ep1, ep2, ep3 = EndpointFactory(), EndpointFactory(), EndpointFactory()
    session.commit()

    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep1, old_primary_certificate=old_cert1, new_primary_certificate=new_cert1
    )
    _setup_rotation_eligible_endpoint_sni_certificate(
        endpoint=ep2, old_sni_certificate=old_cert1, new_sni_certificate=new_cert1
    )
    _setup_rotation_eligible_endpoint(
        endpoint=ep3,
        old_primary_certificate=old_cert1, new_primary_certificate=new_cert1,
        old_sni_certificate=old_cert2, new_sni_certificate=new_cert2,
    )

    rotate(
        endpoint_name=None,
        source=None,
        old_certificate_name=None,
        new_certificate_name=None,
        message=None,
        commit=True,
        region=None
    )

    assert ep1.primary_certificate == new_cert1
    assert len(ep1.sni_certificates) == 0

    assert ep2.primary_certificate is None
    assert ep2.sni_certificates == [new_cert1]

    assert ep3.primary_certificate == new_cert1
    assert ep3.sni_certificates == [new_cert2]


def test_rotate_cli_bulk_in_region(session, source_plugin):
    """
    Ensure that the CLI command 'lemur certificate rotate --region <region>' correctly rotates
    all endpoints in the given region which have a certificate attached to it that has been re-issued.
    """
    from lemur.certificates.cli import rotate

    old_cert1, new_cert1 = CertificateFactory(), CertificateFactory()
    old_cert2, new_cert2 = CertificateFactory(), CertificateFactory()
    ep1, ep2, ep3 = EndpointFactory(), EndpointFactory(), EndpointFactory()
    ep1.dnsname = "my-loadbalancer1-1234567890.us-east-1.elb.amazonaws.com"
    ep2.dnsname = "my-loadbalancer2-1234567890.us-east-1.elb.amazonaws.com"
    ep3.dnsname = "my-loadbalancer3-1234567890.us-west-2.elb.amazonaws.com"
    session.commit()

    _setup_rotation_eligible_endpoint(
        endpoint=ep1,
        old_primary_certificate=old_cert1, new_primary_certificate=new_cert1,
        old_sni_certificate=old_cert2, new_sni_certificate=new_cert2,
    )
    _setup_rotation_eligible_endpoint(
        endpoint=ep2,
        old_primary_certificate=old_cert1, new_primary_certificate=new_cert1,
        old_sni_certificate=old_cert2, new_sni_certificate=new_cert2,
    )
    _setup_rotation_eligible_endpoint(
        endpoint=ep3,
        old_primary_certificate=old_cert1, new_primary_certificate=new_cert1,
        old_sni_certificate=old_cert2, new_sni_certificate=new_cert2,
    )

    rotate(
        endpoint_name=None,
        source=None,
        old_certificate_name=None,
        new_certificate_name=None,
        message=None,
        commit=True,
        region="us-east-1"
    )

    assert ep1.primary_certificate == new_cert1
    assert ep1.sni_certificates == [new_cert2]

    assert ep2.primary_certificate == new_cert1
    assert ep2.sni_certificates == [new_cert2]

    assert ep3.primary_certificate == old_cert1
    assert ep3.sni_certificates == [old_cert2]


def test_rotate_cli_old_to_new(session, source_plugin):
    """
    Ensure that the CLI command 'lemur rotate -n <new_certificate_name> -o <old_certificate_name>
    correctly rotates all endpoints using the old certificate with the new certificate.
    """
    from lemur.certificates.cli import rotate

    old_cert1, new_cert1 = CertificateFactory(), CertificateFactory()
    old_cert2, new_cert2 = CertificateFactory(), CertificateFactory()
    ep1, ep2, ep3 = EndpointFactory(), EndpointFactory(), EndpointFactory()
    session.commit()

    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep1, old_primary_certificate=old_cert1, new_primary_certificate=new_cert1
    )
    _setup_rotation_eligible_endpoint_sni_certificate(
        endpoint=ep2, old_sni_certificate=old_cert1, new_sni_certificate=new_cert1
    )
    _setup_rotation_eligible_endpoint(
        endpoint=ep3,
        old_primary_certificate=old_cert1, new_primary_certificate=new_cert1,
        old_sni_certificate=old_cert2, new_sni_certificate=new_cert2,
    )

    rotate(
        endpoint_name=None,
        source=None,
        old_certificate_name=old_cert1.name,
        new_certificate_name=new_cert1.name,
        message=None,
        commit=True,
        region=None
    )

    assert ep1.primary_certificate == new_cert1
    assert len(ep1.sni_certificates) == 0

    assert ep2.primary_certificate is None
    assert ep2.sni_certificates == [new_cert1]

    assert ep3.primary_certificate == new_cert1
    assert ep3.sni_certificates == [old_cert2]

    rotate(
        endpoint_name=None,
        source=None,
        old_certificate_name=old_cert2.name,
        new_certificate_name=new_cert2.name,
        message=None,
        commit=True,
        region=None
    )

    assert ep3.primary_certificate == new_cert1
    assert ep3.sni_certificates == [new_cert2]


def test_rotate_cli_endpoint(session, source_plugin):
    """
    Ensure that the CLI command 'lemur rotate -e <endpoint_name> -n <new_certificate_name>
    correctly rotates the specified endpoint using the specified certificate.
    """
    from lemur.certificates.cli import rotate

    old_cert1, new_cert1 = CertificateFactory(), CertificateFactory()
    old_cert2, new_cert2 = CertificateFactory(), CertificateFactory()
    ep1, ep2, ep3 = EndpointFactory(), EndpointFactory(), EndpointFactory()
    session.commit()

    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep1, old_primary_certificate=old_cert1, new_primary_certificate=new_cert1
    )

    _setup_rotation_eligible_endpoint_sni_certificate(
        endpoint=ep2, old_sni_certificate=old_cert1, new_sni_certificate=new_cert1
    )

    _setup_rotation_eligible_endpoint(
        endpoint=ep3,
        old_primary_certificate=old_cert1, new_primary_certificate=new_cert1,
        old_sni_certificate=old_cert2, new_sni_certificate=new_cert2,
    )

    rotate(
        endpoint_name=ep1.name,
        source=None,
        old_certificate_name=None,
        new_certificate_name=new_cert1.name,
        message=None,
        commit=True,
        region=None
    )

    assert ep1.primary_certificate == new_cert1
    assert len(ep1.sni_certificates) == 0

    assert ep2.primary_certificate is None
    assert ep2.sni_certificates == [old_cert1]

    assert ep3.primary_certificate == old_cert1
    assert ep3.sni_certificates == [old_cert2]

    rotate(
        endpoint_name=ep2.name,
        source=None,
        old_certificate_name=None,
        new_certificate_name=new_cert1.name,
        message=None,
        commit=True,
        region=None
    )

    assert ep1.primary_certificate == new_cert1
    assert len(ep1.sni_certificates) == 0

    assert ep2.primary_certificate is None
    assert ep2.sni_certificates == [old_cert1]

    assert ep3.primary_certificate == old_cert1
    assert ep3.sni_certificates == [old_cert2]

    rotate(
        endpoint_name=ep3.name,
        source=None,
        old_certificate_name=None,
        new_certificate_name=new_cert1.name,
        message=None,
        commit=True,
        region=None
    )

    assert ep1.primary_certificate == new_cert1
    assert len(ep1.sni_certificates) == 0

    assert ep2.primary_certificate is None
    assert ep2.sni_certificates == [old_cert1]

    assert ep3.primary_certificate == new_cert1
    assert ep3.sni_certificates == [old_cert2]


def _setup_rotation_eligible_endpoint_primary_certificate(endpoint, old_primary_certificate, new_primary_certificate):
    """Sets up an endpoint with only a primary certificate that is eligible for rotation."""
    old_primary_certificate.replaced = [new_primary_certificate]
    new_primary_certificate.replaces = [old_primary_certificate]
    endpoint.primary_certificate = old_primary_certificate


def _setup_rotation_eligible_endpoint_sni_certificate(endpoint, old_sni_certificate, new_sni_certificate):
    """Sets up an endpoint both only a SNI certificate that is eligible for rotation."""
    old_sni_certificate.replaced = [new_sni_certificate]
    new_sni_certificate.replaces = [old_sni_certificate]
    endpoint.add_sni_certificate(old_sni_certificate)


def _setup_rotation_eligible_endpoint(
        endpoint,
        old_primary_certificate,
        new_primary_certificate,
        old_sni_certificate,
        new_sni_certificate
):
    """Sets up an endpoint both both a primary and SNI certificate that is eligible for rotation."""
    old_primary_certificate.replaced = [new_primary_certificate]
    old_sni_certificate.replaced = [new_sni_certificate]
    new_primary_certificate.replaces = [old_primary_certificate]
    new_sni_certificate.replaces = [old_sni_certificate]
    endpoint.primary_certificate = old_primary_certificate
    endpoint.add_sni_certificate(old_sni_certificate)
