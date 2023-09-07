import pytest

from lemur.endpoints.views import *  # noqa
from lemur.tests.factories import EndpointFactory, CertificateFactory, SourceFactory


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


def test_rotate_cli_by_source_primary(session, source_plugin):
    """
    Ensure that the CLI command 'lemur rotate_by_source --source 'test source'
    correctly rotates all endpoints using the old certificate with the new certificate.
    Ensure that we properly rotate Primary Certificates
    """
    from lemur.certificates.cli import rotate
    from lemur.sources.service import delete as delete_source

    # Setup Primary Certs
    old_cert1, new_cert1 = CertificateFactory(), CertificateFactory()
    old_cert2, new_cert2 = CertificateFactory(), CertificateFactory()

    ep1, ep2 = EndpointFactory(), EndpointFactory()

    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep1, old_primary_certificate=old_cert1, new_primary_certificate=new_cert1
    )

    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep2, old_primary_certificate=old_cert2, new_primary_certificate=new_cert2
    )

    source_name = "test-source"
    source = _setup_source_for_endpoints([ep1, ep2], source_name)

    rotate(
        source=source_name,
        message=None,
        commit=True,
        endpoint_name=None,
        old_certificate_name=None,
        new_certificate_name=None,
        region=None,
    )

    session.commit()

    assert ep1.primary_certificate == new_cert1
    assert ep2.primary_certificate == new_cert2

    # cleanup
    delete_source(source.id)


def test_rotate_cli_by_source_sni(session, source_plugin):
    """
    Ensure that the CLI command 'lemur rotate_by_source --source 'test source'
    correctly rotates all endpoints using the old certificate with the new certificate.
    Ensure that we properly rotate SNI Certificates
    """
    from lemur.certificates.cli import rotate
    from lemur.sources.service import delete as delete_source

    # Setup Primary Certs
    primary_cert1, primary_cert2 = CertificateFactory(), CertificateFactory()

    # Setup SNI Certs
    old_sni_cert1, new_sni_cert1 = CertificateFactory(), CertificateFactory()
    old_sni_cert2, new_sni_cert2 = CertificateFactory(), CertificateFactory()

    # Setup endpoints
    ep1, ep2 = EndpointFactory(), EndpointFactory()

    # Add Primary Certs to Endpoints
    ep1.primary_certificate = primary_cert1
    ep2.primary_certificate = primary_cert2

    _setup_rotation_eligible_endpoint_sni_certificate(ep1, old_sni_cert1, new_sni_cert1)
    _setup_rotation_eligible_endpoint_sni_certificate(ep2, old_sni_cert2, new_sni_cert2)

    # Setup Source
    source_name = "test-source"
    source = _setup_source_for_endpoints([ep1, ep2], source_name)

    session.commit()

    rotate(
        source=source_name,
        message=None,
        commit=True,
        endpoint_name=None,
        old_certificate_name=None,
        new_certificate_name=None,
        region=None,
    )

    # Ensure that SNI certs were rotated
    assert ep1.sni_certificates == [new_sni_cert1]
    assert ep2.sni_certificates == [new_sni_cert2]

    # Ensure that Primary certs were not rotated
    assert ep1.primary_certificate == primary_cert1
    assert ep2.primary_certificate == primary_cert2

    # cleanup
    delete_source(source.id)


def test_rotate_cli_by_source_multiple_sources(session, source_plugin):
    """
    Ensure that the CLI command 'lemur rotate_by_source --source 'test source'
    correctly rotates all endpoints using the old certificate with the new certificate.
    Ensure that when we have multiple Sources we are only rotating the endpoints on the
    source that we pass in
    """
    from lemur.certificates.cli import rotate
    from lemur.sources.service import delete as delete_source

    # These endpoints will be associated to Source="test-source" and should be rotated
    ep1, ep2 = EndpointFactory(), EndpointFactory()

    # These endpoints will be associated to Source="test-source-other" and should NOT be rotated
    ep3, ep4 = EndpointFactory(), EndpointFactory()

    # Setup Primary Certs
    ep1_old_cert, ep1_new_cert = CertificateFactory(), CertificateFactory()
    ep2_old_cert, ep2_new_cert = CertificateFactory(), CertificateFactory()
    ep3_old_cert, ep3_new_cert = CertificateFactory(), CertificateFactory()
    ep4_old_cert, ep4_new_cert = CertificateFactory(), CertificateFactory()

    # Setup all endpoints to be eligible for rotation
    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep1, old_primary_certificate=ep1_old_cert, new_primary_certificate=ep1_new_cert
    )
    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep2, old_primary_certificate=ep2_old_cert, new_primary_certificate=ep2_new_cert
    )
    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep3, old_primary_certificate=ep3_old_cert, new_primary_certificate=ep3_new_cert
    )
    _setup_rotation_eligible_endpoint_primary_certificate(
        endpoint=ep4, old_primary_certificate=ep4_old_cert, new_primary_certificate=ep4_new_cert
    )

    # Associated ep1 and ep2 with Source.label="test-source"
    source_name = "test-source"
    source = _setup_source_for_endpoints([ep1, ep2], source_name)

    # Associated ep3 and ep4 with Source.label="test-source-other"
    source_name_other = "test-source-other"
    source_other = _setup_source_for_endpoints([ep3, ep4], source_name_other)

    session.commit()

    rotate(
        source=source_name,
        message=None,
        commit=True,
        endpoint_name=None,
        old_certificate_name=None,
        new_certificate_name=None,
        region=None,
    )

    # Ensure endpoints associated with Source.label="test-source" are rotated
    assert ep1.primary_certificate == ep1_new_cert
    assert ep2.primary_certificate == ep2_new_cert
    # Ensure endpoints associated with Source.label="test-source-other" are NOT rotated
    assert ep3.primary_certificate == ep3_old_cert
    assert ep4.primary_certificate == ep4_old_cert

    rotate(
        source=source_name_other,
        message=None,
        commit=True,
        endpoint_name=None,
        old_certificate_name=None,
        new_certificate_name=None,
        region=None,
    )

    # Ensure endpoints associated with Source.label="test-source-other" are rotated
    assert ep3.primary_certificate == ep3_new_cert
    assert ep4.primary_certificate == ep4_new_cert

    # cleanup
    delete_source(source.id)
    delete_source(source_other.id)


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


def _setup_source_for_endpoints(endpoints, label):
    source = SourceFactory()
    source.label = label

    for endpoint in endpoints:
        endpoint.source = source

    return source
