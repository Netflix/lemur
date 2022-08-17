import pytest
from lemur.endpoints.models import Endpoint
from lemur.models import EndpointsCertificates
from lemur.tests.factories import CertificateFactory, EndpointFactory
from sqlalchemy.exc import SQLAlchemyError


def test_primary_certificate_assoc(session):
    """Ensure that a primary certificate can be associated with an endpoint."""
    # Create and associate primary certificate with an endpoint
    crt = CertificateFactory()

    expected_endpoint = EndpointFactory()
    expected_endpoint.primary_certificate = crt

    actual_endpoint = session.query(Endpoint).filter(Endpoint.name == expected_endpoint.name).scalar()
    assert expected_endpoint == actual_endpoint
    assert actual_endpoint.primary_certificate == crt


def test_secondary_certificates_assoc(session):
    """Ensure that secondary certificates can be associated with an endpoint."""
    # Create and associate primary certificate with an endpoint
    crt = CertificateFactory()

    expected_endpoint = EndpointFactory()
    expected_endpoint.primary_certificate = crt

    # Create and associate secondary certificates with endpoint
    additional_certs = [CertificateFactory() for _ in range(0, 5)]

    for crt in additional_certs:
        # TODO(EDGE-1363) Expose API for managing secondary certificates associated with an endpoint
        expected_endpoint.certificates_assoc.append(
            EndpointsCertificates(certificate=crt, endpoint=expected_endpoint, primary=False)
        )

    actual_endpoint = session.query(Endpoint).filter(Endpoint.name == expected_endpoint.name).scalar()
    assert expected_endpoint == actual_endpoint


def test_primary_certificate_uniqueness(session):
    """Ensure that only one primary certificate can be associated with an endpoint."""
    # Create and associate two primary certificates with an endpoint
    crt = CertificateFactory()
    endpoint = EndpointFactory()
    endpoint.primary_certificate = crt

    # TODO(EDGE-1363) Expose API for managing secondary certificates associated with an endpoint
    endpoint.certificates_assoc.append(
        EndpointsCertificates(certificate=CertificateFactory(), endpoint=endpoint, primary=True)
    )

    with pytest.raises(Exception):
        session.commit()


def test_certificate_path(session):
    crt = CertificateFactory()
    fake_path = "/fake/path"
    endpoint = EndpointFactory()
    endpoint.primary_certificate = crt
    endpoint.certificate_path = fake_path

    assert endpoint.certificate_path == fake_path


def test_certificate_uniqueness(session):
    """Ensure that a given SNI certificate can be associated with an endpoint more than once."""
    # Create and associate primary certificate with an endpoint
    endpoint = EndpointFactory()
    endpoint.primary_certificate = CertificateFactory()

    # Associate a SNI certificate with the endpoint twice
    try:
        crt = CertificateFactory()
        for _ in range(0, 2):
            # TODO(EDGE-1363) Expose API for managing secondary certificates associated with an endpoint
            endpoint.certificates_assoc.append(
                EndpointsCertificates(certificate=crt, endpoint=endpoint, primary=False)
            )
    except SQLAlchemyError:
        assert False
